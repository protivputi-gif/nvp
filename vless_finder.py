#!/usr/bin/env python3
"""VLESS Finder 3.1 — массовая проверка VLESS-подписок.

Исправлено в 3.1 (сверх 3.0):
  * Подписки больше не обрезаются при скачивании (читаем поток до EOF).
  * Для xray 26.x+ автоматический пиннинг SHA-256 сертификата ноды —
    allowInsecure удалён из xray 2026-06-01, пиннинг его заменяет.
  * Поддержка type=httpupgrade (раньше выпадал из SUPPORTED_NETWORKS).
  * Пост-квантовое шифрование VLESS (encryption=mlkem768…) больше не
    отсекается валидатором.
  * Диагностика отказов (_error_key) группирует причины корректно,
    сохраняя HTTP-статусы.
  * Обрезанные ссылки отсеиваются на этапе парсинга (_looks_truncated).

Зависимости: pip install aiohttp rich
Платформа: Linux/macOS/WSL, Python 3.10+
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import contextlib
import csv
import hashlib
import io
import json
import os
import platform
import random
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlparse

import aiohttp
from rich.console import Console
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                           TimeElapsedColumn)
from rich.table import Table

__version__ = "3.1.0"
console = Console()

if sys.version_info < (3, 10):
    sys.exit("Нужен Python 3.10+")

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


# =============================================================================
# 1. МОДЕЛИ ДАННЫХ
# =============================================================================

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

NETWORK_ALIASES = {
    "websocket": "ws",
    "splithttp": "xhttp",
    "raw": "tcp",
    "h2": "http",
}

COSMETIC_PARAMS = {
    "fp", "allowinsecure", "insecure", "spx", "fragment", "note", "remark",
    "packetencoding", "vcn", "pcs", "pqv",
}


def resolve_security(p: dict[str, str]) -> str:
    sec = (p.get("security") or "").strip().lower()
    if not sec or sec == "auto":
        if p.get("pbk") or p.get("public-key"):
            return "reality"
        if p.get("sni") or p.get("fp") or p.get("alpn"):
            return "tls"
        return "none"
    return sec


@dataclass
class VlessLink:
    raw: str
    uuid: str
    host: str
    port: int
    params: dict[str, str] = field(default_factory=dict)
    name: str = ""

    @property
    def security(self) -> str:
        return resolve_security(self.params)

    @property
    def network(self) -> str:
        t = self.params.get("type", "tcp").lower()
        return NETWORK_ALIASES.get(t, t)

    @property
    def sni(self) -> str:
        return self.params.get("sni", "")

    @property
    def fingerprint(self) -> str:
        return self.params.get("fp", "")

    @property
    def public_key(self) -> str:
        return self.params.get("pbk", "") or self.params.get("public-key", "")

    @property
    def short_id(self) -> str:
        return self.params.get("sid", "") or self.params.get("short-id", "")

    @property
    def flow(self) -> str:
        return self.params.get("flow", "")

    @property
    def alpn(self) -> str:
        return self.params.get("alpn", "")

    def country_hint(self) -> str:
        m = re.search(r"(?:^|[\s\-|(])([A-Z]{2,3})(?:[\s\-)|]|$)", self.name)
        if m and m.group(1).upper() not in ("TLS", "TCP", "WS", "GRPC", "XTLS",
                                            "VMESS", "VLESS", "BL", "RU"):
            return m.group(1).upper()
        return ""

    def effective_params(self, smart: bool = False) -> dict[str, str]:
        p = dict(self.params)
        sec = resolve_security(p)
        net = NETWORK_ALIASES.get(p.get("type", "tcp").lower(),
                                  p.get("type", "tcp").lower())
        eff = {
            "security": sec,
            "type": net,
            "encryption": p.get("encryption", "") or "none",
            "path": unquote(p.get("path", "")) or "/",
            "host": p.get("host", "").lower(),
            "sni": p.get("sni", "").lower(),
            "fp": p.get("fp", ""),
            "alpn": ",".join(sorted(a for a in p.get("alpn", "").split(",") if a)),
            "flow": p.get("flow", ""),
            "mode": p.get("mode", ""),
            "servicename": p.get("servicename", ""),
            "headertype": p.get("headertype", ""),
            "authority": p.get("authority", ""),
            "extra": p.get("extra", ""),
        }
        if sec == "reality":
            eff["pbk"] = p.get("pbk") or p.get("public-key", "")
            eff["sid"] = p.get("sid") or p.get("short-id", "")
        for k, v in p.items():
            if k not in eff and k not in ("public-key", "short-id"):
                eff[k] = v.strip().lower() if isinstance(v, str) else v
        if smart:
            eff = {k: v for k, v in eff.items() if k not in COSMETIC_PARAMS}
        return {k: v for k, v in eff.items() if v != ""}

    def dedup_key(self, smart: bool = False) -> str:
        e = self.effective_params(smart=smart)
        return f"{self.uuid}@{self.host.lower()}:{self.port}?" + \
            "&".join(f"{k}={v}" for k, v in sorted(e.items()))

    @classmethod
    def parse(cls, link: str) -> "VlessLink | None":
        link = link.strip().strip('"').strip("'")
        if not link.lower().startswith("vless://"):
            return None
        try:
            parsed = urlparse(link)
            uid = unquote(parsed.username or "")
            host = parsed.hostname or ""
            port = parsed.port
            if not UUID_RE.match(uid):
                return None
            if not host or not port or not (0 < port < 65536):
                return None
            name = ""
            if "#" in link:
                name = unquote(link.split("#", 1)[1]).strip()[:120]
            query = parsed.query.replace("&amp;", "&")
            params = {k.lower(): v for k, v in
                      parse_qsl(query, keep_blank_values=True)}
            return cls(raw=link, uuid=uid.lower(), host=host, port=port,
                       params=params, name=name)
        except ValueError:
            return None


@dataclass
class NodeResult:
    link: str
    name: str = ""
    host: str = ""
    country: str = ""
    network: str = ""
    security: str = ""
    alive: bool = False
    latency_ms: float | None = None
    target_latency_s: float | None = None
    http_status: int | None = None
    speed_mbps: float = 0.0
    bytes_downloaded: int = 0
    error: str = ""
    score: float = 0.0
    round_ok: list[bool] = field(default_factory=list)
    round_latency_s: list[float | None] = field(default_factory=list)
    round_speed_mbps: list[float] = field(default_factory=list)

    @property
    def rounds_passed(self) -> int:
        return sum(1 for x in self.round_ok if x)

    @property
    def worst_latency_s(self) -> float | None:
        vals = [x for x in self.round_latency_s if x is not None]
        return max(vals) if vals else None

    @classmethod
    def from_link(cls, vl: VlessLink) -> "NodeResult":
        return cls(link=vl.raw, name=vl.name or vl.host,
                   host=f"{vl.host}:{vl.port}", country=vl.country_hint(),
                   network=vl.network, security=vl.security)


# =============================================================================
# 2. КОНФИГУРАЦИЯ + ЦЕЛЬ
# =============================================================================

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_bool(name: str, default: bool = True) -> bool:
    v = os.environ.get(name, "")
    if not v:
        return default
    return v.strip().lower() not in ("0", "false", "no", "off")


@dataclass
class CheckConfig:
    CHECK_URL: str = ""
    CHECK_NAME: str = "target"
    EXPECT_STATUS: str = os.environ.get("VF_EXPECT_STATUS", "any")
    FOLLOW_REDIRECTS: bool = _env_bool("VF_REDIRECTS", True)
    BODY_MATCH: str = os.environ.get("VF_BODY_MATCH", "")
    BODY_CHECK_MIN_BYTES: int = _env_int("VF_MIN_BODY", 0)
    BODY_CHECK_READ_BYTES: int = 262144

    SITE_TIMEOUT: float = _env_float("VF_SITE_TIMEOUT", 15.0)
    SITE_RETRIES: int = _env_int("VF_SITE_RETRIES", 2)
    MAX_TARGET_LATENCY_S: float = _env_float("VF_MAX_TARGET_LATENCY", 0.0)
    USER_AGENT: str = os.environ.get("VF_UA", DEFAULT_UA)

    TCP_PING_TIMEOUT: float = _env_float("VF_TCP_TIMEOUT", 6.0)
    LATENCY_SAMPLES: int = _env_int("VF_LATENCY_SAMPLES", 3)
    DNS_TIMEOUT: float = _env_float("VF_DNS_TIMEOUT", 5.0)

    PRECHECK_ENABLED: bool = _env_bool("VF_PRECHECK", True)
    PRECHECK_HOST: str = ""
    PRECHECK_PORT: int = 443
    PRECHECK_TIMEOUT: float = _env_float("VF_PRECHECK_TIMEOUT", 6.0)

    SPEEDTEST_ENABLED: bool = _env_bool("VF_SPEEDTEST", True)
    SPEED_TEST_URLS: tuple[str, ...] = (
        "https://speed.cloudflare.com/__down?bytes=25000000",
        "https://proof.ovh.net/files/10Mb.dat",
        "http://ipv4.download.thinkbroadband.com/10MB.zip",
    )
    SPEED_TEST_BYTES: int = 10 * 1024 * 1024
    SPEED_TEST_TIMEOUT: float = _env_float("VF_SPEED_TIMEOUT", 30.0)
    ADAPTIVE_SPEED_ENABLED: bool = _env_bool("VF_ADAPTIVE_SPEED", True)
    FAST_THRESHOLD_MBPS: float = 80.0
    QUICK_DOWNLOAD_BYTES: int = 2 * 1024 * 1024
    MIN_DOWNLOAD_SPEED_MBPS: float = _env_float("VF_MIN_SPEED", 2.0)

    STABILITY_ROUNDS: int = _env_int("VF_STABILITY_ROUNDS", 2)
    STABILITY_ROUND_GAP: float = _env_float("VF_STABILITY_GAP", 3.0)

    MAX_CONCURRENT: int = _env_int("VF_MAX_CONCURRENT", 100)
    XRAY_START_WAIT: float = _env_float("VF_XRAY_START_WAIT", 3.0)
    FETCH_TIMEOUT: float = _env_float("VF_FETCH_TIMEOUT", 120.0)
    FETCH_RETRIES: int = _env_int("VF_FETCH_RETRIES", 2)
    MAX_SUB_BYTES: int = _env_int("VF_MAX_SUB_BYTES", 64 * 1024 * 1024)
    MAX_LINKS: int = _env_int("VF_MAX_LINKS", 300000)
    SMART_DEDUP: bool = _env_bool("VF_SMART_DEDUP", True)

    DEFAULT_FP: str = os.environ.get("VF_DEFAULT_FP", "chrome")
    AUTO_PIN: bool = _env_bool("VF_AUTO_PIN", True)

    TOP_N: int = _env_int("VF_TOP_N", 100)
    OUT_GOOD_FILE: str = "good_vless.txt"
    OUT_TOP_FILE: str = "best_vless.txt"
    OUT_REPORT_FILE: str = "report.csv"
    OUT_INFO_FILE: str = "run_info.json"


CFG = CheckConfig()

DEFAULT_TARGET = (os.environ.get("VF_TARGET", "")
                  or os.environ.get("VF_CHECK_URL", "") or "tg-api")

LIGHT_TARGETS: dict[str, dict] = {
    "tg-api": {
        "url": "https://api.telegram.org/bot1/getMe",
        "expect": "200,401,404", "match": '"ok":', "min_body": 0,
        "redirects": False,
        "note": "Bot API: 401 без токена = хост доступен",
    },
    "tg-web": {
        "url": "https://web.telegram.org/a/",
        "expect": "200", "match": "telegram", "min_body": 512,
        "redirects": True,
        "note": "веб-клиент Telegram (редиректит между /a/ и /k/)",
    },
    "nvidia": {
        "url": "https://integrate.api.nvidia.com/v1",
        "expect": "any", "match": "", "min_body": 0,
        "redirects": False, "note": "NVIDIA API",
    },
    "nvidia-models": {
        "url": "https://integrate.api.nvidia.com/v1/models",
        "expect": "200,401,403,404", "match": "", "min_body": 0,
        "redirects": False, "note": "NVIDIA models endpoint",
    },
    "openai": {
        "url": "https://api.openai.com/v1/models",
        "expect": "200,401,403", "match": "", "min_body": 0,
        "redirects": False, "note": "OpenAI API",
    },
    "gh-api": {
        "url": "https://api.github.com/",
        "expect": "200,403,429", "match": "", "min_body": 0,
        "redirects": False, "note": "GitHub API",
    },
    "cf-trace": {
        "url": "https://www.cloudflare.com/cdn-cgi/trace",
        "expect": "200", "match": "colo=", "min_body": 0,
        "redirects": False, "note": "~300 байт, маркер colo=",
    },
    "yt204": {
        "url": "https://www.youtube.com/generate_204",
        "expect": "204", "match": "", "min_body": 0,
        "redirects": False, "note": "пустой 204",
    },
    "g204": {
        "url": "https://www.gstatic.com/generate_204",
        "expect": "204", "match": "", "min_body": 0,
        "redirects": False, "note": "Google 204",
    },
    "cp204": {
        "url": "https://cp.cloudflare.com/generate_204",
        "expect": "204", "match": "", "min_body": 0,
        "redirects": False, "note": "Cloudflare 204",
    },
    "youtube": {
        "url": "https://www.youtube.com/",
        "expect": "200", "match": "", "min_body": 20000,
        "redirects": True, "note": "тяжёлая главная",
    },
    "google": {
        "url": "https://www.google.com/",
        "expect": "200", "match": "", "min_body": 1024,
        "redirects": True, "note": "главная Google",
    },
}


def normalize_check_url(value: str) -> str:
    v = (value or "").strip().strip('"').strip("'")
    if not v:
        raise ValueError("не задан адрес цели")
    if "://" not in v:
        v = "https://" + v
    p = urlparse(v)
    if p.scheme not in ("http", "https"):
        raise ValueError(f"схема {p.scheme!r} не поддерживается")
    if not p.hostname:
        raise ValueError(f"не удалось определить хост в {value!r}")
    if not p.path:
        v = p._replace(path="/").geturl()
    return v


def set_check_target(url_or_domain: str) -> str:
    url = normalize_check_url(url_or_domain)
    p = urlparse(url)
    CFG.CHECK_URL = url
    CFG.CHECK_NAME = p.hostname or "target"
    CFG.PRECHECK_HOST = CFG.CHECK_NAME
    CFG.PRECHECK_PORT = p.port or (443 if p.scheme == "https" else 80)
    return url


def apply_target(name_or_url: str) -> str:
    key = (name_or_url or "").strip()
    preset = LIGHT_TARGETS.get(key.lower())
    if not preset:
        return set_check_target(key)
    url = set_check_target(preset["url"])
    CFG.EXPECT_STATUS = preset.get("expect", "any")
    CFG.BODY_MATCH = preset.get("match", "")
    CFG.BODY_CHECK_MIN_BYTES = int(preset.get("min_body", 0))
    if "redirects" in preset:
        CFG.FOLLOW_REDIRECTS = bool(preset["redirects"])
    return url


def status_ok(status: int) -> bool:
    spec = (CFG.EXPECT_STATUS or "any").strip().lower()
    if spec in ("", "any", "*"):
        return status > 0
    for part in spec.split(","):
        part = part.strip()
        if len(part) == 3 and part.endswith("xx") and part[0].isdigit():
            if status // 100 == int(part[0]):
                return True
        elif part.isdigit() and status == int(part):
            return True
    return False


apply_target(DEFAULT_TARGET)


# =============================================================================
# 3. ПАРСИНГ ПОДПИСОК
# =============================================================================

VLESS_RE = re.compile(r"vless://[^\s'\"<>]+", re.I)
B64_BLOCK_RE = re.compile(r"[A-Za-z0-9+/=_-]{200,}")


def _looks_truncated(link: str) -> bool:
    """Отбраковка обрезанных ссылок, у которых query обрывается посередине."""
    if "?" not in link:
        return False
    q = link.split("?", 1)[1].split("#", 1)[0]
    if not q:
        return False
    return (q.endswith(("&", "=", "%", "{", '"'))
            or bool(re.search(r"%[0-9A-Fa-f]?$", q)))


def try_b64_decode(s: str) -> str | None:
    s = "".join(s.split())
    if len(s) < 32 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", s):
        return None
    s2 = s.replace("-", "+").replace("_", "/")
    s2 += "=" * (-len(s2) % 4)
    try:
        data = base64.b64decode(s2, validate=False)
        txt = data.decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if "vless://" in txt or "vmess://" in txt or "ss://" in txt:
        return txt
    return None


def extract_vless_from_text(text: str, smart_dedup: bool | None = None) -> list[VlessLink]:
    smart = CFG.SMART_DEDUP if smart_dedup is None else smart_dedup
    links: list[VlessLink] = []
    seen: set[str] = set()

    def add(vl: VlessLink | None):
        if vl is None:
            return
        key = vl.dedup_key(smart=smart)
        if key in seen:
            return
        seen.add(key)
        links.append(vl)

    def harvest(src: str):
        for m in VLESS_RE.finditer(src):
            candidate = m.group(0).rstrip(".,;)]}'\"")
            if _looks_truncated(candidate):
                continue
            add(VlessLink.parse(candidate))

    harvest(text)

    decoded_whole = try_b64_decode(text)
    if decoded_whole:
        harvest(decoded_whole)
    else:
        compact = re.sub(r"\s+", "", text)
        found_block = False
        for m in B64_BLOCK_RE.finditer(compact):
            decoded = try_b64_decode(m.group(0))
            if decoded:
                found_block = True
                harvest(decoded)
        if not found_block:
            for line in text.splitlines():
                decoded = try_b64_decode(line.strip())
                if decoded:
                    harvest(decoded)
    return links[:CFG.MAX_LINKS]


def dedup_links(raw_links: list[str], smart: bool | None = None) -> list[str]:
    smart = CFG.SMART_DEDUP if smart is None else smart
    seen: set[str] = set()
    uniq: list[str] = []
    for l in raw_links:
        vl = VlessLink.parse(l)
        if vl is None:
            continue
        if _looks_truncated(l):
            continue
        k = vl.dedup_key(smart=smart)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(vl.raw)
    return uniq


# =============================================================================
# 4. ИСТОЧНИКИ ПОДПИСОК
# =============================================================================

SOURCES_FILENAME = "subscriptions.txt"

DEFAULT_SUBSCRIPTION_URLS: list[str] = [
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/mohammadaz2/v2rayConfigsForYou/main/sub/vless.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",
    "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/vless.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/vless_sub.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/vless",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/yebekhe/V2Hub/main/merged_vless",
    "https://raw.githubusercontent.com/itsyebekhe/HiN-VPN/main/subscription/normal/vless",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub_Merge.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
]


def read_urls_file(path: str) -> list[str]:
    urls: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            u = line.strip()
            if u and not u.startswith("#") and u not in urls:
                urls.append(u)
    return urls


def ensure_default_sources_file(path: str) -> None:
    header = (
        "# Источники VLESS-подписок: один URL на строку, '#' — комментарий.\n"
    )
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(DEFAULT_SUBSCRIPTION_URLS) + "\n")
    console.print(f"[yellow]Создан {path} "
                  f"({len(DEFAULT_SUBSCRIPTION_URLS)} источников)[/]")


def resolve_sources_path(workdir: str = ".", explicit: str = "") -> str:
    if explicit:
        return explicit
    cand = os.path.join(workdir, SOURCES_FILENAME)
    if os.path.isfile(cand):
        return cand
    return os.environ.get("VF_SOURCES_FILE", "") or cand


def load_sources(workdir: str = ".", sources_file: str = "") -> list[str]:
    path = resolve_sources_path(workdir, sources_file)
    if not os.path.isfile(path):
        ensure_default_sources_file(path)
    urls = read_urls_file(path)
    local_file = os.path.join(workdir, "known_subscriptions.txt")
    if os.path.isfile(local_file):
        for u in read_urls_file(local_file):
            if u not in urls:
                urls.append(u)
    for u in os.environ.get("VF_EXTRA_SOURCES", "").split(","):
        u = u.strip()
        if u and u not in urls:
            urls.append(u)
    return urls


async def _read_body_capped(r: aiohttp.ClientResponse, cap: int) -> bytes:
    """FIX 3.1: content.read(n) возвращает «до n» и обрезало подписки.
    Читаем поток до EOF, ограничивая только суммарный объём."""
    buf = bytearray()
    async for chunk in r.content.iter_chunked(256 * 1024):
        buf.extend(chunk)
        if len(buf) >= cap:
            break
    return bytes(buf)


async def fetch_links_from_urls(urls: list[str], concurrency: int = 8) -> list[str]:
    results: list[str] = []
    stats = {"ok": 0, "fail": 0}
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    timeout = aiohttp.ClientTimeout(total=CFG.FETCH_TIMEOUT, sock_read=90)
    # Без Accept-Encoding — пусть aiohttp сам договаривается и распаковывает
    headers = {"User-Agent": CFG.USER_AGENT, "Accept": "text/plain, */*"}
    async with aiohttp.ClientSession(connector=connector, timeout=timeout,
                                     headers=headers) as session:
        async def fetch(u: str):
            async with sem:
                last_err = ""
                for attempt in range(1 + max(0, CFG.FETCH_RETRIES)):
                    try:
                        async with session.get(u, allow_redirects=True) as r:
                            if r.status != 200:
                                last_err = f"HTTP {r.status}"
                                await asyncio.sleep(0.5 * (attempt + 1))
                                continue
                            data = await _read_body_capped(r, CFG.MAX_SUB_BYTES)
                            text = data.decode("utf-8", errors="ignore")
                        return u, [vl.raw for vl in extract_vless_from_text(text)], ""
                    except Exception as e:
                        last_err = type(e).__name__
                        await asyncio.sleep(0.5 * (attempt + 1))
                return u, None, last_err

        tasks = [asyncio.create_task(fetch(u)) for u in urls]
        for coro in asyncio.as_completed(tasks):
            u, links, err = await coro
            if links is None:
                stats["fail"] += 1
                console.print(f"  [red][skip][/] {u} [dim]({err})[/]")
            else:
                stats["ok"] += 1
                console.print(f"  [green][ok][/][green]{len(links):>7}[/] ссылок: {u}")
                results.extend(links)
    console.print(f"[dim]Источников: успешно {stats['ok']}, "
                  f"недоступно {stats['fail']}[/]")
    return dedup_links(results)


# =============================================================================
# 5. ГЕНЕРАЦИЯ КОНФИГА XRAY
# =============================================================================

class XrayConfigError(ValueError):
    pass


class UnsupportedNode(ValueError):
    pass


_XRAY_VER_CACHE: tuple | None = None


def xray_binary_path() -> str:
    return os.environ.get(
        "XRAY_BINARY",
        shutil.which("xray") or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "xray_bin", "xray"),
    )


def _xray_version_tuple() -> tuple:
    global _XRAY_VER_CACHE
    if _XRAY_VER_CACHE is None:
        ver: tuple = ()
        try:
            out = subprocess.run([xray_binary_path(), "version"],
                                 capture_output=True, text=True, timeout=10).stdout
            m = re.search(r"Xray\s+(\d+)\.(\d+)\.(\d+)", out)
            if m:
                ver = tuple(int(g) for g in m.groups())
        except Exception:
            pass
        _XRAY_VER_CACHE = ver
    return _XRAY_VER_CACHE


VALID_FPS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360",
             "qq", "random", "randomized", "randomizednoalpn", "unsafe"}


def _fp(vl: VlessLink) -> str:
    fp = (vl.fingerprint or CFG.DEFAULT_FP or "chrome").lower()
    if fp.startswith("hello"):
        return fp
    return fp if fp in VALID_FPS else "chrome"


def _alpn_list(vl: VlessLink) -> list[str]:
    items = [a.strip() for a in vl.alpn.split(",") if a.strip()]
    items = [a for a in items if a.lower() not in ("h3", "h3-29")]
    if vl.network in ("ws", "httpupgrade"):
        items = [a for a in items if a == "http/1.1"]
    return items


def _build_tls_stream(vl: VlessLink, pin: str = "") -> dict:
    """TLS-настройки с пиннингом сертификата.

    FIX 3.1: allowInsecure удалён из xray 2026-06-01. Вместо него
    pinnedPeerCertSha256 — хэш leaf-сертификата ноды, который мы узнаём
    заранее (probe_peer_cert_sha256). Пиннинг принимается xray без
    проверки CA/имени и полностью заменяет allowInsecure для тестовых нод.
    """
    tls: dict = {"fingerprint": _fp(vl)}
    if vl.sni:
        tls["serverName"] = vl.sni
    elif vl.params.get("host"):
        tls["serverName"] = vl.params["host"]
    alpn = _alpn_list(vl)
    if alpn:
        tls["alpn"] = alpn
    pins = []
    if vl.params.get("pcs"):
        pins.append(vl.params["pcs"].replace(":", "").lower())
    if pin:
        pins.append(pin)
    if pins:
        tls["pinnedPeerCertSha256"] = ",".join(dict.fromkeys(pins))
    else:
        # fallback для старых xray (<25.12), где allowInsecure ещё жив
        ver = _xray_version_tuple()
        if not ver or ver < (25, 12, 0):
            tls["allowInsecure"] = True
    if vl.params.get("vcn"):
        tls["verifyPeerCertByName"] = vl.params["vcn"]
    if vl.params.get("cs"):
        tls["cipherSuites"] = unquote(vl.params["cs"])
    return tls


def _build_reality_stream(vl: VlessLink) -> dict:
    reality: dict = {"publicKey": vl.public_key, "fingerprint": _fp(vl)}
    if vl.sni:
        reality["serverName"] = vl.sni
    if vl.short_id:
        reality["shortId"] = vl.short_id
    if vl.params.get("spx"):
        reality["spiderX"] = unquote(vl.params["spx"])
    return reality


# FIX 3.1: httpupgrade добавлен в список поддерживаемых
SUPPORTED_NETWORKS = {"tcp", "ws", "grpc", "http", "httpupgrade", "xhttp"}
SUPPORTED_SECURITY = {"none", "tls", "reality"}
SUPPORTED_FLOWS = {"", "xtls-rprx-vision"}


def validate_node(vl: VlessLink) -> None:
    if vl.security not in SUPPORTED_SECURITY:
        raise UnsupportedNode(f"security={vl.security}")
    if vl.network not in SUPPORTED_NETWORKS:
        raise UnsupportedNode(f"type={vl.network}")
    if vl.security == "reality" and not vl.public_key:
        raise UnsupportedNode("reality без pbk")
    if vl.flow not in SUPPORTED_FLOWS:
        raise UnsupportedNode(f"flow={vl.flow!r}")
    # FIX 3.1: НЕ валидируем encryption — post-quantum шифры
    # (mlkem768x25519plus.native.0rtt...) легальны с xray v25.9.5


def _build_ws_settings(vl: VlessLink) -> dict:
    ws: dict = {}
    path = vl.params.get("path")
    if path:
        ws["path"] = unquote(path)
    host = vl.params.get("host") or ""
    if host:
        ws["host"] = host
        ws["headers"] = {"Host": host}
    ed = vl.params.get("ed", "")
    if ed:
        if "|" in ed:
            mx, hdrs = ed.split("|", 1)
            headers = dict(ws.get("headers", {}))
            for hdr in unquote(hdrs).split("&"):
                if ":" in hdr:
                    k, v = hdr.split(":", 1)
                    headers[k.strip()] = v.strip()
            if headers:
                ws["headers"] = headers
            ed = mx
        with contextlib.suppress(ValueError):
            n = int(ed)
            if n > 0:
                ws["maxEarlyData"] = n
                ws["earlyDataHeaderName"] = "Sec-WebSocket-Protocol"
    return ws


def _build_grpc_settings(vl: VlessLink) -> dict:
    mode = vl.params.get("mode", "")
    service = vl.params.get("servicename", "")
    if not service and mode and mode not in ("gun", "multi"):
        service = mode
    grpc: dict = {"serviceName": service, "multiMode": mode == "multi"}
    if vl.params.get("authority"):
        grpc["authority"] = vl.params["authority"]
    return grpc


def _build_tcp_settings(vl: VlessLink) -> dict:
    if (vl.params.get("headertype") or "").lower() != "http":
        return {}
    path = unquote(vl.params.get("path", "/")) or "/"
    req: dict = {"path": [path], "headers": {}}
    host = vl.params.get("host")
    if host:
        req["headers"]["Host"] = [host]
    return {"header": {"type": "http", "request": req}}


def _parse_extra(raw: str) -> dict | None:
    if not raw:
        return None
    try:
        obj = json.loads(unquote(raw))
        return obj if isinstance(obj, dict) else None
    except (ValueError, TypeError):
        return None


def build_xray_config(link_raw: str, proxy_port: int,
                      cert_pin: str = "") -> dict:
    """HTTP-инбаунд на 127.0.0.1 + VLESS-аутбаунд.

    cert_pin — SHA-256 leaf-сертификата ноды (узнаём заранее через
    probe_peer_cert_sha256). Для TLS-нод это заменяет удалённый
    allowInsecure и позволяет проходить с самоподписанными/чужими cert.
    """
    vl = VlessLink.parse(link_raw)
    if vl is None:
        raise XrayConfigError("не удалось распарсить ссылку")
    validate_node(vl)

    # FIX 3.1: encryption передаётся как есть (включая post-quantum)
    user: dict = {"id": vl.uuid, "level": 0,
                  "encryption": vl.params.get("encryption") or "none"}
    if vl.flow:
        user["flow"] = vl.flow

    sec = vl.security
    stream: dict = {"network": vl.network, "security": sec}
    if sec == "reality":
        stream["realitySettings"] = _build_reality_stream(vl)
    elif sec == "tls":
        stream["tlsSettings"] = _build_tls_stream(vl, pin=cert_pin)

    host = vl.params.get("host", "")
    path = unquote(vl.params.get("path", "/")) or "/"
    if vl.network == "ws":
        stream["wsSettings"] = _build_ws_settings(vl)
    elif vl.network == "grpc":
        stream["grpcSettings"] = _build_grpc_settings(vl)
    elif vl.network == "http":
        # HTTP/2: httpSettings, host — СПИСОК
        stream["httpSettings"] = {"host": [host] if host else [], "path": path}
    elif vl.network == "httpupgrade":
        stream["httpupgradeSettings"] = {"host": host, "path": path}
    elif vl.network == "xhttp":
        xhttp: dict = {"host": host, "path": path,
                       "mode": vl.params.get("mode", "auto") or "auto"}
        extra = _parse_extra(vl.params.get("extra", ""))
        if extra:
            xhttp["extra"] = extra
        stream["xhttpSettings"] = xhttp
    elif vl.network == "tcp":
        tcp = _build_tcp_settings(vl)
        if tcp:
            stream["tcpSettings"] = tcp

    return {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": proxy_port,
            "protocol": "http",
            "settings": {},
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{"address": vl.host, "port": vl.port,
                                    "users": [user]}]},
            "streamSettings": stream,
        }],
    }


# =============================================================================
# 6. МЕНЕДЖЕР ПРОЦЕССОВ XRAY
# =============================================================================

_LIVE_XRAY: set["XrayProcess"] = set()


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class XrayProcess:
    def __init__(self, config_dict: dict):
        self._cfg = config_dict
        self._proc: asyncio.subprocess.Process | None = None
        self.port: int = config_dict["inbounds"][0]["port"]
        self._tmpdir = tempfile.mkdtemp(prefix="xraycfg_")
        self.log_tail: str = ""

    @property
    def proxy_host(self) -> str:
        return "127.0.0.1"

    @property
    def proxy_port(self) -> int:
        return self.port

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _read_log(self) -> str:
        with contextlib.suppress(Exception):
            p = os.path.join(self._tmpdir, "xray.log")
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    return f.read(4096).decode("utf-8", errors="ignore").strip()
        return ""

    async def start(self, wait_seconds: float | None = None):
        wait_seconds = CFG.XRAY_START_WAIT if wait_seconds is None else wait_seconds
        cfg_path = os.path.join(self._tmpdir, "config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(self._cfg, f)

        logf = open(os.path.join(self._tmpdir, "xray.log"), "wb")
        try:
            self._proc = await asyncio.create_subprocess_exec(
                xray_binary_path(), "-config", cfg_path,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=logf,
                start_new_session=True,
            )
        finally:
            logf.close()

        _LIVE_XRAY.add(self)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_seconds
        while loop.time() < deadline:
            if self._proc.returncode is not None:
                self.log_tail = self._read_log()
                raise XrayConfigError(
                    f"xray вышел при старте (rc={self._proc.returncode}) "
                    f"{self.log_tail[:200]}")
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", self.port), 0.4)
                writer.close()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), 1)
                return
            except (OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.05)
        raise TimeoutError("xray не поднял прокси-порт")

    async def stop(self):
        _LIVE_XRAY.discard(self)
        p = self._proc
        if p is not None and p.returncode is None:
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(p.wait(), 5)
        shutil.rmtree(self._tmpdir, ignore_errors=True)


def kill_all_xray() -> None:
    for xp in list(_LIVE_XRAY):
        p = xp._proc
        if p is not None and p.returncode is None:
            with contextlib.suppress(Exception):
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        shutil.rmtree(xp._tmpdir, ignore_errors=True)
    _LIVE_XRAY.clear()


@asynccontextmanager
async def running_xray(link_raw: str, cert_pin: str = ""):
    last_exc: Exception | None = None
    for _ in range(2):
        cfg = build_xray_config(link_raw, find_free_port(), cert_pin=cert_pin)
        xp = XrayProcess(cfg)
        try:
            await xp.start()
        except TimeoutError as e:
            last_exc = e
            await xp.stop()
            continue
        except XrayConfigError as e:
            last_exc = e
            await xp.stop()
            continue
        try:
            yield xp
        finally:
            await xp.stop()
        return
    raise last_exc or XrayConfigError("xray не запустился")


# =============================================================================
# 7. СЕТЕВЫЕ ЗОНДЫ
# =============================================================================

_DNS_CACHE: dict[str, str] = {}
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Кэш пиннинга сертификатов: (host, port, sni) -> sha256 hex
_CERT_CACHE: dict[tuple[str, int, str], str] = {}


async def resolve_host(host: str) -> str | None:
    if _IPV4_RE.match(host) or ":" in host:
        return host
    cached = _DNS_CACHE.get(host)
    if cached:
        return cached
    loop = asyncio.get_running_loop()
    for family in (socket.AF_INET, socket.AF_UNSPEC):
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, 0, family=family, type=socket.SOCK_STREAM),
                CFG.DNS_TIMEOUT)
        except (socket.gaierror, OSError, asyncio.TimeoutError):
            continue
        for info in infos:
            ip = info[4][0]
            _DNS_CACHE[host] = ip
            return ip
    return None


async def probe_peer_cert_sha256(host: str, port: int, sni: str,
                                 timeout: float = 5.0) -> str:
    """FIX 3.1: узнаём SHA-256 leaf-сертификата ноды прямым TLS-контактом.

    Нужен потому, что allowInsecure удалён из xray (2026-06-01), а
    pinnedPeerCertSha256 с хэшем leaf принимается без проверки CA/имени.
    Это позволяет проходить TLS-рукопожатие к нодам с самоподписанными
    или чужими сертификатами — норма для публичных подписок.
    """
    key = (host, port, sni)
    if key in _CERT_CACHE:
        return _CERT_CACHE[key]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(Exception):
        ctx.set_alpn_protocols(["http/1.1"])
    h = ""
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx,
                                    server_hostname=sni or host), timeout)
        obj = writer.get_extra_info("ssl_object")
        der = obj.getpeercert(binary_form=True) if obj else None
        if der:
            h = hashlib.sha256(der).hexdigest()
    except Exception:
        h = ""
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), 1)
    _CERT_CACHE[key] = h
    return h


async def measure_tcp_latency(host: str, port: int,
                              samples: int | None = None) -> float | None:
    samples = max(1, CFG.LATENCY_SAMPLES if samples is None else samples)
    min_success = max(1, (samples + 1) // 2)
    ip = await resolve_host(host)
    if ip is None:
        return None
    latencies: list[float] = []
    for _ in range(samples):
        t0 = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=CFG.TCP_PING_TIMEOUT)
            latencies.append((time.perf_counter() - t0) * 1000)
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), 1)
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.02)
    if len(latencies) < min_success:
        return None
    latencies.sort()
    return latencies[len(latencies) // 2]


async def precheck_tunneled_connect(proxy_host: str, proxy_port: int,
                                    target_host: str, target_port: int,
                                    timeout: float) -> bool:
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port), timeout)
        req = (f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
               f"Host: {target_host}:{target_port}\r\n\r\n").encode()
        writer.write(req)
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout)
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return 200 <= int(parts[1]) < 300
        return True
    except Exception:
        return True
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), 1)


async def _check_site_once(session: aiohttp.ClientSession, proxy: str, url: str,
                           timeout: float) -> tuple[bool, float, int]:
    t0 = time.perf_counter()
    try:
        async with session.get(url, proxy=proxy,
                               timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=CFG.FOLLOW_REDIRECTS) as r:
            ok = status_ok(r.status)
            if ok and (CFG.BODY_MATCH or CFG.BODY_CHECK_MIN_BYTES > 0):
                try:
                    chunk = await r.content.read(CFG.BODY_CHECK_READ_BYTES)
                except Exception:
                    chunk = b""
                if len(chunk) < CFG.BODY_CHECK_MIN_BYTES:
                    ok = False
                if ok and CFG.BODY_MATCH:
                    ok = CFG.BODY_MATCH.lower().encode() in chunk.lower()
            return ok, time.perf_counter() - t0, r.status
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError):
        return False, time.perf_counter() - t0, 0


async def check_site(session: aiohttp.ClientSession, proxy: str, url: str,
                     timeout: float) -> tuple[bool, float, int]:
    attempts = 1 + max(0, CFG.SITE_RETRIES)
    total, status = 0.0, 0
    for _ in range(attempts):
        ok, dt, status = await _check_site_once(session, proxy, url, timeout)
        total += dt
        if ok:
            return True, total, status
    return False, total, status


async def _download_once(session: aiohttp.ClientSession, proxy: str, url: str,
                         max_bytes: int, timeout: float) -> tuple[float, int]:
    got = 0
    t0 = time.perf_counter()
    try:
        async with session.get(url, proxy=proxy,
                               timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=True) as r:
            if r.status != 200:
                return 0.0, 0
            async for chunk in r.content.iter_chunked(64 * 1024):
                got += len(chunk)
                if got >= max_bytes:
                    break
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return 0.0, got
    dt = time.perf_counter() - t0
    if got > 1_000_000 and dt > 0.05:
        return got * 8 / dt / 1e6, got
    return 0.0, got


async def download_speed_test(session: aiohttp.ClientSession, proxy: str,
                              max_bytes: int, timeout: float) -> tuple[float, int]:
    urls = list(CFG.SPEED_TEST_URLS)
    random.shuffle(urls)
    best_mbps, best_bytes = 0.0, 0
    quick = min(max_bytes, CFG.QUICK_DOWNLOAD_BYTES)
    for url in urls:
        target = quick if CFG.ADAPTIVE_SPEED_ENABLED else max_bytes
        mbps, got = await _download_once(session, proxy, url, target, timeout)
        if got > 1_000_000 and mbps > 0 and got < target:
            mbps = mbps * got / target
        if mbps > best_mbps:
            best_mbps, best_bytes = mbps, got
        if (CFG.ADAPTIVE_SPEED_ENABLED and 0 < mbps < CFG.FAST_THRESHOLD_MBPS
                and got >= target):
            second = quick if mbps < CFG.FAST_THRESHOLD_MBPS / 2 else max_bytes
            mbps2, got2 = await _download_once(session, proxy, url, second, timeout)
            if got2 > 1_000_000 and mbps2 > 0 and got2 < second:
                mbps2 = mbps2 * got2 / second
            if mbps2 > best_mbps:
                best_mbps, best_bytes = mbps2, got2
        if best_mbps > 1:
            break
    return best_mbps, best_bytes


# =============================================================================
# 8. КОНВЕЙЕР ПРОВЕРКИ
# =============================================================================

def compute_score(res: NodeResult) -> float:
    if not res.alive:
        return 0.0
    if not CFG.SPEEDTEST_ENABLED:
        worst = res.worst_latency_s
        base = (worst * 1000) if worst is not None else (res.latency_ms or 999.0)
        return round(max(0.0, 100.0 * (1.0 / (1.0 + base / 400.0))), 1)
    s = min(90.0, 20 + 25 * (res.speed_mbps ** 0.5)) if res.speed_mbps else 0.0
    p = 0.0 if res.latency_ms is None else max(0.0, min(90.0, 95 - 0.085 * res.latency_ms))
    return round(0.45 * s + 0.35 * p + 0.20 * 100.0, 1)


async def _run_check_round(session: aiohttp.ClientSession, proxy: str,
                           bytes_cap: int) -> dict | None:
    try:
        ok, dt, status = await check_site(session, proxy, CFG.CHECK_URL,
                                          CFG.SITE_TIMEOUT)
        speed, nbytes = 0.0, 0
        if ok and CFG.SPEEDTEST_ENABLED:
            speed, nbytes = await download_speed_test(
                session, proxy, bytes_cap, CFG.SPEED_TEST_TIMEOUT)
        return {"ok": ok, "latency": dt, "status": status,
                "speed": speed, "bytes": nbytes}
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return None


async def _probe_via_proxy(session: aiohttp.ClientSession, proxy: str,
                           res: NodeResult) -> bool:
    total_rounds = 1 + max(0, int(CFG.STABILITY_ROUNDS))
    for rnd in range(total_rounds):
        if rnd > 0:
            await asyncio.sleep(CFG.STABILITY_ROUND_GAP)
        cap = (CFG.SPEED_TEST_BYTES if rnd == 0
               else min(CFG.SPEED_TEST_BYTES, CFG.QUICK_DOWNLOAD_BYTES))
        out = await _run_check_round(session, proxy, cap)
        if out is None:
            res.error = f"сбой соединения (раунд {rnd + 1}/{total_rounds})"
            res.round_ok.append(False)
            res.round_latency_s.append(None)
            res.round_speed_mbps.append(0.0)
            return False

        res.round_ok.append(out["ok"])
        res.round_latency_s.append(round(out["latency"], 3) if out["ok"] else None)
        res.round_speed_mbps.append(round(out["speed"], 2))
        if rnd == 0:
            res.http_status = out["status"] or None
            res.target_latency_s = round(out["latency"], 3) if out["ok"] else None

        if not out["ok"]:
            res.error = (f"цель не открылась (раунд {rnd + 1}/{total_rounds}, "
                         f"статус {out['status'] or 'нет ответа'})")
            return False
        if CFG.MAX_TARGET_LATENCY_S > 0 and out["latency"] > CFG.MAX_TARGET_LATENCY_S:
            res.error = f"отклик {out['latency']:.2f}s > {CFG.MAX_TARGET_LATENCY_S}s"
            return False
        if CFG.SPEEDTEST_ENABLED and out["speed"] < CFG.MIN_DOWNLOAD_SPEED_MBPS:
            res.error = (f"скорость {out['speed']:.2f} < "
                         f"{CFG.MIN_DOWNLOAD_SPEED_MBPS} Мбит/с")
            return False
        res.bytes_downloaded += out["bytes"]

    res.speed_mbps = round(min(res.round_speed_mbps), 2) if CFG.SPEEDTEST_ENABLED else 0.0
    res.alive = True
    return True


async def check_one_node(link: str, sem_xray: asyncio.Semaphore,
                         sem_tcp: asyncio.Semaphore) -> NodeResult | None:
    vl = VlessLink.parse(link)
    if vl is None:
        return None
    res = NodeResult.from_link(vl)
    try:
        validate_node(vl)
    except UnsupportedNode as e:
        res.error = f"unsupported: {e}"
        return res

    cert_pin = ""
    async with sem_tcp:
        lat = await measure_tcp_latency(vl.host, vl.port)
        # FIX 3.1: дешёвый пиннинг сертификата до запуска xray
        if lat is not None and vl.security == "tls" and CFG.AUTO_PIN:
            cert_pin = await probe_peer_cert_sha256(
                vl.host, vl.port,
                vl.sni or vl.params.get("host", "") or vl.host)
    if lat is None:
        res.error = "tcp/dns: сервер ноды недоступен"
        return res
    res.latency_ms = round(lat, 1)

    async with sem_xray:
        try:
            async with running_xray(vl.raw, cert_pin=cert_pin) as xp:
                if CFG.PRECHECK_ENABLED and not await precheck_tunneled_connect(
                        xp.proxy_host, xp.proxy_port,
                        CFG.PRECHECK_HOST, CFG.PRECHECK_PORT, CFG.PRECHECK_TIMEOUT):
                    res.error = f"туннель к {CFG.PRECHECK_HOST} не проходит"
                    return res
                connector = aiohttp.TCPConnector(limit=8, ssl=False)
                async with aiohttp.ClientSession(
                        connector=connector,
                        headers={"User-Agent": CFG.USER_AGENT}) as session:
                    await _probe_via_proxy(session, xp.proxy_url, res)
        except XrayConfigError as e:
            res.error = f"config: {e}"
        except TimeoutError:
            res.error = "xray не запустился"
        except Exception as e:
            res.error = f"{type(e).__name__}: {e}"

    if res.alive:
        res.score = compute_score(res)
    return res


async def check_all(links: list[str], outdir: str = ".") -> list[NodeResult]:
    total = len(links)
    console.print(f"[bold]Проверяем {total} нод · цель: {CFG.CHECK_URL} · "
                  f"параллельно {CFG.MAX_CONCURRENT}[/]")
    sem_xray = asyncio.Semaphore(CFG.MAX_CONCURRENT)
    sem_tcp = asyncio.Semaphore(max(200, CFG.MAX_CONCURRENT * 4))

    results: list[NodeResult] = []
    stats = {"done": 0, "alive": 0}
    live_path = Path(outdir) / CFG.OUT_GOOD_FILE
    live_path.parent.mkdir(parents=True, exist_ok=True)
    live_f = open(live_path, "w", encoding="utf-8")

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console, transient=True,
    )
    t_start = time.perf_counter()
    try:
        with progress:
            task = progress.add_task("Проверка нод", total=total)

            async def worker(link: str):
                try:
                    res = await check_one_node(link, sem_xray, sem_tcp)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    res = NodeResult(link=link, error=f"worker: {type(e).__name__}: {e}")
                stats["done"] += 1
                if res is not None:
                    results.append(res)
                    if res.alive:
                        stats["alive"] += 1
                        live_f.write(res.link + "\n")
                        live_f.flush()
                progress.update(task, advance=1,
                                description=f"Ноды · живых {stats['alive']}")
                if stats["done"] % 200 == 0:
                    rate = stats["done"] / max(0.001, time.perf_counter() - t_start)
                    console.print(f"  [dim]{stats['done']}/{total} · "
                                  f"живых {stats['alive']} · {rate:.1f} нод/с[/]")

            await asyncio.gather(*(worker(l) for l in links),
                                 return_exceptions=True)
    finally:
        live_f.close()

    console.print(f"[bold green]Живых нод: {stats['alive']} из {total}[/] "
                  f"[dim]({time.perf_counter() - t_start:.0f} с)[/]")
    return results


# =============================================================================
# 9. ОТЧЁТЫ
# =============================================================================

REPORT_HEADER = ["alive", "score", "speed_Mbps", "latency_ms", "target_latency_s",
                 "worst_target_latency_s", "http_status", "rounds_passed",
                 "rounds_total", "round_latencies_s", "round_speeds_Mbps",
                 "network", "security", "country", "name", "error", "link"]


def _report_row(r: NodeResult) -> list:
    lats = ",".join("" if x is None else str(x) for x in r.round_latency_s)
    speeds = ",".join(str(x) for x in r.round_speed_mbps)
    return [int(r.alive), r.score, r.speed_mbps, r.latency_ms or "",
            r.target_latency_s or "", r.worst_latency_s or "", r.http_status or "",
            r.rounds_passed, len(r.round_ok), lats, speeds,
            r.network, r.security, r.country, r.name, r.error, r.link]


def save_results(results: list[NodeResult], outdir: str = ".",
                 include_all: bool = False) -> dict[str, str]:
    outdir_p = Path(outdir)
    outdir_p.mkdir(parents=True, exist_ok=True)
    good = [r for r in results if r.alive]
    good.sort(key=lambda r: (r.score, -(r.latency_ms or 9e9)), reverse=True)
    top = good[:CFG.TOP_N]

    p_good = outdir_p / CFG.OUT_GOOD_FILE
    p_top = outdir_p / CFG.OUT_TOP_FILE
    p_csv = outdir_p / CFG.OUT_REPORT_FILE

    def write_links(path, rows):
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(r.link + "\n")

    write_links(p_good, good)
    write_links(p_top, top)

    rows = results if include_all else good
    with open(p_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(REPORT_HEADER)
        for r in rows:
            w.writerow(_report_row(r))

    rounds = 1 + max(0, int(CFG.STABILITY_ROUNDS))
    console.print("[bold green]Сохранено:[/]")
    console.print(f"  {p_good}: {len(good)} рабочих нод "
                  f"({CFG.CHECK_NAME} во всех {rounds} раундах)")
    console.print(f"  {p_top}: топ-{len(top)}")
    console.print(f"  {p_csv}: отчёт ({len(rows)} строк"
                  f"{', включая мёртвые' if include_all else ''})")
    return {"good": str(p_good), "top": str(p_top), "report": str(p_csv)}


def _error_key(err: str) -> str:
    """FIX 3.1: корректная группировка причин отказа — сохраняет статусы,
    схлопывает только номера раундов и конкретные числовые значения."""
    e = re.sub(r"раунд \d+/\d+", "раунд N/M", err or "неизвестно")
    e = re.sub(r"отклик [\d.]+s", "отклик Xs", e)
    e = re.sub(r"скорость [\d.]+", "скорость X", e)
    return e[:150]


def print_error_breakdown(results: list[NodeResult], n: int = 10) -> None:
    dead = [r for r in results if not r.alive]
    if not dead:
        return
    reasons = Counter(_error_key(r.error) for r in dead)
    t = Table(title=f"Причины отказа ({len(dead)} нод)")
    t.add_column("Кол-во", justify="right", style="yellow")
    t.add_column("Причина", overflow="fold")
    for reason, cnt in reasons.most_common(n):
        t.add_row(str(cnt), reason)
    console.print(t)


def print_table(results: list[NodeResult], n: int = 25):
    alive = [r for r in results if r.alive]
    alive.sort(key=lambda r: r.score, reverse=True)
    t = Table(title=f"Топ-{min(n, len(alive))} нод · {CFG.CHECK_NAME} · "
                    f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC")
    t.add_column("#", style="dim", width=4)
    t.add_column("Score", justify="right", style="bold cyan")
    t.add_column("Пинг мс", justify="right")
    t.add_column("Цель с", justify="right", style="green")
    t.add_column("Худшая с", justify="right")
    if CFG.SPEEDTEST_ENABLED:
        t.add_column("Мбит/с", justify="right", style="green")
    t.add_column("Раунды", justify="center")
    t.add_column("Транспорт", justify="center")
    t.add_column("Нода", overflow="fold", max_width=40)
    for i, r in enumerate(alive[:n], 1):
        row = [str(i), f"{r.score:.1f}",
               f"{r.latency_ms:.0f}" if r.latency_ms else "-",
               f"{r.target_latency_s:.2f}" if r.target_latency_s else "-",
               f"{r.worst_latency_s:.2f}" if r.worst_latency_s else "-"]
        if CFG.SPEEDTEST_ENABLED:
            row.append(f"{r.speed_mbps:.1f}")
        row += [f"{r.rounds_passed}/{len(r.round_ok)}",
                f"{r.network}/{r.security}", r.name or r.host]
        t.add_row(*row)
    console.print(t)


def write_run_info(outdir: str, stats: dict, seed: int | None,
                   elapsed: float) -> str:
    info = {
        "version": __version__,
        "finished_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "elapsed_s": round(elapsed, 1),
        "seed": seed,
        "target": {"url": CFG.CHECK_URL, "expect_status": CFG.EXPECT_STATUS,
                   "body_match": CFG.BODY_MATCH,
                   "min_body": CFG.BODY_CHECK_MIN_BYTES,
                   "follow_redirects": CFG.FOLLOW_REDIRECTS},
        "settings": {"concurrency": CFG.MAX_CONCURRENT,
                     "stability_rounds": CFG.STABILITY_ROUNDS,
                     "stability_gap_s": CFG.STABILITY_ROUND_GAP,
                     "speedtest": CFG.SPEEDTEST_ENABLED,
                     "max_target_latency_s": CFG.MAX_TARGET_LATENCY_S,
                     "site_timeout_s": CFG.SITE_TIMEOUT,
                     "site_retries": CFG.SITE_RETRIES,
                     "tcp_timeout_s": CFG.TCP_PING_TIMEOUT,
                     "latency_samples": CFG.LATENCY_SAMPLES,
                     "precheck": CFG.PRECHECK_ENABLED,
                     "smart_dedup": CFG.SMART_DEDUP,
                     "auto_pin": CFG.AUTO_PIN},
        "stats": stats,
    }
    p = Path(outdir) / CFG.OUT_INFO_FILE
    with open(p, "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2)
    return str(p)


# =============================================================================
# 10. АВТОУСТАНОВКА XRAY
# =============================================================================

def _xray_asset() -> str:
    system = platform.system().lower()
    arch = platform.machine().lower()
    if system == "darwin":
        return ("Xray-macos-arm64-v8a.zip" if arch in ("arm64", "aarch64")
                else "Xray-macos-64.zip")
    return {
        "x86_64": "Xray-linux-64.zip",
        "amd64": "Xray-linux-64.zip",
        "aarch64": "Xray-linux-arm64-v8a.zip",
        "arm64": "Xray-linux-arm64-v8a.zip",
        "armv7l": "Xray-linux-arm32-v7a.zip",
        "armv6l": "Xray-linux-arm32-v6.zip",
    }.get(arch, "Xray-linux-64.zip")


async def install_xray(dest_dir: str | None = None) -> str:
    url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{_xray_asset()}"
    dest_dir = dest_dir or os.path.join(os.getcwd(), "xray_bin")
    os.makedirs(dest_dir, exist_ok=True)
    async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=180),
            headers={"User-Agent": CFG.USER_AGENT}) as s:
        async with s.get(url, allow_redirects=True) as r:
            r.raise_for_status()
            data = await r.read()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(dest_dir)
    binpath = os.path.join(dest_dir, "xray")
    if not os.path.isfile(binpath):
        raise RuntimeError("в архиве не оказалось бинарника xray")
    os.chmod(binpath, 0o755)
    return binpath


def ensure_xray_binary() -> bool:
    return os.path.isfile(xray_binary_path()) or shutil.which("xray") is not None


def preflight_checks(auto_install: bool) -> None:
    if os.name != "posix":
        console.print("[red]Нужен Linux/macOS (или WSL).[/]")
        sys.exit(2)
    if ensure_xray_binary():
        console.print(f"[green]xray найден:[/] {xray_binary_path()}")
        ver = _xray_version_tuple()
        if ver:
            console.print(f"[dim]версия xray: {'.'.join(map(str, ver))}[/]")
        return
    if not auto_install:
        console.print("[red]xray не найден.[/] Запустите с --install.")
        sys.exit(2)
    console.print("[yellow]Скачиваем xray...[/]")
    binpath = asyncio.run(install_xray())
    os.environ["XRAY_BINARY"] = binpath
    console.print(f"[green]xray установлен: {binpath}[/]")


# =============================================================================
# 11. CLI
# =============================================================================

async def collect_links(args, outdir: str) -> list[str]:
    if args.from_file:
        with open(args.from_file, encoding="utf-8", errors="ignore") as f:
            text = f.read()
        links = [vl.raw for vl in extract_vless_from_text(text)]
        console.print(f"[cyan]Загружено {len(links)} ссылок из {args.from_file}[/]")
        return links
    urls = load_sources(outdir, args.sources)
    with open(os.path.join(outdir, "subscription_urls.txt"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(urls))
    console.print(f"[cyan]Скачиваем {len(urls)} подписок...[/]")
    links = await fetch_links_from_urls(urls)
    console.print(f"[green]Получено {len(links)} уникальных VLESS-ссылок.[/]")
    return links


def apply_cli_overrides(args) -> None:
    apply_target(args.target or DEFAULT_TARGET)
    if args.expect_status:
        CFG.EXPECT_STATUS = args.expect_status
    if args.no_redirects:
        CFG.FOLLOW_REDIRECTS = False
    if args.redirects:
        CFG.FOLLOW_REDIRECTS = True
    if args.body_match is not None:
        CFG.BODY_MATCH = args.body_match
    if args.min_body is not None:
        CFG.BODY_CHECK_MIN_BYTES = max(0, args.min_body)
    if args.no_speedtest:
        CFG.SPEEDTEST_ENABLED = False
    if args.min_speed is not None:
        CFG.MIN_DOWNLOAD_SPEED_MBPS = max(0.0, args.min_speed)
    if args.max_target_latency is not None:
        CFG.MAX_TARGET_LATENCY_S = max(0.0, args.max_target_latency)
    if args.site_timeout is not None:
        CFG.SITE_TIMEOUT = max(1.0, args.site_timeout)
    if args.site_retries is not None:
        CFG.SITE_RETRIES = max(0, args.site_retries)
    if args.tcp_timeout is not None:
        CFG.TCP_PING_TIMEOUT = max(0.5, args.tcp_timeout)
    if args.latency_samples is not None:
        CFG.LATENCY_SAMPLES = max(1, args.latency_samples)
    if args.precheck_timeout is not None:
        CFG.PRECHECK_TIMEOUT = max(0.5, args.precheck_timeout)
    if args.no_precheck:
        CFG.PRECHECK_ENABLED = False
    if args.concurrency:
        CFG.MAX_CONCURRENT = max(1, args.concurrency)
    if args.stability is not None:
        CFG.STABILITY_ROUNDS = max(0, args.stability)
    if args.gap is not None:
        CFG.STABILITY_ROUND_GAP = max(0.0, args.gap)
    if args.top:
        CFG.TOP_N = max(1, args.top)
    if args.strict_dedup:
        CFG.SMART_DEDUP = False
    if args.default_fp:
        CFG.DEFAULT_FP = args.default_fp
    if args.no_auto_pin:
        CFG.AUTO_PIN = False


async def amain(args) -> int:
    t_start = time.perf_counter()
    try:
        apply_cli_overrides(args)
    except ValueError as e:
        console.print(f"[red]Некорректная цель:[/] {e}")
        return 2

    loop = asyncio.get_running_loop()
    loop.set_default_executor(ThreadPoolExecutor(
        max_workers=min(512, max(64, CFG.MAX_CONCURRENT * 2)),
        thread_name_prefix="vf"))

    console.print(f"[cyan]Цель:[/] {CFG.CHECK_URL}")
    console.print(f"[dim]expect={CFG.EXPECT_STATUS} · match={CFG.BODY_MATCH!r} · "
                  f"min_body={CFG.BODY_CHECK_MIN_BYTES} · "
                  f"redirects={CFG.FOLLOW_REDIRECTS} · "
                  f"speedtest={'on' if CFG.SPEEDTEST_ENABLED else 'off'} · "
                  f"раундов={1 + CFG.STABILITY_ROUNDS} · "
                  f"пауза={CFG.STABILITY_ROUND_GAP}s · "
                  f"дедуп={'умный' if CFG.SMART_DEDUP else 'строгий'} · "
                  f"auto_pin={'on' if CFG.AUTO_PIN else 'off'}[/]")

    outdir = args.out or "."
    os.makedirs(outdir, exist_ok=True)

    links = await collect_links(args, outdir)
    before = len(links)
    links = dedup_links(links)
    if before != len(links):
        console.print(f"[dim]Дедупликация: {before} -> {len(links)}[/]")
    if not links:
        console.print("[red]Не найдено ни одной VLESS-ссылки.[/]")
        return 1

    with open(os.path.join(outdir, "all_found_links.txt"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(links))

    seed = args.shuffle_seed
    if not args.no_shuffle:
        if seed is None:
            seed = random.randrange(2 ** 31)
        random.Random(seed).shuffle(links)
        console.print(f"[dim]Перемешано, seed={seed} "
                      f"(повтор: --shuffle-seed {seed})[/]")
    if args.limit:
        links = links[:args.limit]
        console.print(f"[dim]Выборка: {len(links)} нод[/]")

    results = await check_all(links, outdir)
    alive = [r for r in results if r.alive]

    save_results(results, outdir, include_all=args.report_all or not alive)
    if not alive:
        console.print("[red]Ни одна нода не прошла проверку.[/]")
        print_error_breakdown(results)
        console.print("[yellow]Подсказки:\n"
                      "  --no-precheck        исключит ложный отсев разведкой\n"
                      "  --site-timeout 20    даст медленным нодам шанс\n"
                      "  --no-auto-pin        сравнить без пиннинга сертификата\n"
                      "  --report-all         уже включён в report.csv[/]")
    else:
        print_table(results, n=min(25, CFG.TOP_N))
        if args.report_all:
            print_error_breakdown(results)

    info = write_run_info(outdir, {"total": len(links), "alive": len(alive),
                                   "dead": len(results) - len(alive)},
                          seed, time.perf_counter() - t_start)
    console.print(f"[dim]Параметры прогона: {info}[/]")
    return 0 if alive else 3


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vless_finder",
        description="Массовая проверка VLESS-подписок: стабильно ли работает "
                    "ОДНА заданная цель через ноду.")

    g = p.add_argument_group("цель")
    g.add_argument("--target", "--domain", "--url", dest="target", default="",
                   metavar="NAME|HOST|URL",
                   help=f"пресет или свой адрес; по умолчанию {DEFAULT_TARGET}")
    g.add_argument("--list-targets", action="store_true", help="показать пресеты")
    g.add_argument("--expect-status", metavar="LIST", default=None,
                   help="any | 200,204,401 | 2xx,401")
    g.add_argument("--body-match", metavar="STR", default=None)
    g.add_argument("--min-body", type=int, default=None, metavar="BYTES")
    g.add_argument("--no-redirects", action="store_true")
    g.add_argument("--redirects", action="store_true",
                   help="принудительно следовать редиректам")

    g = p.add_argument_group("скорость и качество")
    g.add_argument("--no-speedtest", action="store_true")
    g.add_argument("--min-speed", type=float, default=None, metavar="MBPS")
    g.add_argument("--max-target-latency", type=float, default=None, metavar="SEC")
    g.add_argument("--site-timeout", type=float, default=None, metavar="SEC")
    g.add_argument("--site-retries", type=int, default=None, metavar="N")
    g.add_argument("--tcp-timeout", type=float, default=None, metavar="SEC")
    g.add_argument("--latency-samples", type=int, default=None, metavar="N")
    g.add_argument("--precheck-timeout", type=float, default=None, metavar="SEC")
    g.add_argument("--no-precheck", action="store_true")
    g.add_argument("--no-auto-pin", action="store_true",
                   help="отключить авто-пиннинг сертификата TLS-нод "
                        "(для сравнения с xray 26.x)")

    g = p.add_argument_group("стабильность и масштаб")
    g.add_argument("--stability", type=int, default=None, metavar="N")
    g.add_argument("--gap", type=float, default=None, metavar="SEC")
    g.add_argument("--concurrency", "-c", type=int, default=None)
    g.add_argument("--limit", type=int, default=0)
    g.add_argument("--no-shuffle", action="store_true")
    g.add_argument("--shuffle-seed", type=int, default=None, metavar="N")
    g.add_argument("--strict-dedup", action="store_true",
                   help="не схлопывать ноды, отличающиеся только fp/insecure")
    g.add_argument("--default-fp", metavar="FP", default=None,
                   help=f"uTLS-отпечаток по умолчанию ({CFG.DEFAULT_FP})")

    g = p.add_argument_group("источники и вывод")
    g.add_argument("--sources", metavar="FILE", default="")
    g.add_argument("--from-file", metavar="FILE")
    g.add_argument("--out", default="")
    g.add_argument("--top", type=int, default=None)
    g.add_argument("--report-all", action="store_true",
                   help="в report.csv включить мёртвые ноды с причинами")
    g.add_argument("--install", action="store_true")
    g.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if args.list_targets:
        t = Table(title="Пресеты целей (--target NAME)")
        t.add_column("Имя", style="cyan")
        t.add_column("URL", overflow="fold")
        t.add_column("Статусы")
        t.add_column("Маркер")
        t.add_column("Redirects")
        t.add_column("Заметка", style="dim", overflow="fold")
        for k, v in LIGHT_TARGETS.items():
            t.add_row(k, v["url"], v["expect"], repr(v["match"]),
                      str(v.get("redirects", True)), v.get("note", ""))
        console.print(t)
        return 0

    preflight_checks(args.install)
    try:
        return asyncio.run(amain(args))
    except KeyboardInterrupt:
        console.print("\n[red]Прервано пользователем. Найденные ноды уже "
                      "записаны в good_vless.txt.[/]")
        return 130
    finally:
        kill_all_xray()


if __name__ == "__main__":
    raise SystemExit(main())