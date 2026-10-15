#!/usr/bin/env python3
"""VLESS Finder — единый исполняемый скрипт (все модули собраны в одном файле).

Сбор VLESS-подписок с известных публичных источников (GitHub API-поиск НЕ
используется), массовая проверка каждой ноды через xray и отбор лучших.

Конвейер:
    11 публичных подписок  ->  парсинг/дедупликация (в т.ч. base64)
    -> TCP-пинг            ->  доступность сайтов через SOCKS5-прокси xray
    -> замер скорости      ->  скоринг               ->  good/best/report

Запуск:
    python vless_finder.py                 # полный прогон по всем источникам
    python vless_finder.py --limit 500     # проверить только первые 500 нод
    python vless_finder.py --install       # скачать xray, если его нет
    python vless_finder.py --from-file sub.txt   # взять ссылки из локального файла

Зависимости: aiohttp, rich (+ PySocks для socks5h). Установить:
    pip install aiohttp rich PySocks

Переменные окружения (необязательные):
    VF_MAX_CONCURRENT   одновременных проверок (по умолчанию 30)
    VF_LATENCY_SAMPLES  число замеров TCP-пинга (3)
    VF_MIN_SPEED        минимальная скорость Мбит/с для топ-файла (2.0)
    VF_TOP_N            сколько лучших нод сохранить (100)
    VF_EXTRA_SOURCES    доп. URL подписок через запятую
    XRAY_BINARY         путь к бинарнику xray
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import contextlib
import csv
import io
import json
import os
import platform
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid as uuidlib
import zipfile
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

__version__ = "1.2.0"
console = Console()


# =============================================================================
# 1. МОДЕЛИ ДАННЫХ  (бывш. models.py)
# =============================================================================
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


@dataclass
class VlessLink:
    """Разобранный и валидированный URL vless://..."""
    raw: str
    uuid: str
    host: str
    port: int
    params: dict[str, str] = field(default_factory=dict)
    name: str = ""

    @property
    def security(self) -> str:
        return self.params.get("security", "none").lower()

    @property
    def network(self) -> str:
        return self.params.get("type", "tcp").lower()

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
        """Попытка определить страну по имени ноды."""
        m = re.search(r"(?:^|[\s\-|(])([A-Z]{2,3})(?:[\s\-)|]|$)", self.name)
        if m and m.group(1).upper() not in ("TLS", "TCP", "WS", "GRPC", "XTLS", "VMESS"):
            return m.group(1).upper()
        return ""

    def normalized(self) -> str:
        """Канонический вид ссылки (для дедупликации)."""
        return f"{self.uuid}@{self.host.lower()}:{self.port}?" + \
               "&".join(f"{k}={v}" for k, v in sorted(self.params.items()))

    @classmethod
    def parse(cls, link: str) -> "VlessLink | None":
        """Разбирает одну строку vless://... Возвращает None если ссылка битая."""
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
            params = {k.lower(): v for k, v in
                      parse_qsl(parsed.query, keep_blank_values=True)}
            return cls(raw=link, uuid=uid.lower(), host=host, port=port,
                       params=params, name=name)
        except ValueError:
            return None


def is_valid_uuid(u: str) -> bool:
    try:
        uuidlib.UUID(u)
        return True
    except (ValueError, AttributeError):
        return False


@dataclass
class NodeResult:
    """Итог проверки одной ноды (жива/мертва, пинг, скорость, рейтинг)."""
    link: str
    name: str = ""
    host: str = ""
    country: str = ""
    alive: bool = False                                        # прошли все обязательные сайты
    sites_ok: dict[str, float] = field(default_factory=dict)   # сайт -> время ответа
    latency_ms: float | None = None                            # минимальный пинг до ноды
    speed_mbps: float = 0.0                                    # скорость скачивания через прокси
    bytes_downloaded: int = 0
    error: str = ""
    score: float = 0.0

    @property
    def sites_ok_count(self) -> int:
        return len(self.sites_ok)

    @classmethod
    def from_link(cls, vl: VlessLink) -> "NodeResult":
        return cls(link=vl.raw, name=vl.name or vl.host,
                   host=f"{vl.host}:{vl.port}", country=vl.country_hint())


# =============================================================================
# 2. КОНФИГУРАЦИЯ  (бывш. settings.py)
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


@dataclass
class CheckConfig:
    """Параметры тестирования прокси."""
    TEST_SITES: dict[str, str] = field(default_factory=lambda: {
        "youtube": "https://www.youtube.com/generate_204",
        "telegram": "https://web.telegram.org/a/",
        "nvidia": "https://www.nvidia.com/en-us/drivers/",
        "google": "https://www.google.com/generate_204",
        "cloudflare": "https://www.cloudflare.com/cdn-cgi/trace",
        "wikipedia": "https://en.wikipedia.org/wiki/Main_Page",
    })
    REQUIRED_SITES: tuple[str, ...] = ("youtube", "telegram", "nvidia")
    SPEED_TEST_URLS: tuple[str, ...] = (
        "https://speed.cloudflare.com/__down?bytes=25000000",   # 25 МБ
        "https://proof.ovh.net/files/10Mb.dat",                 # 10 МБ
        "http://ipv4.download.thinkbroadband.com/10MB.zip",     # 10 МБ
    )
    SPEED_TEST_BYTES: int = 10 * 1024 * 1024
    SITE_TIMEOUT: float = 15.0
    SPEED_TEST_TIMEOUT: float = 30.0
    MAX_CONCURRENT: int = _env_int("VF_MAX_CONCURRENT", 30)
    LATENCY_SAMPLES: int = _env_int("VF_LATENCY_SAMPLES", 3)
    MIN_DOWNLOAD_SPEED_MBPS: float = _env_float("VF_MIN_SPEED", 2.0)
    TOP_N: int = _env_int("VF_TOP_N", 100)
    OUT_GOOD_FILE: str = "good_vless.txt"
    OUT_TOP_FILE: str = "best_vless.txt"
    OUT_REPORT_FILE: str = "report.csv"


CFG = CheckConfig()


# =============================================================================
# 3. ПАРСИНГ ПОДПИСОК  (бывш. parser.py)
# =============================================================================
VLESS_RE = re.compile(r"vless://[A-Za-z0-9_-]+@[^\s/?#'\"]+:\d{1,5}\?[^\s'\"<>]*", re.I)


def try_b64_decode(s: str) -> str | None:
    """Пытается декодировать строку как base64 (с восстановлением паддинга)."""
    s = "".join(s.split())
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", s):
        return None
    s2 = s.replace("-", "+").replace("_", "/")
    s2 += "=" * (-len(s2) % 4)
    try:
        data = base64.b64decode(s2, validate=False)
    except (binascii.Error, ValueError):
        return None
    try:
        txt = data.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        return None
    if "vless://" in txt or "vmess://" in txt or "ss://" in txt:
        return txt
    return None


def extract_vless_from_text(text: str) -> list[VlessLink]:
    """Вытаскивает все vless-ссылки из произвольного текста (файл подписок).

    Сначала прямые ссылки; если их нет — пытается раскодировать base64-блоки
    (весь текст или построчно). Дедупликация по VlessLink.normalized().
    """
    links: list[VlessLink] = []
    seen: set[str] = set()

    def add(vl: VlessLink | None):
        if vl is None:
            return
        key = vl.normalized()
        if key not in seen:
            seen.add(key)
            links.append(vl)

    for m in VLESS_RE.finditer(text):
        add(VlessLink.parse(m.group(0)))

    if links:
        return links

    candidates = [text] + text.splitlines()
    for cand in candidates:
        decoded = try_b64_decode(cand.strip())
        if decoded and "vless://" in decoded:
            for m in VLESS_RE.finditer(decoded):
                add(VlessLink.parse(m.group(0)))
        if len(links) > 5000:
            break
    return links


# =============================================================================
# 4. ИСТОЧНИКИ ПОДПИСОК  (бывш. sources.py)
# =============================================================================
# Прямые URL подписок из популярных агрегаторов бесплатных прокси.
# Список актуализирован 2026-10-16: GitHub-поиск не используется, только эти
# прямые подписки + проверенные живые старые источники (мёртвые удалены).
KNOWN_SUBSCRIPTION_URLS: list[str] = [
    # --- подписки, указанные пользователем (все живые, проверено) ---
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",   # ~250 нод
    "https://raw.githubusercontent.com/mohammadaz2/v2rayConfigsForYou/main/sub/vless.txt",                          # ~350 нод
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless",                                 # ~3600 нод
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",                                 # очень большой (~148k строк)
    "https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/main/config/protocols/vless.txt",               # ~1150 нод
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",                      # ~3750 нод
    "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/vless.txt",                           # ~350 нод
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/vless_sub.txt",                       # ~150 нод
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/vless.txt",                           # ~3800 нод
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",                                         # ~140 нод
    # --- старые источники, оставлен только живой (проверено 2026-10-16) ---
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/vless",                                               # ~10k нод
]


def load_sources(workdir: str = ".") -> list[str]:
    """Возвращает список URL источников: встроенный список + локальный файл + env."""
    urls = list(KNOWN_SUBSCRIPTION_URLS)

    local_file = os.path.join(workdir, "known_subscriptions.txt")
    if os.path.isfile(local_file):
        with open(local_file, encoding="utf-8", errors="ignore") as f:
            for line in f:
                u = line.strip()
                if u and not u.startswith("#") and u not in urls:
                    urls.append(u)

    extra = os.environ.get("VF_EXTRA_SOURCES", "")
    for u in extra.split(","):
        u = u.strip()
        if u and u not in urls:
            urls.append(u)

    return urls


async def fetch_links_from_urls(urls: list[str], concurrency: int = 10) -> list[str]:
    """Скачивает все URL и извлекает из них vless:// ссылки (в т.ч. из base64)."""
    results: list[str] = []
    sem = asyncio.Semaphore(concurrency)

    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

        async def fetch(u: str):
            async with sem:
                try:
                    async with session.get(u, headers={"User-Agent": "Mozilla/5.0"}) as r:
                        if r.status != 200:
                            return u, None
                        text = await r.text(errors="ignore")
                except Exception:
                    return u, None
                links = [vl.raw for vl in extract_vless_from_text(text)]
                return u, links

        tasks = [asyncio.create_task(fetch(u)) for u in urls]
        for coro in asyncio.as_completed(tasks):
            u, links = await coro
            if links is None:
                print(f"  [skip] источник недоступен: {u}")
            else:
                print(f"  [ok]   {len(links):>6} ссылок: {u}")
                results.extend(links)

    seen: set[str] = set()
    uniq = []
    for l in results:
        if l not in seen:
            seen.add(l)
            uniq.append(l)
    return uniq


# =============================================================================
# 5. ГЕНЕРАЦИЯ КОНФИГА XRAY  (бывш. config_builder.py)
# =============================================================================
class XrayConfigError(ValueError):
    """Конфиг для xray построить нельзя (непарсящаяся ссылка и т.п.)."""


def tls_fingerprint(vl: VlessLink) -> str:
    return vl.fingerprint or "chrome"


def _build_tls_stream(vl: VlessLink) -> dict:
    tls: dict = {}
    if vl.sni:
        tls["serverName"] = vl.sni
    if vl.fingerprint:
        tls["fingerprint"] = vl.fingerprint
    if vl.alpn:
        tls["alpn"] = [a for a in vl.alpn.split(",") if a]
    tls["allowInsecure"] = True   # тестовые ноды часто с самоподписанными cert
    return tls


def _build_reality_stream(vl: VlessLink) -> dict:
    reality = {"publicKey": vl.public_key, "fingerprint": tls_fingerprint(vl)}
    if vl.short_id:
        reality["shortId"] = vl.short_id
    return reality


def _build_ws_settings(vl: VlessLink) -> dict:
    ws: dict = {}
    if vl.params.get("path"):
        ws["path"] = vl.params["path"]
    if vl.params.get("host"):
        ws["host"] = vl.params["host"]
    if vl.params.get("ed"):  # extra data
        try:
            _mx, hdrs = vl.params["ed"].split("|", 1)
            ws["headers"] = dict([hdr.split(":", 1) for hdr in hdrs.split("&")
                                  if ":" in hdr])
        except ValueError:
            pass
    return ws


def _build_grpc_settings(vl: VlessLink) -> dict:
    grpc: dict = {"serviceName": vl.params.get("serviceName",
                                             vl.params.get("mode", ""))}
    if vl.params.get("authority"):
        grpc["authority"] = vl.params["authority"]
    if vl.params.get("mode"):
        grpc["multiMode"] = vl.params["mode"] == "multi"
    return grpc


def build_xray_config(link_raw: str, socks_port: int) -> dict:
    """Генерирует конфигурацию xray из ссылки vless://.

    Инбаунд — SOCKS5 на 127.0.0.1:socks_port (без авторизации),
    аутбаунд — VLESS-нода с соответствующим streamSettings.
    """
    vl = VlessLink.parse(link_raw)
    if vl is None:
        raise XrayConfigError("не удалось распарсить ссылку")

    encryption = vl.params.get("encryption", "none")
    vnext_user = {"id": vl.uuid, "encryption": encryption or "none"}
    if vl.flow:
        vnext_user["level"] = 0
        vnext_user["flow"] = vl.flow

    stream: dict = {"network": vl.network, "security": vl.security}
    if vl.security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = _build_reality_stream(vl)
    elif vl.security in ("tls", ""):
        if vl.security == "tls":
            stream["tlsSettings"] = _build_tls_stream(vl)

    if vl.network == "ws":
        stream["wsSettings"] = _build_ws_settings(vl)
    elif vl.network == "grpc":
        stream["grpcSettings"] = _build_grpc_settings(vl)
    elif vl.network == "http":
        stream["httpUpgradeSettings"] = {
            "host": vl.params.get("host", ""),
            "path": vl.params.get("path", "/"),
        }
    elif vl.network == "xhttp":
        stream["xhttpSettings"] = {
            "host": vl.params.get("host", ""),
            "path": vl.params.get("path", "/"),
            "mode": vl.params.get("mode", "auto"),
        }

    return {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{"address": vl.host, "port": vl.port,
                                    "users": [vnext_user]}]},
            "streamSettings": stream,
        }],
    }


# =============================================================================
# 6. МЕНЕДЖЕР ПРОЦЕССОВ XRAY  (бывш. xray_manager.py)
# =============================================================================
XRAY_BINARY = os.environ.get(
    "XRAY_BINARY",
    shutil.which("xray") or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "xray_bin", "xray"),
)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class XrayProcess:
    """Один запущенный процесс xray c SOCKS5 на 127.0.0.1:port."""

    def __init__(self, config_dict: dict):
        self._cfg = config_dict
        self._proc: subprocess.Popen | None = None
        self.port: int = config_dict["inbounds"][0]["port"]
        self._tmpdir = tempfile.mkdtemp(prefix="xraycfg_")

    @property
    def socks_proxy_url(self) -> str:
        return f"socks5h://127.0.0.1:{self.port}"

    async def start(self, wait_seconds: float = 2.5):
        cfg_path = os.path.join(self._tmpdir, "config.json")
        with open(cfg_path, "w") as f:
            json.dump(self._cfg, f)

        def _spawn():
            return subprocess.Popen(
                [XRAY_BINARY, "-config", cfg_path],
                stdout=subprocess.DEVNULL,
                stderr=open(os.path.join(self._tmpdir, "xray.log"), "wb"),
                preexec_fn=os.setsid,
            )

        self._proc = await asyncio.get_running_loop().run_in_executor(None, _spawn)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_seconds
        while loop.time() < deadline:
            if self._proc.poll() is not None:
                raise XrayConfigError(
                    f"xray завершился при старте (rc={self._proc.returncode})")
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", self.port), 0.4)
                writer.close()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), 1)
                return
            except (OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.15)
        raise TimeoutError("xray не поднял SOCKS-порт")

    async def stop(self):
        if self._proc and self._proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                self._proc.kill()
        if self._proc:
            try:
                await asyncio.get_running_loop().run_in_executor(
                    None, self._proc.wait, 5)
            except Exception:
                pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)


@asynccontextmanager
async def running_xray(link_raw: str):
    """Контекст: поднять xray-прокси для ссылки, использовать, погасить."""
    port = find_free_port()
    cfg = build_xray_config(link_raw, port)
    xp = XrayProcess(cfg)
    await xp.start()
    try:
        yield xp
    finally:
        await xp.stop()


# =============================================================================
# 7. СЕТЕВЫЕ ЗОНДЫ  (бывш. net_probe.py)
# =============================================================================
async def measure_tcp_latency(host: str, port: int, samples: int = 3) -> float | None:
    """Сколько установок TCP-соединения до сервера ноды; возвращает медиану в мс."""
    latencies: list[float] = []
    for _ in range(samples):
        t0 = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=6)
            dt = (time.perf_counter() - t0) * 1000
            latencies.append(dt)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except Exception:
                pass
        except (OSError, asyncio.TimeoutError):
            return None
        await asyncio.sleep(0.05)
    if not latencies:
        return None
    latencies.sort()
    return latencies[len(latencies) // 2]


async def check_site(session: aiohttp.ClientSession, proxy: str, url: str,
                     timeout: float) -> tuple[bool, float]:
    """Открывает сайт через SOCKS-прокси. Возвращает (доступен, время_сек)."""
    t0 = time.perf_counter()
    try:
        async with session.get(url, proxy=proxy,
                               timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=True) as r:
            ok = r.status in (200, 204, 301, 302, 307, 403) and \
                 (r.status != 403 or "cloudflare" not in url)
            if r.status >= 500:
                ok = False
            if not ok and r.status < 400:
                ok = True
            if ok:
                try:
                    await r.content.read(65536)
                except Exception:
                    pass
        dt = time.perf_counter() - t0
        return ok, dt
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return False, time.perf_counter() - t0


async def download_speed_test(session: aiohttp.ClientSession, proxy: str,
                              max_bytes: int, timeout: float) -> tuple[float, int]:
    """Качает файл через прокси, возвращает (Мбит/с, байт). Только полезная нагрузка."""
    urls = list(CFG.SPEED_TEST_URLS)
    random.shuffle(urls)
    best_mbps, best_bytes = 0.0, 0
    for url in urls:
        got = 0
        t0 = time.perf_counter()
        try:
            async with session.get(url, proxy=proxy,
                                   timeout=aiohttp.ClientTimeout(total=timeout),
                                   allow_redirects=True) as r:
                if r.status != 200:
                    continue
                async for chunk in r.content.iter_chunked(64 * 1024):
                    got += len(chunk)
                    if got >= max_bytes:
                        break
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            continue
        dt = time.perf_counter() - t0
        if got > 1_000_000 and dt > 0.05:      # минимум 1 МБ чтобы замер имел смысл
            mbps = got * 8 / dt / 1e6
            if mbps > best_mbps:
                best_mbps, best_bytes = mbps, got
        if best_mbps > 1:                       # уже нашли быстрый источник — хватит
            break
    return best_mbps, best_bytes


# =============================================================================
# 8. КОНВЕЙЕР ПРОВЕРКИ НОД  (бывш. checker.py)
# =============================================================================
def compute_score(res: NodeResult) -> float:
    """Рейтинг 0..100: скорость (45%) + пинг (35%) + покрытие сайтов (20%)."""
    if not res.alive:
        return 0.0
    s = min(90.0, 20 + 25 * (res.speed_mbps ** 0.5)) if res.speed_mbps else 0.0
    if res.latency_ms is None:
        p = 0.0
    else:
        p = max(0.0, min(90.0, 95 - 0.085 * res.latency_ms))
    c = 100.0 * res.sites_ok_count / max(1, len(CFG.TEST_SITES))
    return round(0.45 * s + 0.35 * p + 0.20 * c, 1)


async def _probe_via_proxy(session: aiohttp.ClientSession, proxy: str,
                           res: NodeResult) -> bool:
    """Проверяет обязательные сайты и меряет скорость; заполняет res.

    Возвращает True, если нода живая (все REQUIRED_SITES доступны).
    """
    tasks = {name: asyncio.create_task(
        check_site(session, proxy, url, CFG.SITE_TIMEOUT))
        for name, url in CFG.TEST_SITES.items()}
    results = await asyncio.gather(*tasks.values())
    for name, (ok, dt) in zip(tasks.keys(), results):
        if ok:
            res.sites_ok[name] = round(dt, 2)

    missing_required = [s for s in CFG.REQUIRED_SITES if s not in res.sites_ok]
    if missing_required:
        res.error = "недоступны обязательные: " + ",".join(missing_required)
        return False

    mbps, nbytes = await download_speed_test(
        session, proxy, CFG.SPEED_TEST_BYTES, CFG.SPEED_TEST_TIMEOUT)
    res.speed_mbps = round(mbps, 2)
    res.bytes_downloaded = nbytes
    res.alive = True
    return True


async def check_one_node(link: str, sem: asyncio.Semaphore) -> NodeResult | None:
    """Полная проверка одной ноды; возвращает результат или None (битая ссылка)."""
    vl = VlessLink.parse(link)
    if vl is None:
        return None
    res = NodeResult.from_link(vl)
    async with sem:
        lat = await measure_tcp_latency(vl.host, vl.port, CFG.LATENCY_SAMPLES)
        if lat is None:
            res.error = "tcp connect failed"
            return res
        res.latency_ms = round(lat, 1)

        try:
            async with running_xray(vl.raw) as xp:
                connector = aiohttp.TCPConnector(limit=8, ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    await _probe_via_proxy(session, xp.socks_proxy_url, res)
        except XrayConfigError as e:
            res.error = f"config: {e}"
        except TimeoutError:
            res.error = "xray не запустился"
        except Exception as e:  # noqa: BLE001
            res.error = f"{type(e).__name__}: {e}"
    if res.alive:
        res.score = compute_score(res)
    return res


async def check_all(links: list[str]) -> list[NodeResult]:
    """Массовая проверка всех ссылок. Возвращает список результатов живых нод."""
    total = len(links)
    console.print(f"[bold]Проверяем {total} подписок через xray "
                  f"(параллельно {CFG.MAX_CONCURRENT})...[/]")
    sem = asyncio.Semaphore(CFG.MAX_CONCURRENT)
    good: list[NodeResult] = []
    stats = {"done": 0, "alive": 0, "dead": 0}

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )

    with progress:
        task = progress.add_task("Проверка нод", total=total)

        async def worker(link: str):
            res = await check_one_node(link, sem)
            stats["done"] += 1
            if res and res.alive:
                stats["alive"] += 1
                good.append(res)
            elif res:
                stats["dead"] += 1
            progress.update(task, advance=1)
            if stats["done"] % 200 == 0:
                console.print(f"  готово {stats['done']}/{total}, "
                              f"живых {stats['alive']}, битых {stats['dead']}")

        await asyncio.gather(*(worker(l) for l in links),
                             return_exceptions=True)

    console.print(f"[bold green]Живых нод: {len(good)} из {total}[/]")
    good.sort(key=lambda r: r.score, reverse=True)
    return good


# =============================================================================
# 9. ОТЧЁТЫ  (бывш. report.py)
# =============================================================================
def save_results(results: list[NodeResult], outdir: str = ".") -> dict[str, str]:
    """Записывает good_vless.txt / best_vless.txt / report.csv. Возвращает пути."""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    good = [r for r in results if r.alive and r.speed_mbps > 0]
    good.sort(key=lambda r: (r.score, r.speed_mbps), reverse=True)
    top = good[: CFG.TOP_N]

    paths = {}

    def write_links(path, rows):
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(r.link + "\n")

    p_good = outdir / CFG.OUT_GOOD_FILE
    p_top = outdir / CFG.OUT_TOP_FILE
    p_csv = outdir / CFG.OUT_REPORT_FILE

    write_links(p_good, good)
    write_links(p_top, top)
    paths.update(good=str(p_good), top=str(p_top), report=str(p_csv))

    with open(p_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["score", "speed_Mbps", "latency_ms", "sites_ok", "country",
                    "name", "link"])
        for r in good:
            sites = ";".join(f"{k}={v}s" for k, v in sorted(r.sites_ok.items()))
            w.writerow([r.score, r.speed_mbps, r.latency_ms or "", sites,
                        r.country, r.name, r.link])

    console.print("[bold green]Сохранено:[/]")
    console.print(f"  {p_good}: {len(good)} рабочих подписок "
                  f"(YT+TG+NVIDIA доступны одновременно)")
    console.print(f"  {p_top}: топ-{len(top)} лучших по скорости/качеству")
    console.print(f"  {p_csv}: подробный отчёт")
    return paths


def print_table(results: list[NodeResult], n: int = 25):
    """Красивая таблица топ-нод в консоль."""
    t = Table(title=f"Топ-{min(n, len(results))} VLESS-нод "
                    f"({datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC)")
    t.add_column("#", style="dim", width=4)
    t.add_column("Score", justify="right", style="bold cyan")
    t.add_column("Скорость Мбит/с", justify="right", style="green")
    t.add_column("Пинг мс", justify="right")
    t.add_column("Стр", justify="center")
    t.add_column("Сайты", style="yellow")
    t.add_column("Нода", overflow="fold", max_width=40)
    for i, r in enumerate(results[:n], 1):
        sites = ",".join(sorted(r.sites_ok.keys()))
        t.add_row(str(i), f"{r.score:.0f}", f"{r.speed_mbps:.1f}",
                  f"{r.latency_ms:.0f}" if r.latency_ms else "-",
                  r.country or "?", sites, r.name or r.host)
    console.print(t)


# =============================================================================
# 10. АВТОУСТАНОВКА XRAY  (бывш. installer.py)
# =============================================================================
_XRAY_ASSETS = {
    "x86_64": "Xray-linux-64.zip",
    "amd64": "Xray-linux-64.zip",
    "aarch64": "Xray-linux-arm64-v8a.zip",
    "arm64": "Xray-macos-arm64-v8a.zip",
}


async def install_xray(dest_dir: str | None = None) -> str:
    """Скачивает последний релиз xray для текущей платформы и распаковывает."""
    arch = platform.machine().lower()
    asset = _XRAY_ASSETS.get(arch, "Xray-linux-64.zip")
    url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{asset}"
    if dest_dir is None:
        dest_dir = os.path.join(os.getcwd(), "xray_bin")
    os.makedirs(dest_dir, exist_ok=True)

    async with aiohttp.ClientSession() as s:
        async with s.get(url) as r:
            r.raise_for_status()
            data = await r.read()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(dest_dir)
    binpath = os.path.join(dest_dir, "xray")
    os.chmod(binpath, 0o755)
    return binpath


def ensure_xray_binary() -> bool:
    """Есть ли уже xray рядом со скриптом или в PATH."""
    return os.path.isfile(XRAY_BINARY) or shutil.which("xray") is not None


# =============================================================================
# 11. CLI  (бывш. __main__.py)
# =============================================================================
def preflight_checks(auto_install: bool) -> None:
    """Проверяем наличие xray; при --install скачиваем бинарник."""
    if ensure_xray_binary():
        console.print(f"[green]xray найден:[/] {XRAY_BINARY}")
        return
    if not auto_install:
        console.print("[red]xray не найден.[/] Установите его "
                      "(https://github.com/XTLS/Xray-core/releases) или запустите "
                      "с --install, чтобы скачать автоматически.")
        sys.exit(2)
    console.print("[yellow]Скачиваем xray...[/]")
    binpath = asyncio.run(install_xray())
    console.print(f"[green]xray установлен в {binpath}[/]")


async def collect_links(args, outdir: str) -> list[str]:
    """Фаза сбора ссылок: локальный файл ИЛИ прямые подписки из источников."""
    if args.from_file:
        with open(args.from_file, encoding="utf-8", errors="ignore") as f:
            text = f.read()
        links = [vl.raw for vl in extract_vless_from_text(text)]
        console.print(f"[cyan]Загружено {len(links)} подписок из {args.from_file}[/]")
        return links

    urls = load_sources(outdir)
    cache_path = os.path.join(outdir, "subscription_urls.txt")
    with open(cache_path, "w") as f:
        f.write("\n".join(urls))
    console.print(f"[cyan]Скачиваем {len(urls)} подписок (GitHub-поиск отключён)...[/]")
    links = await fetch_links_from_urls(urls)
    console.print(f"[green]Подписки дали {len(links)} уникальных VLESS-ссылок.[/]")
    return links


async def amain(args) -> int:
    if args.concurrency:
        CFG.MAX_CONCURRENT = args.concurrency
    if args.min_speed is not None:
        CFG.MIN_DOWNLOAD_SPEED_MBPS = args.min_speed
    if args.top:
        CFG.TOP_N = args.top
    outdir = args.out or "."
    os.makedirs(outdir, exist_ok=True)

    # ---------- фаза сбора ссылок ----------
    links = await collect_links(args, outdir)
    if not links:
        console.print("[red]Не найдено ни одной VLESS-подписки. "
                      "Проверьте доступность источников в KNOWN_SUBSCRIPTION_URLS.[/]")
        return 1

    dump = os.path.join(outdir, "all_found_links.txt")
    with open(dump, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    console.print(f"[dim]Все найденные ссылки сохранены в {dump}[/]")

    if args.limit:
        links = links[: args.limit]

    # ---------- фаза проверки ----------
    results = await check_all(links)
    if not results:
        console.print("[red]Ни одна нода не прошла проверку (все сайты недоступны "
                      "или скорость 0).[/]")
        return 3

    best = [r for r in results if r.speed_mbps >= CFG.MIN_DOWNLOAD_SPEED_MBPS]
    console.print(f"[bold]Прошли порог скорости "
                  f">= {CFG.MIN_DOWNLOAD_SPEED_MBPS} Мбит/с: {len(best)} нод[/]")

    save_results(best, outdir)
    print_table(best, n=min(25, CFG.TOP_N))
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vless_finder",
        description="Сбор VLESS-подписок с известных публичных источников (без GitHub API-поиска), "
                    "массовая проверка доступности "
                    "сайтов (YouTube/Telegram/NVIDIA...) и замера скорости скачивания. "
                    "В файл попадают только ноды, у которых ВСЁ работает вместе.")
    p.add_argument("--concurrency", "-c", type=int, default=None,
                   help=f"одновременных проверок (по умолчанию {CFG.MAX_CONCURRENT})")
    p.add_argument("--min-speed", type=float, default=None,
                   help="минимальная скорость скачивания Мбит/с для топ-файла")
    p.add_argument("--top", type=int, default=None,
                   help=f"сколько лучших нод сохранить (по умолчанию {CFG.TOP_N})")
    p.add_argument("--limit", type=int, default=0,
                   help="проверить только первые N найденных ссылок (0 = все)")
    p.add_argument("--out", default="", help="папка для результатов (по текущей)")
    p.add_argument("--from-file", metavar="FILE",
                   help="взять подписки из локального файла вместо скачивания источников")
    p.add_argument("--install", action="store_true",
                   help="автоматически скачать xray если он не установлен")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    preflight_checks(args.install)
    try:
        return asyncio.run(amain(args))
    except KeyboardInterrupt:
        console.print("\n[red]Прервано пользователем.[/]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
