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
    VF_PRECHECK         0 — отключить дешёвую разведку CONNECT перед полным
                        циклом проверки (по умолчанию включена)
    VF_PRECHECK_TIMEOUT таймаут разведки, сек (6.0)
    VF_ADAPTIVE_SPEED   0 — качать тестовый файл всегда полным объёмом
                        (по умолчанию адаптивный замер: быстрые ноды
                        останавливаются на 2 МБ)
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

__version__ = "1.3.0"
console = Console()


# =============================================================================
# 1. МОДЕЛИ ДАННЫХ  (бывш. models.py)
# =============================================================================
# Канонический формат UUID: 8-4-4-4-12 hex-символов.
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def resolve_security(p: dict[str, str]) -> str:
    """Единая точка резолвинга security для дедупликации и генератора конфига.

    Раньше `security=auto` интерпретировался двумя разными способами:
    effective_params() считал его TLS при наличии sni/fp/alpn, а билдер
    конфига — plaintext без TLS-секции. Одна и та же нода дедуплицировалась
    как TLS, а тестировалась как открытое соединение — расхождение давало
    ложные вердикты. Теперь обе ветки вызывают эту функцию.
    """
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
    """Разобранный и валидированный URL vless://..."""
    raw: str
    uuid: str
    host: str
    port: int
    params: dict[str, str] = field(default_factory=dict)
    name: str = ""

    @property
    def security(self) -> str:
        """Эффективная security с учётом подразумеваемых значений."""
        return resolve_security(self.params)

    @property
    def network(self) -> str:
        t = self.params.get("type", "tcp").lower()
        # alias'ы из подписок: websocket -> ws, httpupgrade остаётся как есть
        return {"websocket": "ws"}.get(t, t)

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

    def effective_params(self) -> dict[str, str]:
        """Параметры со значениями по умолчанию и алиасами.

        Две физически одинаковые ноды, записанные с разными написаниями
        (type=websocket vs type=ws, отсутствие security=none и т.п.),
        дают одинаковый результат — иначе дедупликация их не схлопнет
        и одна нода проверяется несколько раз.
        """
        p = dict(self.params)
        # security нормализуется единой функцией resolve_security():
        # значение по умолчанию, auto и подразумевание по sni/fp/alpn/pbk —
        # тот же код, что использует генератор конфига xray
        sec = resolve_security(p)
        net = p.get("type", "tcp").lower()
        net = {"websocket": "ws"}.get(net, net)
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
            # имена query-параметров приводятся к нижнему регистру при парсинге,
            # поэтому обращаться надо к "servicename" (см. VlessLink.parse)
            "serviceName": p.get("servicename", ""),
        }
        if sec == "reality":
            eff["pbk"] = p.get("pbk") or p.get("public-key", "")
            eff["sid"] = p.get("sid") or p.get("short-id", "")
        elif sec == "tls":
            # allowInsecure всегда принудительно включён в тестовом конфиге,
            # поэтому на физическую идентичность ноды не влияет
            pass
        for k, v in p.items():
            if k not in eff and k not in ("public-key", "short-id"):
                eff[k] = v.strip().lower() if isinstance(v, str) else v
        return {k: v for k, v in eff.items() if v != ""}

    def dedup_key(self) -> str:
        """Эффективный ключ дедупликации (без имени узла)."""
        e = self.effective_params()
        return f"{self.uuid}@{self.host.lower()}:{self.port}?" + \
               "&".join(f"{k}={v}" for k, v in sorted(e.items()))

    def normalized(self) -> str:
        """Канонический вид ссылки (для дедупликации)."""
        return self.dedup_key()

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
    # Стабильность (см. STABILITY_ROUNDS): round 0 — основной замер, далее
    # контрольные раунды. списки равны по длине; элементы None = сбой раунда.
    round_sites_ok: list[int] = field(default_factory=list)    # число сайтов в раунде
    round_speed_mbps: list[float] = field(default_factory=list)
    round_max_site_latency: list[float | None] = field(default_factory=list)

    @property
    def sites_ok_count(self) -> int:
        return len(self.sites_ok)

    @property
    def coverage_pct(self) -> float:
        """Худшее покрытие обязательных сайтов по всем раундам, %.

        Нода проходит только при 100% во всех раундах, поэтому для живых нод
        это всегда 100.0 — колонка служит доказательством стабильности.
        """
        if not self.round_sites_ok:
            return 100.0 * self.sites_ok_count / max(1, len(CFG.REQUIRED_SITES))
        return 100.0 * min(self.round_sites_ok) / len(CFG.REQUIRED_SITES)

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
    # Проверка «живости» ноды идёт ТОЛЬКО по обязательным сайтам (см.
    # REQUIRED_SITES) — раньше дополнительно опрашивались google/cloudflare/
    # wikipedia, но на отбор они не влияли, а лишь замедляли каждый прогон
    # (3 лишних запроса × SITE_RETRIES retries на каждую из сотен нод).
    TEST_SITES: dict[str, str] = field(default_factory=lambda: {
        # Главная страница YouTube вместо /generate_204: эндпоинт 204 может
        # отвечать даже когда основной контент youtube.com блокируется/не
        # грузится. Проверка «главная реально скачивается» — как при загрузке
        # видео; порог тела см. BODY_CHECK_MIN_BYTES.
        "youtube": "https://www.youtube.com/",
        "telegram": "https://web.telegram.org/a/",
        # API-эндпоинт вместо тяжёлой страницы /en-us/drivers/: отвечает
        # быстро и стабильно (401 без токена = хост достижим через прокси).
        "nvidia": "https://integrate.api.nvidia.com/v1",
    })
    # Минимальный объём загруженного тела HTML-страницы, чтобы считать её
    # реально скачиваемой (а не «пустым» ответом балансировщика).
    BODY_CHECK_MIN_BYTES: int = 1024
    REQUIRED_SITES: tuple[str, ...] = ("youtube", "telegram", "nvidia")
    SPEED_TEST_URLS: tuple[str, ...] = (
        "https://speed.cloudflare.com/__down?bytes=25000000",   # 25 МБ
        "https://proof.ovh.net/files/10Mb.dat",                 # 10 МБ
        "http://ipv4.download.thinkbroadband.com/10MB.zip",     # 10 МБ
    )
    SPEED_TEST_BYTES: int = 10 * 1024 * 1024
    SITE_RETRIES: int = 2        # повторы при таймаутах (тяжёлые страницы типа
                                 # web.telegram.org через медленные ноды не успевают за один проход)
    SITE_TIMEOUT: float = 15.0
    SPEED_TEST_TIMEOUT: float = 30.0
    MAX_CONCURRENT: int = _env_int("VF_MAX_CONCURRENT", 30)
    LATENCY_SAMPLES: int = _env_int("VF_LATENCY_SAMPLES", 3)

    # --- ускорение конвейера -------------------------------------------------
    # «Разведка» перед запуском xray: дешёвый HTTP-CONNECT до сайта через
    # TCP-туннель ноды (без TLS и без скачивания тела). Если нода не может
    # даже установить туннель к youtube — запускать ради неё xray, опрашивать
    # сайты и качать тестовый файл бессмысленно. Отсевает мёртвые/заблокированные
    # ноды за доли секунды вместо полного цикла (~минуты на медленных нодах).
    PRECHECK_ENABLED: bool = os.environ.get("VF_PRECHECK", "1") != "0"
    PRECHECK_HOST: str = "www.youtube.com"
    PRECHECK_PORT: int = 443
    PRECHECK_TIMEOUT: float = _env_float("VF_PRECHECK_TIMEOUT", 6.0)
    # Адаптивный замер скорости: полный объём (SPEED_TEST_BYTES) качается
    # только если по первым байтам скорость ниже FAST_THRESHOLD_MBPS — иначе
    # быстрый результат надёжен уже на малом объёме и экономит ~10 МБ трафика
    # и секунды на каждую из сотен живых нод.
    ADAPTIVE_SPEED_ENABLED: bool = os.environ.get("VF_ADAPTIVE_SPEED", "1") != "0"
    FAST_THRESHOLD_MBPS: float = 80.0
    QUICK_DOWNLOAD_BYTES: int = 2 * 1024 * 1024
    MIN_DOWNLOAD_SPEED_MBPS: float = _env_float("VF_MIN_SPEED", 2.0)

    # --- стабильность ---------------------------------------------------------
    # Требование: покрытие 100% (все обязательные сайты) НЕ разово, а во всех
    # раундах проверки подряд. Кратковременные «вспышки живости» (нода
    # ответила один раз и пропала) отсекаются контрольными раундами:
    STABILITY_ROUNDS: int = _env_int("VF_STABILITY_ROUNDS", 2)   # доп. контрольных раундов после основного
    STABILITY_ROUND_GAP: float = _env_float("VF_STABILITY_GAP", 3.0)  # пауза между раундами, сек
    # В финальном рейтинге скорость считается как МИНИМУМ по всем раундам
    # (худший случай честнее среднего: «быстрая», но нестабильная нода не
    # получит ложно-высокое место).
    TOP_N: int = _env_int("VF_TOP_N", 100)
    OUT_GOOD_FILE: str = "good_vless.txt"
    OUT_TOP_FILE: str = "best_vless.txt"
    OUT_REPORT_FILE: str = "report.csv"


CFG = CheckConfig()

# Сколько тела страницы читать за один проход при проверке доступности
# (достаточно для вердикта «главная грузится», не скачиваем весь HTML).
BODY_CHECK_READ_BYTES = 262144


# =============================================================================
# 3. ПАРСИНГ ПОДПИСОК  (бывш. parser.py)
# =============================================================================
# Query теперь необязателен: ссылки вида vless://uuid@host:port#name раньше
# молча терялись, потому что обязательный "\?" не совпадал.
VLESS_RE = re.compile(r"vless://[A-Za-z0-9_-]+@[^\s/?#'\"]+:\d{1,5}(?:\?[^\s'\"<>]*)?", re.I)


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

    Прямые ссылки и base64-блоки (весь текст или построчно) обрабатываются
    ВСЕГДА — раньше base64 игнорировался, если в тексте нашлась хотя бы одна
    прямая ссылка, и часть нод молча терялась.
    Дедупликация: сначала по каноническому виду (normalized), затем по
    эффективному ключу (dedup_key) — физически одинаковые ноды с разными
    написаниями параметров схлопываются в одну.
    """
    links: list[VlessLink] = []
    seen_norm: set[str] = set()
    seen_eff: set[str] = set()

    def add(vl: VlessLink | None):
        if vl is None:
            return
        key = vl.normalized()
        if key in seen_norm:
            return
        ekey = vl.dedup_key()
        if ekey in seen_eff:
            return
        seen_norm.add(key)
        seen_eff.add(ekey)
        links.append(vl)

    def harvest(src: str):
        for m in VLESS_RE.finditer(src):
            add(VlessLink.parse(m.group(0)))

    harvest(text)

    # base64-блоки декодируем всегда, а не только когда прямых ссылок нет
    candidates = [text] + text.splitlines()
    for cand in candidates:
        decoded = try_b64_decode(cand.strip())
        if decoded and "vless://" in decoded:
            harvest(decoded)
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


def dedup_links(raw_links: list[str]) -> list[str]:
    """Дедупликация сырых ссылок по эффективному ключу (без имени узла).

    Разные написания одной физической ноды (type=ws vs type=websocket,
    явные/подразумеваемые security/path и т.п.) схлопываются в одну — иначе
    лимит --limit съедают дубли и одна нода проверяется несколько раз.
    """
    seen_norm: set[str] = set()
    seen_eff: set[str] = set()
    uniq: list[str] = []
    for l in raw_links:
        vl = VlessLink.parse(l)
        if vl is None:
            continue
        nk, ek = vl.normalized(), vl.dedup_key()
        if nk in seen_norm or ek in seen_eff:
            continue
        seen_norm.add(nk)
        seen_eff.add(ek)
        uniq.append(vl.raw)
    return uniq


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

    return dedup_links(results)


# =============================================================================
# 5. ГЕНЕРАЦИЯ КОНФИГА XRAY  (бывш. config_builder.py)
# =============================================================================
class XrayConfigError(ValueError):
    """Конфиг для xray построить нельзя (непарсящаяся ссылка и т.п.)."""


_XRAY_VER_CACHE: tuple | None = None


def _xray_binary_path() -> str:
    """Путь к бинарнику xray (env XRAY_BINARY -> PATH -> ./xray_bin/xray).

    Вычисляется при каждом вызове, а не на уровне модуля: раньше константа
    XRAY_BINARY определялась в секции 6, а читалась из функции в секции 5 —
    порядок работал лишь по случайности отложенного вызова.
    """
    return os.environ.get(
        "XRAY_BINARY",
        shutil.which("xray") or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                             "xray_bin", "xray"),
    )


def _xray_version_tuple() -> tuple:
    """Версия бинарника xray, кэшируется. Пустой кортеж — определить не удалось."""
    global _XRAY_VER_CACHE
    if _XRAY_VER_CACHE is None:
        ver = ()
        try:
            out = subprocess.run([_xray_binary_path(), "version"], capture_output=True,
                                 text=True, timeout=10).stdout
            m = re.search(r"Xray\s+(\d+)\.(\d+)\.(\d+)", out)
            if m:
                ver = tuple(int(g) for g in m.groups())
        except Exception:  # noqa: BLE001
            pass
        _XRAY_VER_CACHE = ver
    return _XRAY_VER_CACHE


def _tls_insecure_field() -> dict:
    """Поле отключения проверки сертификата с учётом версии xray.

    В xray >= 25.12 опция allowInsecure удалена и заменена на
    disableSystemRooting (включённая проверка только системными корнями
    без привязки к имени) — это ближайший аналог старого allowInsecure
    для теста публичных нод с самоподписанными/чужими сертификатами.
    """
    ver = _xray_version_tuple()
    if ver and ver >= (25, 12, 0):
        return {"disableSystemRooting": True}
    return {"allowInsecure": True}


def _build_tls_stream(vl: VlessLink) -> dict:
    tls: dict = {}
    if vl.sni:
        tls["serverName"] = vl.sni
    if vl.fingerprint:
        tls["fingerprint"] = vl.fingerprint
    else:
        # без uTLS-отпечатка xray использует обычный TLS (runtime бинарника),
        # а не фолбэк "chrome", который может не совпасть с ожиданиями сервера
        tls["fingerprint"] = ""
    if vl.alpn:
        tls["alpn"] = [a for a in vl.alpn.split(",") if a]
    tls.update(_tls_insecure_field())   # тестовые ноды часто с самоподписанными cert
    return tls


def _build_reality_stream(vl: VlessLink) -> dict:
    reality: dict = {"publicKey": vl.public_key}
    if vl.fingerprint:
        reality["fingerprint"] = vl.fingerprint
    else:
        reality["fingerprint"] = ""
    if vl.sni:
        reality["serverName"] = vl.sni
    if vl.short_id:
        reality["shortId"] = vl.short_id
    return reality


# потоки/безопасность, которые xray точно принимает в streamSettings
SUPPORTED_NETWORKS = {"tcp", "ws", "grpc", "http", "xhttp"}
SUPPORTED_SECURITY = {"none", "tls", "reality"}


class UnsupportedNode(ValueError):
    """Нода использует протокол/настройки, которые xray не примет."""


def validate_node(vl: VlessLink) -> None:
    """Отсекает заведомо неподдерживаемые ноды ДО запуска xray.

    Без проверки xray падает на старте процесса и нода помечается как
    «мёртвая», хотя она просто не поддерживается парсером.
    """
    net = vl.network
    # security уже резолвится через resolve_security() (в т.ч. auto -> none),
    # поэтому здесь сравниваемся только с реально поддерживаемыми значениями
    sec = vl.security
    if sec not in SUPPORTED_SECURITY:
        raise UnsupportedNode(f"security={sec} не поддерживается")
    if net not in SUPPORTED_NETWORKS:
        raise UnsupportedNode(f"type={net} не поддерживается")
    if sec == "reality" and not vl.public_key:
        raise UnsupportedNode("reality без pbk (публичный ключ отсутствует)")
    if vl.flow and vl.flow not in ("", "xtls-rpb", "xtls-rprx-vision"):
        # опечатки вида xtls-rpб (кириллица) или неизвестные flow — xray отвергнет конфиг
        raise UnsupportedNode(f"flow={vl.flow!r} не поддерживается")


def _build_ws_settings(vl: VlessLink) -> dict:
    ws: dict = {}
    path = vl.params.get("path")
    if path:
        ws["path"] = unquote(path)
    if vl.params.get("host"):
        ws["host"] = vl.params["host"]
    if vl.params.get("ed"):  # extra data: "<max>|Header:value&Header2:value2"
        try:
            _mx, hdrs = vl.params["ed"].split("|", 1)
            headers = {}
            for hdr in unquote(hdrs).split("&"):
                if ":" in hdr:
                    k, v = hdr.split(":", 1)
                    headers[k.strip()] = v.strip()
            if headers:
                ws["headers"] = headers
        except ValueError:
            pass
    return ws


def _build_grpc_settings(vl: VlessLink) -> dict:
    mode = vl.params.get("mode", "")
    service = vl.params.get("servicename", "")
    if not service and mode and mode != "multi":
        # в некоторых подписках serviceName приезжает в параметре mode;
        # значение "multi" — это режим мультиплексирования, не имя сервиса
        service = mode
    grpc: dict = {"serviceName": service}
    if vl.params.get("authority"):
        grpc["authority"] = vl.params["authority"]
    if mode:
        grpc["multiMode"] = mode == "multi"
    return grpc


def build_xray_config(link_raw: str, socks_port: int) -> dict:
    """Генерирует конфигурацию xray из ссылки vless://.

    Инбаунд — SOCKS5 на 127.0.0.1:socks_port (без авторизации),
    аутбаунд — VLESS-нода с соответствующим streamSettings.
    """
    vl = VlessLink.parse(link_raw)
    if vl is None:
        raise XrayConfigError("не удалось распарсить ссылку")
    validate_node(vl)

    encryption = vl.params.get("encryption", "none")
    vnext_user = {"id": vl.uuid, "encryption": encryption or "none"}
    if vl.flow:
        vnext_user["level"] = 0
        vnext_user["flow"] = vl.flow

    # vl.security уже резолвится через resolve_security() — та же логика,
    # что и в effective_params()/дедупликации: security=auto больше не
    # расходится между «нода считается TLS» и «тестируется как plaintext»
    sec = vl.security
    stream: dict = {"network": vl.network, "security": sec}
    if sec == "reality":
        stream["realitySettings"] = _build_reality_stream(vl)
    elif sec == "tls":
        stream["tlsSettings"] = _build_tls_stream(vl)

    if vl.network == "ws":
        stream["wsSettings"] = _build_ws_settings(vl)
    elif vl.network == "grpc":
        stream["grpcSettings"] = _build_grpc_settings(vl)
    elif vl.network == "http":
        stream["httpUpgradeSettings"] = {
            "host": vl.params.get("host", ""),
            "path": unquote(vl.params.get("path", "/")) or "/",
        }
    elif vl.network == "xhttp":
        stream["xhttpSettings"] = {
            "host": vl.params.get("host", ""),
            "path": unquote(vl.params.get("path", "/")) or "/",
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
XRAY_BINARY = _xray_binary_path()


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
    """Сколько установок TCP-соединения до сервера ноды; возвращает медиану в мс.

    Единичный сетевой глитч больше не убивает ноду: неудачи допускаются,
    если хотя бы часть замеров успешна (не менее MIN_SUCCESS из samples).
    Результат возвращается только когда ни один замер не прошёл.
    """
    samples = max(1, samples)
    min_success = max(1, (samples + 1) // 2)   # нужно >50% успешных замеров
    latencies: list[float] = []
    failures = 0
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
            failures += 1
        await asyncio.sleep(0.05)
    if len(latencies) < min_success:
        return None
    latencies.sort()
    return latencies[len(latencies) // 2]


async def precheck_tunneled_connect(proxy: str, host: str, port: int,
                                    timeout: float) -> bool:
    """Дешёвая «разведка» туннеля ноды ДО полноценной проверки.

    Открывает SOCKS5h-туннель и шлёт HTTP/1.1 `CONNECT host:port` (без TLS и
    без скачивания тела). Если нода не может установить туннель даже до
    youtube.com — запускать ради неё xray-цикл с опросом сайтов и закачкой
    тестового файла бессмысленно: это экономит десятки секунд на каждой
    мёртвой/заблокированной ноде (а таких большинство в публичных подписках).

    Возвращает True при ответе 2xx (туннель к цели проходит). Исключение —
    любой сетевой сбой/таймаут: решение о жизни ноды тогда принимает
    полный цикл проверки (precheck лишь ускоряет явные провалы).
    """
    try:
        async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=timeout)) as s:
            async with s.request("CONNECT", f"https://{host}:{port}",
                                 proxy=proxy) as r:
                return 200 <= r.status < 300
    except Exception:  # noqa: BLE001 — таймаут/обрыв = «не отсеиваем», решит полный цикл
        return True


async def check_site(session: aiohttp.ClientSession, proxy: str, url: str,
                     timeout: float) -> tuple[bool, float]:
    """Открывает сайт через SOCKS-прокси. Возвращает (доступен, время_сек).

    Для HTML-страниц (youtube, telegram) успех = статус 2xx/3xx И реально
    загруженное тело >= BODY_CHECK_MIN_BYTES байт: главная страница должна
    скачиваться целиком, а не только «пинговаться» служебным эндпоинтом.
    Повторяет попытку при таймаутах (SITE_RETRIES раз): тяжёлые страницы
    через медленные ноды часто не успевают за один проход, и без повторов
    живые ноды ложно помечались мёртвыми.
    """
    attempts = 1 + max(0, CFG.SITE_RETRIES if _is_timeout_url(url) else 2)
    t_total = 0.0
    for attempt in range(attempts):
        ok, dt = await _check_site_once(session, proxy, url, timeout)
        t_total += dt
        if ok:
            return True, t_total
    return False, t_total


def _is_timeout_url(url: str) -> bool:
    # «Тяжёлые» страницы (полный HTML, а не пустые 204-эндпоинты) требуют
    # полных SITE_RETRIES повторов: через медленные ноды они не успевают
    # за один проход.
    return "generate_204" not in url and "cdn-cgi/trace" not in url


def _needs_body_check(url: str) -> bool:
    """HTML-страницы проверяются «по телу»: 200 с пустым/обрезанным ответом
    (частый случай для youtube.com на заблокированных направлениях — эндпоинт
    /generate_204 отвечает, а контент не грузится) НЕ считается успехом —
    главная страница должна реально скачиваться.
    API-эндпоинты (nvidia) и служебные 204-адреса проверяются только по статусу.
    """
    return ("youtube.com" in url or "telegram.org" in url) and \
           "generate_204" not in url


async def _check_site_once(session: aiohttp.ClientSession, proxy: str, url: str,
                           timeout: float) -> tuple[bool, float]:
    """Одна попытка открытия сайта через SOCKS-прокси."""
    t0 = time.perf_counter()
    try:
        async with session.get(url, proxy=proxy,
                               timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=True) as r:
            # Белый список статусов = «хост достижим через прокси».
            ok = r.status in (200, 204, 301, 302, 307, 403) and \
                 (r.status != 403 or "cloudflare" not in url)
            if r.status >= 500:
                ok = False
            # API-эндпоинты (например, integrate.api.nvidia.com/v1) отдают
            # 404/401 без корректного пути/токена — это нормальный ответ
            # сервера: TLS через прокси прошёл, хост достижим.
            if not ok and r.status in (401, 404):
                ok = True
            if ok:
                # Читаем тело до BODY_CHECK_READ_BYTES байт: для HTML-страниц
                # объём ответа идёт в вердикт («главная реально грузится»),
                # для остальных — просто прогреваем соединение.
                body_bytes = 0
                try:
                    chunk = await r.content.read(BODY_CHECK_READ_BYTES)
                    body_bytes = len(chunk)
                except Exception:
                    body_bytes = 0
                if _needs_body_check(url) and r.status == 200 and \
                        body_bytes < CFG.BODY_CHECK_MIN_BYTES:
                    ok = False
        dt = time.perf_counter() - t0
        return ok, dt
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return False, time.perf_counter() - t0


async def _download_once(session: aiohttp.ClientSession, proxy: str, url: str,
                         max_bytes: int, timeout: float) -> tuple[float, int]:
    """Одна закачка тестового файла; возвращает (Мбит/с, байт) по полезной нагрузке."""
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
    if got > 1_000_000 and dt > 0.05:      # минимум 1 МБ чтобы замер имел смысл
        return got * 8 / dt / 1e6, got
    return 0.0, got


async def download_speed_test(session: aiohttp.ClientSession, proxy: str,
                              max_bytes: int, timeout: float) -> tuple[float, int]:
    """Качает файл через прокси, возвращает (Мбит/с, байт). Только полезная нагрузка.

    Адаптивный объём (точность + скорость): сначала качается малый кусок
    QUICK_DOWNLOAD_BYTES; если измеренная по нему скорость уже выше
    FAST_THRESHOLD_MBPS — результат надёжен и полный объём не нужен (экономия
    ~10 МБ трафика и секунд на каждой быстрой ноде). Медленные ноды добираются
    до полного max_bytes — их замер остаётся таким же точным, как раньше.
    """
    urls = list(CFG.SPEED_TEST_URLS)
    random.shuffle(urls)
    best_mbps, best_bytes = 0.0, 0
    quick = min(max_bytes, CFG.QUICK_DOWNLOAD_BYTES)
    for url in urls:
        target = quick if CFG.ADAPTIVE_SPEED_ENABLED else max_bytes
        mbps, got = await _download_once(session, proxy, url, target, timeout)
        # Приводим частичный замер (например, таймаут на середине объёма) к
        # полному времени скачивания: иначе обрыв на последнем килобайте
        # завышал скорость в разы и нода получала ложно-высокий рейтинг.
        if got > 1_000_000 and mbps > 0 and got < target:
            mbps = mbps * got / target
        if mbps > best_mbps:
            best_mbps, best_bytes = mbps, got
        if (CFG.ADAPTIVE_SPEED_ENABLED and 0 < mbps < CFG.FAST_THRESHOLD_MBPS
                and got >= target):
            # быстрые ноды пропускают этот шаг; медленные докачивают полный
            # объём тем же источником (сопоставимые замеры, без «перескока»
            # между серверами разной пропускной способности). Повторный замер
            # сам по себе адаптивный: если и он стартует медленно — прерываем
            # закачку раньше полного объёма, время всё равно пересчитано.
            second_target = quick if mbps < CFG.FAST_THRESHOLD_MBPS / 2 else max_bytes
            mbps2, got2 = await _download_once(session, proxy, url, second_target, timeout)
            if got2 > 1_000_000 and mbps2 > 0 and got2 < second_target:
                mbps2 = mbps2 * got2 / second_target
            if mbps2 > best_mbps:
                best_mbps, best_bytes = mbps2, got2
        if best_mbps > 1:                       # уже нашли быстрый источник — хватит
            break
    return best_mbps, best_bytes


# =============================================================================
# 8. КОНВЕЙЕР ПРОВЕРКИ НОД  (бывш. checker.py)
# =============================================================================
def compute_score(res: NodeResult) -> float:
    """Рейтинг 0..100: скорость (45%) + пинг (35%) + отклик сайтов (20%).

    Компонента «отклик» = худшее покрытие обязательных сайтов по всем раундам
    (см. coverage_pct): стабильная живая нода даёт 100% и ранжируется по
    скорости (минимум по раундам) и пингу.
    """
    if not res.alive:
        return 0.0
    s = min(90.0, 20 + 25 * (res.speed_mbps ** 0.5)) if res.speed_mbps else 0.0
    if res.latency_ms is None:
        p = 0.0
    else:
        p = max(0.0, min(90.0, 95 - 0.085 * res.latency_ms))
    c = res.coverage_pct
    return round(0.45 * s + 0.35 * p + 0.20 * c, 1)


async def _run_check_round(session: aiohttp.ClientSession, proxy: str) -> dict:
    """Один раунд проверки: все обязательные сайты + замер скорости.

    Возвращает {"sites": {сайт: сек}, "speed": Мбит/с, "bytes": байт} или
    None, если раунд упал на сетевой ошибке (не путать с «нода не открыла
    сайт» — там sites просто неполный).
    """
    try:
        tasks = {name: asyncio.create_task(
            check_site(session, proxy, url, CFG.SITE_TIMEOUT))
            for name, url in CFG.TEST_SITES.items()}
        results = await asyncio.gather(*tasks.values())
        sites = {name: dt for name, (ok, dt) in zip(tasks.keys(), results) if ok}
        speed, nbytes = 0.0, 0
        # Скорость меряется только если в этом раунде открыты ВСЕ обязательные
        # сайты: качать трафик через ноду, которая уже не тянет, бессмысленно.
        if len(sites) == len(CFG.REQUIRED_SITES):
            speed, nbytes = await download_speed_test(
                session, proxy, CFG.SPEED_TEST_BYTES, CFG.SPEED_TEST_TIMEOUT)
        return {"sites": sites, "speed": speed, "bytes": nbytes}
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return None


async def _probe_via_proxy(session: aiohttp.ClientSession, proxy: str,
                           res: NodeResult) -> bool:
    """Проверка живости И стабильности: несколько раундов подряд через один
    запущенный xray (экономия ~1-2 с на перезапуск процесса на каждый раунд).

    Живой считается только нода, которая во ВСЕХ раундах (основной +
    STABILITY_ROUNDS контрольных, разделённых паузой STABILITY_ROUND_GAP):
      1) открыла 100% обязательных сайтов (youtube, telegram, nvidia);
      2) показала скорость не ниже MIN_DOWNLOAD_SPEED_MBPS.
    Замер скорости выполняется в каждом раунде; итоговая скорость — МИНИМУМ
    по раундам (худший случай), поэтому «вспышечные» ноды получают честный
    рейтинг. Сбой соединения посреди раунда — тоже провал стабильности.
    """
    total_rounds = 1 + max(0, int(CFG.STABILITY_ROUNDS))
    for rnd in range(total_rounds):
        if rnd > 0:
            await asyncio.sleep(CFG.STABILITY_ROUND_GAP)
        out = await _run_check_round(session, proxy)
        if out is None:
            res.error = f"сбой соединения в раунде {rnd + 1}/{total_rounds}"
            return False
        missing = [s for s in CFG.REQUIRED_SITES if s not in out["sites"]]
        if missing:
            if rnd == 0:
                res.sites_ok = out["sites"]
            res.round_sites_ok.append(len(out["sites"]))
            res.round_speed_mbps.append(round(out["speed"], 2))
            res.round_max_site_latency.append(
                round(max(out["sites"].values()), 2) if out["sites"] else None)
            res.error = (f"недоступны обязательные: {','.join(missing)} "
                         f"(раунд {rnd + 1}/{total_rounds})")
            return False
        if out["speed"] < CFG.MIN_DOWNLOAD_SPEED_MBPS:
            if rnd == 0:
                res.sites_ok = out["sites"]
            res.round_sites_ok.append(len(out["sites"]))
            res.round_speed_mbps.append(round(out["speed"], 2))
            res.round_max_site_latency.append(
                round(max(out["sites"].values()), 2))
            res.error = (f"скорость {out['speed']:.2f} Мбит/с ниже порога "
                         f"{CFG.MIN_DOWNLOAD_SPEED_MBPS} (раунд {rnd + 1}/"
                         f"{total_rounds})")
            return False
        if rnd == 0:
            res.sites_ok = out["sites"]   # времена ответа основного раунда
        res.bytes_downloaded += out["bytes"]
        res.round_sites_ok.append(len(out["sites"]))
        res.round_speed_mbps.append(round(out["speed"], 2))
        res.round_max_site_latency.append(round(max(out["sites"].values()), 2))

    # Все раунды пройдены: покрытие 100% стабильно; скорость = худшая из
    # замеренных (честный рейтинг); разброс виден по round_* в report.csv.
    res.speed_mbps = round(min(res.round_speed_mbps), 2)
    res.alive = True
    return True


async def check_one_node(link: str, sem: asyncio.Semaphore) -> NodeResult | None:
    """Полная проверка одной ноды; возвращает результат или None (битая ссылка)."""
    vl = VlessLink.parse(link)
    if vl is None:
        return None
    res = NodeResult.from_link(vl)
    try:
        validate_node(vl)
    except UnsupportedNode as e:
        res.error = f"unsupported: {e}"
        return res
    async with sem:
        lat = await measure_tcp_latency(vl.host, vl.port, CFG.LATENCY_SAMPLES)
        if lat is None:
            res.error = "tcp connect failed"
            return res
        res.latency_ms = round(lat, 1)

        try:
            async with running_xray(vl.raw) as xp:
                # Дешёвая разведка туннеля до тяжёлой части проверки: если
                # нода не может установить CONNECT даже до youtube — весь
                # цикл опроса сайтов и закачки заранее обречён.
                if CFG.PRECHECK_ENABLED and not await precheck_tunneled_connect(
                        xp.socks_proxy_url, CFG.PRECHECK_HOST,
                        CFG.PRECHECK_PORT, CFG.PRECHECK_TIMEOUT):
                    res.error = f"туннель к {CFG.PRECHECK_HOST} не проходит"
                    return res
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
        w.writerow(["score", "speed_Mbps", "latency_ms", "coverage_pct",
                    "rounds", "round_speeds_Mbps", "max_site_latency_s",
                    "sites_ok", "country", "name", "link"])
        for r in good:
            sites = ";".join(f"{k}={v}s" for k, v in sorted(r.sites_ok.items()))
            rounds = ",".join(str(x) for x in r.round_speed_mbps)
            spread = [x for x in r.round_max_site_latency if x is not None]
            w.writerow([r.score, r.speed_mbps, r.latency_ms or "",
                        f"{r.coverage_pct:.0f}", len(r.round_sites_ok),
                        rounds, max(spread) if spread else "",
                        sites, r.country, r.name, r.link])

    console.print("[bold green]Сохранено:[/]")
    console.print(f"  {p_good}: {len(good)} рабочих подписок "
                  f"(YT+TG+NVIDIA стабильны во всех "
                  f"{1 + max(0, int(CFG.STABILITY_ROUNDS))} раундах)")
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
    t.add_column("Раб.", justify="center")  # раундов стабильности пройдено
    t.add_column("Стр", justify="center")
    t.add_column("Сайты", style="yellow")
    t.add_column("Нода", overflow="fold", max_width=40)
    for i, r in enumerate(results[:n], 1):
        sites = ",".join(sorted(r.sites_ok.keys()))
        t.add_row(str(i), f"{r.score:.0f}", f"{r.speed_mbps:.1f}",
                  f"{r.latency_ms:.0f}" if r.latency_ms else "-",
                  str(len(r.round_sites_ok)) if r.round_sites_ok else "1",
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

    # Таймаут обязателен: без него aiohttp ждёт тело ответа бесконечно,
    # и один медленный/зависший зеркало-хост останавливает всю установку.
    async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=120)) as s:
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
    # Число контрольных раундов стабильности можно задать из CLI (0 = только
    # основной замер, как в старых версиях).
    if getattr(args, "stability", None) is not None:
        CFG.STABILITY_ROUNDS = max(0, int(args.stability))
    outdir = args.out or "."
    os.makedirs(outdir, exist_ok=True)

    # ---------- фаза сбора ссылок ----------
    links = await collect_links(args, outdir)
    # дедупликация ДО --limit: иначе лимит съедают дубли и одна физическая
    # нода проверяется несколько раз
    before = len(links)
    links = dedup_links(links)
    if before != len(links):
        console.print(f"[dim]Дедупликация: {before} -> {len(links)} уникальных нод[/]")
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

    # Порог уже применён в _probe_via_proxy (res.alive ставится только при
    # скорости >= MIN_DOWNLOAD_SPEED_MBPS) — здесь остаётся pass, чтобы не
    # печатать ложную «дополнительную» фильтрацию.
    best = results
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
    p.add_argument("--stability", type=int, default=None, metavar="N",
                   help=f"контрольных раундов стабильности после основного "
                        f"(по умолчанию {CFG.STABILITY_ROUNDS}; 0 = только "
                        f"основной замер; нода проходит лишь при 100%% сайтов "
                        f"и пороге скорости во всех раундах)")
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
