"""Environment-driven configuration. No YAML, no config file."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field, replace
from typing import Mapping

DEFAULT_DATA_DIR = "/data"
DEFAULT_HTTP_ADDR = "0.0.0.0:8080"
DEFAULT_ADB_BIN = "adb"

#: A key shorter than this is treated as absent: a weak bearer secret is worse than no door,
#: because it invites guessing rather than stopping it. 16 is a floor, not a target; the
#: documented value is 32+ random characters.
API_KEY_MIN_CHARS = 16

DEFAULT_ALLOWED_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)

DEVICE_PORTS: tuple[int, ...] = (5555, 5556, 5557)

MAX_TEXT_CHARS = 512
MAX_SCREENSHOT_BYTES = 4 * 1024 * 1024
MAX_INPUT_CHARS = 512
DISCOVER_MAX_CANDIDATES = 8
CANDIDATE_TTL_SECONDS = 600
MAX_BODY_BYTES = 8 * 1024
MAX_ADB_OUTPUT_BYTES = 4 * 1024 * 1024
ADB_TIMEOUT_SECONDS = 8.0
DISCOVER_TIMEOUT_SECONDS = 0.35
DISCOVER_CONCURRENCY = 32
DISCOVER_MAX_HOSTS = 254

SESSION_IDLE_SECONDS = 8 * 60 * 60
SESSION_ABSOLUTE_SECONDS = 7 * 24 * 60 * 60

COOKIE_NAME = "tvd_session"
PREAUTH_COOKIE_NAME = "tvd_preauth"
SETUP_COOKIE_NAME = "tvd_setup"
CSRF_HEADER = "X-TVD-CSRF"

MIN_PASSWORD_CHARS = 10
MAX_PASSWORD_CHARS = 128

MAX_SESSIONS_PER_USER = 2

LOGIN_BUDGET_PER_IP = 5
LOGIN_BUDGET_PER_USER = 5
LOGIN_BUDGET_GLOBAL = 30
LOGIN_BACKOFF_SECONDS = 30
LOGIN_WINDOW_SECONDS = 300

CACHE_TTL_SECONDS = 30.0
CANDIDATE_TTL_SECONDS = 10 * 60
DISCOVER_MAX_CANDIDATES = 8


@dataclass(frozen=True)
class Config:
    """Runtime configuration. Built once from the environment, then read-only."""

    data_dir: str = DEFAULT_DATA_DIR
    http_addr: str = DEFAULT_HTTP_ADDR
    allow_insecure_http: bool = False
    allowed_cidrs: tuple[str, ...] = DEFAULT_ALLOWED_CIDRS
    mdns_enabled: bool = False
    adb_bin: str = DEFAULT_ADB_BIN
    #: Shared-secret bearer key for the scriptable API. Empty = the API is not enabled.
    api_key: str = ""
    device_ports: tuple[int, ...] = DEVICE_PORTS
    max_text_chars: int = MAX_TEXT_CHARS
    max_screenshot_bytes: int = MAX_SCREENSHOT_BYTES
    discover_max_candidates: int = DISCOVER_MAX_CANDIDATES
    candidate_ttl_seconds: float = CANDIDATE_TTL_SECONDS
    max_body_bytes: int = MAX_BODY_BYTES
    max_adb_output_bytes: int = MAX_ADB_OUTPUT_BYTES
    adb_timeout_seconds: float = ADB_TIMEOUT_SECONDS
    discover_timeout_seconds: float = DISCOVER_TIMEOUT_SECONDS
    discover_concurrency: int = DISCOVER_CONCURRENCY
    discover_max_hosts: int = DISCOVER_MAX_HOSTS
    password_min_chars: int = MIN_PASSWORD_CHARS
    password_max_chars: int = MAX_PASSWORD_CHARS
    max_sessions_per_user: int = MAX_SESSIONS_PER_USER
    session_idle_seconds: int = SESSION_IDLE_SECONDS
    session_absolute_seconds: int = SESSION_ABSOLUTE_SECONDS
    login_budget_per_ip: int = LOGIN_BUDGET_PER_IP
    login_budget_per_user: int = LOGIN_BUDGET_PER_USER
    login_budget_global: int = LOGIN_BUDGET_GLOBAL
    login_backoff_seconds: int = LOGIN_BACKOFF_SECONDS
    login_window_seconds: int = LOGIN_WINDOW_SECONDS
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Config":
        source = env if env is not None else os.environ
        warnings: list[str] = []

        def text(name: str, default: str) -> str:
            raw = (source.get(name) or "").strip()
            if not raw:
                return default
            if _contains_control_chars(raw):
                warnings.append(f"{name} contains control characters; using default")
                return default
            return raw

        def integer(name: str, default: int, low: int, high: int) -> int:
            raw = (source.get(name) or "").strip()
            if not raw:
                return default
            try:
                value = int(raw)
            except ValueError:
                warnings.append(f"{name} is not an integer; using default")
                return default
            if not low <= value <= high:
                warnings.append(f"{name}={value} out of range; using default")
                return default
            return value

        def flag(name: str) -> bool:
            return (source.get(name) or "").strip().lower() in {"1", "true", "yes", "on"}

        def api_key() -> str:
            # `text()` already strips the edges and refuses control characters; the length floor
            # is the real gate. A bearer token is one token, so any internal whitespace means it
            # is not the key the operator typed - refuse it rather than carry a newline in it.
            raw = text("TVD_API_KEY", "")
            if not raw:
                return ""
            if any(char.isspace() for char in raw):
                return ""
            if len(raw) < API_KEY_MIN_CHARS:
                warnings.append(
                    f"TVD_API_KEY is {len(raw)} characters; {API_KEY_MIN_CHARS}+ are required, "
                    "so the scriptable API stays disabled"
                )
                return ""
            return raw

        def cidrs() -> tuple[str, ...]:
            raw = (source.get("TVD_ALLOWED_CIDRS") or "").strip()
            if not raw:
                return DEFAULT_ALLOWED_CIDRS
            accepted: list[str] = []
            for chunk in raw.split(","):
                chunk = chunk.strip()
                if not chunk:
                    continue
                if "/" not in chunk:
                    warnings.append(f"TVD_ALLOWED_CIDRS entry {chunk!r} is not a CIDR; skipped")
                    continue
                try:
                    network = ipaddress.ip_network(chunk, strict=False)
                except ValueError:
                    warnings.append(f"TVD_ALLOWED_CIDRS entry {chunk!r} is invalid; skipped")
                    continue
                if network.version != 4 or not network.is_private:
                    warnings.append(f"TVD_ALLOWED_CIDRS entry {chunk!r} is not a private IPv4 net; skipped")
                    continue
                accepted.append(str(network))
            if not accepted:
                warnings.append("TVD_ALLOWED_CIDRS has no usable entry; using default")
                return DEFAULT_ALLOWED_CIDRS
            return tuple(accepted)

        def ports() -> tuple[int, ...]:
            raw = (source.get("TVD_DEVICE_PORTS") or "").strip()
            if not raw:
                return DEVICE_PORTS
            accepted: list[int] = []
            for chunk in raw.split(","):
                chunk = chunk.strip()
                if not chunk.isdigit():
                    warnings.append(f"TVD_DEVICE_PORTS entry {chunk!r} is not a number; skipped")
                    continue
                value = int(chunk)
                if not 5000 <= value <= 5599:
                    warnings.append(f"TVD_DEVICE_PORTS entry {value} out of range; skipped")
                    continue
                accepted.append(value)
            if not accepted:
                warnings.append("TVD_DEVICE_PORTS has no usable entry; using default")
                return DEVICE_PORTS
            return tuple(accepted)

        cfg = cls(
            data_dir=text("TVD_DATA_DIR", DEFAULT_DATA_DIR),
            http_addr=text("TVD_HTTP_ADDR", DEFAULT_HTTP_ADDR),
            allow_insecure_http=flag("TVD_ALLOW_INSECURE_HTTP"),
            allowed_cidrs=cidrs(),
            mdns_enabled=flag("TVD_MDNS"),
            adb_bin=_safe_binary(text("TVD_ADB_BIN", DEFAULT_ADB_BIN)),
            api_key=api_key(),
            device_ports=ports(),
            max_text_chars=integer("TVD_MAX_TEXT_CHARS", MAX_TEXT_CHARS, 16, 2048),
            max_screenshot_bytes=integer("TVD_MAX_SCREENSHOT_BYTES", MAX_SCREENSHOT_BYTES, 65_536, 16 * 1024 * 1024),
            discover_max_candidates=integer("TVD_DISCOVER_MAX_CANDIDATES", DISCOVER_MAX_CANDIDATES, 1, 32),
            candidate_ttl_seconds=float(integer("TVD_CANDIDATE_TTL_SECONDS", int(CANDIDATE_TTL_SECONDS), 30, 3600)),
            max_body_bytes=integer("TVD_MAX_BODY_BYTES", MAX_BODY_BYTES, 512, 64 * 1024),
            max_adb_output_bytes=integer(
                "TVD_MAX_ADB_OUTPUT_BYTES", MAX_ADB_OUTPUT_BYTES, 64 * 1024, 16 * 1024 * 1024
            ),
            adb_timeout_seconds=float(integer("TVD_ADB_TIMEOUT_SECONDS", int(ADB_TIMEOUT_SECONDS), 1, 60)),
            discover_timeout_seconds=float(
                integer("TVD_DISCOVER_TIMEOUT_MS", int(DISCOVER_TIMEOUT_SECONDS * 1000), 50, 3000) / 1000.0
            ),
            discover_concurrency=integer("TVD_DISCOVER_CONCURRENCY", DISCOVER_CONCURRENCY, 1, 128),
            discover_max_hosts=integer("TVD_DISCOVER_MAX_HOSTS", DISCOVER_MAX_HOSTS, 1, 254),
            password_min_chars=integer("TVD_PASSWORD_MIN_CHARS", MIN_PASSWORD_CHARS, 8, 64),
            password_max_chars=integer("TVD_PASSWORD_MAX_CHARS", MAX_PASSWORD_CHARS, 16, 128),
            max_sessions_per_user=integer("TVD_MAX_SESSIONS_PER_USER", MAX_SESSIONS_PER_USER, 1, 8),
            login_budget_per_ip=integer("TVD_LOGIN_BUDGET_PER_IP", LOGIN_BUDGET_PER_IP, 1, 100),
            login_budget_per_user=integer("TVD_LOGIN_BUDGET_PER_USER", LOGIN_BUDGET_PER_USER, 1, 100),
            login_budget_global=integer("TVD_LOGIN_BUDGET_GLOBAL", LOGIN_BUDGET_GLOBAL, 1, 1_000),
            login_backoff_seconds=integer("TVD_LOGIN_BACKOFF_SECONDS", LOGIN_BACKOFF_SECONDS, 1, 3_600),
            login_window_seconds=integer("TVD_LOGIN_WINDOW_SECONDS", LOGIN_WINDOW_SECONDS, 10, 3_600),
            session_idle_seconds=integer("TVD_SESSION_IDLE_SECONDS", SESSION_IDLE_SECONDS, 60, 86_400),
            session_absolute_seconds=integer(
                "TVD_SESSION_ABSOLUTE_SECONDS", SESSION_ABSOLUTE_SECONDS, 300, 2_592_000
            ),
        )
        return replace(cfg, warnings=tuple(warnings))

    @property
    def listen_host(self) -> str:
        return self.http_addr.rsplit(":", 1)[0] if ":" in self.http_addr else self.http_addr

    @property
    def listen_port(self) -> int:
        if ":" not in self.http_addr:
            return 80
        try:
            return int(self.http_addr.rsplit(":", 1)[1])
        except (TypeError, ValueError):
            return 8080

    @property
    def same_origin(self) -> str:
        host = self.listen_host
        if not host or host in {"0.0.0.0", "::"}:
            host = "localhost"
        return f"http://{host}:{self.listen_port}"

    @property
    def allowed_networks(self) -> tuple[ipaddress.IPv4Network, ...]:
        nets: list[ipaddress.IPv4Network] = []
        for chunk in self.allowed_cidrs:
            try:
                net = ipaddress.ip_network(chunk, strict=False)
            except (TypeError, ValueError):
                continue
            if net.version == 4 and net.is_private:
                nets.append(net)
        return tuple(nets) or tuple(ipaddress.ip_network(c) for c in DEFAULT_ALLOWED_CIDRS)


def _contains_control_chars(value: str) -> bool:
    for ch in value:
        code = ord(ch)
        if ch in "\t\n\r":
            continue
        if code < 0x20 or code == 0x7F:
            return True
    return False


def _safe_binary(value: str) -> str:
    if not value:
        return DEFAULT_ADB_BIN
    if any(char.isspace() for char in value):
        return DEFAULT_ADB_BIN
    if any(bad in value for bad in (";", "|", "&", "$", "`", ">", "<", "*")):
        return DEFAULT_ADB_BIN
    return value
