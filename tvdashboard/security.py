"""Request hygiene: the only place that decides who a request is from.

Responsibilities, in order:
- build a `Request` with bounded, typed fields (no unbounded strings, no raw headers)
- decide whether the request is authenticated
- check that a state-changing request really came from our own page (Origin / Sec-Fetch-Site)
- hand out escaped strings for HTML rendering

Everything else in the app is a consumer of these decisions and must not re-implement them.
"""

from __future__ import annotations

import html
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Mapping

from .config import COOKIE_NAME, CSRF_HEADER, DEFAULT_HTTP_ADDR

#: Browser cookie that carries the session token. Nothing else is ever stored in a cookie.
COOKIE_NAME = COOKIE_NAME
CSRF_HEADER = CSRF_HEADER

#: Requests we refuse to serve because they did not pass the checks below.
DEFAULT_ERROR = "bad_request"

_METHODS = frozenset({"GET", "HEAD", "POST"})
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: A missing `Sec-Fetch-Site` is normal for older browsers; a present one must not say the
#: request was driven by another page. `cross-site` was previously accepted here, which made
#: the check a no-op - the whole point of the header is to name that case.
_ALLOWED_SEC_FETCH_SITE = frozenset({"same-origin", "same-site", "none"})

_MAX_PATH_CHARS = 128
_MAX_QUERY_ITEMS = 16
_MAX_QUERY_KEY_CHARS = 32
_MAX_QUERY_VALUE_CHARS = 128
_MAX_HEADER_ITEMS = 32
_MAX_HEADER_NAME_CHARS = 32
_MAX_HEADER_VALUE_CHARS = 256
_MAX_COOKIE_ITEMS = 8
_MAX_COOKIE_NAME_CHARS = 32
_MAX_COOKIE_VALUE_CHARS = 128
_MAX_JSON_ITEMS = 8
_MAX_JSON_KEY_CHARS = 32
_MAX_JSON_VALUE_CHARS = 1024

_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/%-]{0,127}$")
_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
_CODE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
#: Host header: an IPv4 literal or a plain hostname, with an optional port. No scheme, no path.
_ORIGIN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}(?::\d{1,5})?$")

_DEFAULT_ORIGIN = f"http://{DEFAULT_HTTP_ADDR.rsplit(':', 1)[0]}"


class RequestRejected(ValueError):
    """Raised when a request fails a security check. Carries a stable, safe error code."""

    def __init__(self, code: str = DEFAULT_ERROR, retry_after: int = 0) -> None:
        candidate = code if isinstance(code, str) else ""
        self.code = candidate if _CODE_RE.match(candidate) else DEFAULT_ERROR
        self.retry_after = int(retry_after) if isinstance(retry_after, int) else 0
        super().__init__(self.code)


@dataclass(frozen=True)
class Request:
    """A vetted view of an incoming HTTP request.

    `json` holds string fields taken from a JSON body or from an urlencoded form. Values are
    never re-serialized into a command; consumers validate each field again against its own
    allowlist before use.
    """

    method: str
    path: str
    query: Mapping[str, str] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)
    json: Mapping[str, str] = field(default_factory=dict)
    cookies: Mapping[str, str] = field(default_factory=dict)

    @property
    def token(self) -> str:
        """The session token, already shape-checked. Never a hostname or a device string."""
        candidate = self.cookies.get(COOKIE_NAME, "")
        return candidate if _TOKEN_RE.match(candidate) else ""

    def text(self, name: str) -> str:
        """Return one JSON/form field, as a plain string. Missing or odd fields are ''."""
        value = self.json.get(name, "")
        return value if isinstance(value, str) else ""

    def flag(self, name: str) -> bool:
        return self.text(name).strip().lower() in {"1", "true", "yes", "on"}


def build_request(method: object, target: object, headers: object, body: bytes) -> Request:
    """Build a `Request` from raw server inputs. Never raises; bad input becomes an empty field."""
    return Request(
        method=_clean_method(method),
        path=parse_path(target),
        query=parse_query(target),
        headers=read_headers(headers),
        json=parse_json_body(body),
        cookies=read_cookies(headers),
    )


# ------------------------------------------------------------------------------- parsers


def parse_path(raw: object) -> str:
    """Normalize a request target to a bare, plain-text path. Rejects anything else."""
    if not isinstance(raw, str):
        return ""
    candidate = raw.strip()
    if not candidate.startswith("/"):
        candidate = "/" + candidate
    candidate = candidate.partition("?")[0]
    if not _PATH_RE.match(candidate):
        return ""
    if "//" in candidate or "/../" in candidate or candidate.endswith("/.."):
        return ""
    return candidate.rstrip("/") or "/"


def parse_query(raw: object) -> dict[str, str]:
    """Parse a query string into a small, flat, string-valued mapping."""
    if not isinstance(raw, str) or not raw:
        return {}
    candidate = raw.partition("?")[2] if "?" in raw else raw
    if not candidate or len(candidate) > _MAX_QUERY_ITEMS * (_MAX_QUERY_KEY_CHARS + _MAX_QUERY_VALUE_CHARS):
        return {}
    out: dict[str, str] = {}
    for chunk in candidate.split("&"):
        if len(out) >= _MAX_QUERY_ITEMS:
            break
        key, sep, value = chunk.partition("=")
        if not sep:
            continue
        key = key.strip()[:_MAX_QUERY_KEY_CHARS]
        value = value.strip()[:_MAX_QUERY_VALUE_CHARS]
        if not key or not _SAFE_TOKEN_CHARS.match(key):
            continue
        out.setdefault(key, value)
    return out


def parse_json_body(raw: bytes) -> dict[str, str]:
    """Parse a JSON body, or an urlencoded form body, into a flat string mapping.

    Both encodings are accepted because the page uses plain forms as a no-JS fallback. The
    result is only ever field names we expect and string values we re-validate.
    """
    if not isinstance(raw, bytes) or not raw:
        return {}
    if len(raw) > 64 * 1024:
        return {}
    try:
        parsed = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return _parse_form(raw)
    if not isinstance(parsed, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in parsed.items():
        if len(out) >= _MAX_JSON_ITEMS:
            break
        if not isinstance(key, str) or not _SAFE_TOKEN_CHARS.match(key):
            continue
        if isinstance(value, str):
            out[key] = value[:_MAX_JSON_VALUE_CHARS]
        elif isinstance(value, bool):
            out[key] = "true" if value else "false"
        elif isinstance(value, int) and -0x7FFFFFFF <= value <= 0x7FFFFFFF:
            out[key] = str(value)
    return out


def read_headers(raw: object) -> dict[str, str]:
    """Lower-case header names with capped values. Header lists stay small and never logged raw."""
    source = _as_mapping(raw)
    out: dict[str, str] = {}
    for key, value in source.items():
        if len(out) >= _MAX_HEADER_ITEMS:
            break
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        name = key.strip().lower()[:_MAX_HEADER_NAME_CHARS]
        if not name or not _HEADER_NAME_RE.match(name):
            continue
        out[name] = value.strip()[:_MAX_HEADER_VALUE_CHARS]
    return out


def read_cookies(raw: object) -> dict[str, str]:
    """Parse the `Cookie` header. Only a handful of names are ever interesting."""
    header = _as_mapping(raw).get("cookie", "")
    if not isinstance(header, str) or not header:
        return {}
    out: dict[str, str] = {}
    for chunk in header.split(";"):
        if len(out) >= _MAX_COOKIE_ITEMS:
            break
        name, sep, value = chunk.partition("=")
        if not sep:
            continue
        key = name.strip().lower()[:_MAX_COOKIE_NAME_CHARS]
        value = value.strip()[:_MAX_COOKIE_VALUE_CHARS]
        if not key or not _COOKIE_NAME_RE.match(key):
            continue
        out.setdefault(key, value)
    return out


# ---------------------------------------------------------------------------- decisions


def authorize(app: "object", request: Request) -> str:
    """Return the session token for a request, or '' when there is no valid session.

    `app` is the running application: it owns `sessions`. A missing cookie, a malformed token and
    an expired session all look the same here, so nothing can tell them apart from outside.
    """
    store = getattr(app, "sessions", None)
    if store is None:
        return ""
    token = request.token
    if not _TOKEN_RE.match(token):
        return ""
    return store.authorize(token)


def check_write_headers(app: "object", request: Request, csrf: str = "") -> None:
    """Guard a state-changing request: method, Host, Origin, Sec-Fetch-Site, CSRF.

    Raises `RequestRejected` with a stable code. `csrf` is unused when the caller does not
    require a form token, in which case Origin + session are the gate.
    """
    if request.method not in _UNSAFE_METHODS:
        raise RequestRejected("bad_request")

    host = request.headers.get("host", "")
    if not host or not _ORIGIN_RE.match(host):
        raise RequestRejected("bad_request")

    origin = request.headers.get("origin", "")
    if origin:
        if not _origin_matches(app, origin, host):
            raise RequestRejected("bad_origin")
    else:
        site = request.headers.get("sec-fetch-site", "")
        if site and site not in _ALLOWED_SEC_FETCH_SITE:
            raise RequestRejected("bad_origin")

    supplied = request.json.get(CSRF_FIELD, "") if csrf else ""
    if csrf:
        if not isinstance(supplied, str) or not _TOKEN_RE.match(supplied):
            raise RequestRejected("bad_csrf")
        if not app.sessions.verify_csrf(request.token, supplied):
            raise RequestRejected("bad_csrf")


def origin_of(app: "object") -> str:
    """The one origin this app is served from."""
    config = getattr(app, "config", None)
    if config is None:
        return _DEFAULT_ORIGIN
    return config.same_origin


def client_address(peer: object) -> str:
    """A safe, printable client address for rate-limit keys and logs."""
    if isinstance(peer, tuple) and peer and isinstance(peer[0], str):
        return peer[0][:45]
    if isinstance(peer, str):
        return peer[:45]
    return ""


# ---------------------------------------------------------------------------- rendering


def render_text(value: object) -> str:
    """Escape a value for an HTML element body."""
    return html.escape(_coerce(value), quote=False)


def render_attr(value: object) -> str:
    """Escape a value for a double-quoted HTML attribute."""
    return html.escape(_coerce(value), quote=True)


# ---------------------------------------------------------------------------- private


def _clean_method(value: object) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.strip().upper()
    return candidate if candidate in _METHODS else ""


def _as_mapping(raw: object) -> Mapping[str, str]:
    """Header names, lower-cased. HTTP header names are case-insensitive and the real server
    hands them over capitalised ("Cookie"), so a mapping has to be normalised like a list is."""
    if isinstance(raw, Mapping):
        return {
            key.strip().lower(): value
            for key, value in raw.items()
            if isinstance(key, str) and isinstance(value, str)
        }
    if isinstance(raw, (list, tuple)):
        out: dict[str, str] = {}
        for item in raw:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                key, value = item
                if isinstance(key, str) and isinstance(value, str):
                    out[key.strip().lower()] = value
        return out
    return {}


def _parse_form(raw: bytes) -> dict[str, str]:
    from urllib.parse import parse_qsl

    try:
        pairs = parse_qsl(raw.decode("latin-1"), keep_blank_values=True)
    except (UnicodeDecodeError, ValueError):
        return {}
    out: dict[str, str] = {}
    for key, value in pairs:
        if len(out) >= _MAX_JSON_ITEMS:
            break
        key = key.strip()[:_MAX_JSON_KEY_CHARS]
        if not key or not _SAFE_TOKEN_CHARS.match(key):
            continue
        out.setdefault(key, value.strip()[:_MAX_JSON_VALUE_CHARS])
    return out


def _origin_matches(app: "object", origin: str, host: str) -> bool:
    """An `Origin` is ours when its authority is the `Host` the browser actually used.

    The appliance answers on whatever LAN address the operator typed - a wildcard listener has
    no single name - so the configured origin cannot be the reference. `Host` is, and a browser
    sets both consistently while a cross-site page cannot forge either.
    """
    scheme, separator, authority = origin.partition("://")
    if not separator or scheme not in {"http", "https"}:
        return False
    if not _ORIGIN_RE.match(authority):
        return False
    if authority == host:
        return True
    if origin == origin_of(app):
        return True
    # A wildcard listener is also reachable on its loopback alias.
    port = _listen_port(app)
    return any(authority in {alias, f"{alias}:{port}"} for alias in _LOCAL_ORIGINS)


def _listen_port(app: "object") -> int:
    config = getattr(app, "config", None)
    return int(getattr(config, "listen_port", 8080)) if config is not None else 8080


def _coerce(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return ""


def _safe_code(value: str) -> str:
    return "".join(char for char in value if char.isalnum() or char in "_-")


_SAFE_TOKEN_CHARS = re.compile(r"^[a-z][a-z0-9_]*$")
#: HTTP header names are hyphenated; the token charset above is for query and JSON keys.
_HEADER_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_COOKIE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
_LOCAL_ORIGINS = ("localhost", "127.0.0.1")

#: JSON field name that carries the CSRF token.
CSRF_FIELD = "csrf"

__all__ = [
    "COOKIE_NAME",
    "CSRF_FIELD",
    "CSRF_HEADER",
    "Request",
    "RequestRejected",
    "authorize",
    "build_request",
    "check_write_headers",
    "clean_token",
    "client_address",
    "is_token",
    "origin_of",
    "parse_json_body",
    "parse_path",
    "parse_query",
    "read_cookies",
    "read_headers",
    "render_attr",
    "render_text",
]


def is_token(value: object) -> bool:
    return isinstance(value, str) and bool(_TOKEN_RE.match(value))


def clean_token(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


