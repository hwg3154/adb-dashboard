"""JSON endpoints.

One function per endpoint, reached through a fixed table. Every handler:

- runs only for `POST` (design.md §8: `GET` is for HTML)
- passes through `security.check_write_headers`, which is where Origin, Host and CSRF are decided
- takes its arguments from an allowlist or a validator, never from a string the browser composed
- returns a stable error code, never a device string and never the operator's own input

The same handlers serve the plain `<form>` fallback and `fetch()`. A form gets a redirect back to
the page it came from, a JSON caller gets JSON; nothing else differs.

See `docs/design.md` §8 for the endpoint table and §8.1 for what is deliberately absent.
"""

from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass, field
from typing import Callable

from . import discovery, keys, netguard, security, textentry
from .adb import AdbError, AdbResult
from .auth import AuthError
from .registry import RegistryError
from .security import Request, RequestRejected

#: How many key presses one session may send per window. A stuck key or a scripted flood is a
#: device problem before it is a server problem (design.md §4).
KEY_BUDGET = 40
KEY_WINDOW_SECONDS = 10.0

_PACKAGE_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
#: The only pages a form is allowed to be sent back to.
_RETURN_PAGES = frozenset({"/", "/apps", "/settings", "/setup"})
_DEVICE_PATH = re.compile(r"^/api/devices/([0-9a-f]{32})/([a-z_]{3,16})$")
_DEVICE_FORM_PATH = re.compile(r"^/api/devices/([a-z_]{3,16})$")

#: Where a form POST lands when it succeeds. `fetch()` callers ignore this.
_FORM_REDIRECT = {
    "/api/login": "/",
    "/api/logout": "/login",
    "/api/change_password": "/settings",
    "/api/join": "/settings",
    "/api/discover": "/setup",
}


@dataclass
class Result:
    """What a handler produced. The web layer turns this into bytes and nothing more."""

    status: int = 200
    payload: dict[str, object] = field(default_factory=dict)
    #: Set for a form POST so the browser lands back on a page instead of on raw JSON.
    redirect: str = ""
    set_cookie: str = ""
    clear_cookie: bool = False
    #: A pre-encoded body (used for nothing today; screenshots travel as base64 JSON).
    raw: bytes | None = None
    content_type: str = "application/json; charset=utf-8"


def ok(**fields: object) -> Result:
    payload: dict[str, object] = {"ok": True}
    payload.update(fields)
    return Result(200, payload)


def fail(code: str, status: int = 400, **fields: object) -> Result:
    payload: dict[str, object] = {"ok": False, "error": code}
    payload.update(fields)
    return Result(status, payload)


class KeyBudget:
    """A tiny fixed-window budget, keyed by session token."""

    def __init__(self, budget: int = KEY_BUDGET, window: float = KEY_WINDOW_SECONDS) -> None:
        self._budget = max(1, int(budget))
        self._window = max(1.0, float(window))
        self._hits: dict[str, list[float]] = {}

    def allow(self, token: str) -> bool:
        now = time.monotonic()
        bucket = [stamp for stamp in self._hits.get(token, ()) if now - stamp < self._window]
        if len(bucket) >= self._budget:
            self._hits[token] = bucket
            return False
        bucket.append(now)
        self._hits[token] = bucket
        if len(self._hits) > 32:
            self._forget_idle(now)
        return True

    def _forget_idle(self, now: float) -> None:
        self._hits = {
            token: bucket
            for token, bucket in self._hits.items()
            if any(now - stamp < self._window for stamp in bucket)
        }


_KEYS = KeyBudget()


# ------------------------------------------------------------------------------- dispatch


def handle(app: object, request: Request, ip: str = "") -> Result:
    """Route one POST. Raises `RequestRejected` only for failures the web layer should format."""
    path = request.path
    handler = _ROUTES.get(path)
    device_action = _device_action(path)

    if handler is None and device_action is None:
        return fail("not_found", 404)

    # `/api/login` is the one endpoint reachable without a session, so it cannot carry a
    # session-bound CSRF token. Origin and Host still have to check out.
    needs_csrf = path != "/api/login"
    token = security.authorize(app, request)
    security.check_write_headers(app, request, csrf=token if needs_csrf else "")

    if needs_csrf and not token:
        return _finish(request, path, fail("unauthorized", 401))

    if device_action is not None:
        device_id, action = device_action
        return _finish(request, path, _device(app, request, token, device_id, action))

    return _finish(request, path, handler(app, request, token, ip))


def _finish(request: Request, path: str, result: Result) -> Result:
    """Give a form POST somewhere to land; leave a JSON caller alone."""
    if result.redirect or result.status >= 400 or not _is_form(request):
        return result
    result.redirect = _FORM_REDIRECT.get(path) or _referer_path(request)
    return result


def _referer_path(request: Request) -> str:
    """The path part of our own Referer, or '/'. Never a host, never an off-site URL."""
    raw = request.headers.get("referer", "")
    if not isinstance(raw, str) or not raw:
        return "/"
    path = raw.partition("://")[2]
    path = "/" + path.partition("/")[2] if "/" in path else "/"
    path = path.partition("?")[0]
    return path if path in _RETURN_PAGES else "/"


def _is_form(request: Request) -> bool:
    content_type = request.headers.get("content-type", "").lower()
    return "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type


def _device_action(path: str) -> tuple[str, str] | None:
    match = _DEVICE_PATH.match(path)
    if match:
        return match.group(1), match.group(2)
    return None


# --------------------------------------------------------------------------------- session


def _login(app: object, request: Request, token: str, ip: str) -> Result:
    """Sign in, or create the one account when there is none yet (design.md §7)."""
    username = request.text("username")
    password = request.text("password")
    try:
        if not app.auth.is_initialized:
            opened = app.auth.bootstrap(username, password, ip)
        else:
            opened = app.auth.login(username, password, ip)
    except AuthError as exc:
        return Result(_auth_status(exc.code), exc.as_dict())
    except (ValueError, RegistryError):
        return fail("bad_request")

    new_token = opened.get("token", "")
    result = ok(action=opened.get("action", "session_opened"))
    result.set_cookie = new_token if isinstance(new_token, str) else ""
    return result


def _logout(app: object, request: Request, token: str, ip: str) -> Result:
    app.auth.logout(token)
    result = ok(action="logged_out")
    result.clear_cookie = True
    return result


def _change_password(app: object, request: Request, token: str, ip: str) -> Result:
    try:
        changed = app.auth.change_password(token, request.text("current"), request.text("password"))
    except AuthError as exc:
        return Result(_auth_status(exc.code), exc.as_dict())

    # Every session was revoked, including this one; adopt the replacement so the operator is
    # not bounced to the login page by their own password change.
    new_token = changed.get("token", "")
    result = ok(action="password_changed")
    result.set_cookie = new_token if isinstance(new_token, str) else ""
    return result


def _auth_status(code: str) -> int:
    return {
        "bad_credentials": 401,
        "unauthorized": 401,
        "locked": 429,
        "weak_password": 400,
        "not_initialized": 409,
        "already_initialized": 409,
    }.get(code, 400)


# ---------------------------------------------------------------------------------- remote


def _key(app: object, request: Request, token: str, ip: str) -> Result:
    if not _KEYS.allow(token):
        return fail("rate_limited", 429, retry_after=int(KEY_WINDOW_SECONDS))
    try:
        spec = keys.resolve_key(request.text("key"))
    except keys.InvalidKey:
        return fail("bad_key")

    target = _target(app)
    if not target:
        return fail("no_device", 409)
    return _adb(lambda: app.adb.send_key(target, spec.alias), key=spec.alias)


def _text(app: object, request: Request, token: str, ip: str) -> Result:
    target = _target(app)
    if not target:
        return fail("no_device", 409)
    raw = request.text("text")
    try:
        # Sanitize here purely to answer with a precise code; adb sanitizes again on the way out.
        textentry.sanitize_text(raw, app.config.max_text_chars)
    except textentry.TextRejected:
        return fail("bad_text")
    # design.md §9: the text itself is never logged, only its length.
    return _adb(lambda: app.adb.send_text(target, raw, submit=request.flag("submit")), chars=len(raw))


def _screenshot(app: object, request: Request, token: str, ip: str) -> Result:
    target = _target(app)
    if not target:
        return fail("no_device", 409)
    try:
        payload, result = app.adb.screenshot(target)
    except AdbError:
        return fail("adb_missing", 503)
    except ValueError:
        return fail("bad_target")
    if not result.ok or not payload:
        return fail("adb_failed", 502, code=result.status.name.lower())

    limit = int(app.config.max_screenshot_bytes)
    truncated = len(payload) > limit
    return ok(
        png=base64.b64encode(payload[:limit]).decode("ascii"),
        bytes=min(len(payload), limit),
        truncated=truncated,
        elapsed_ms=result.elapsed_ms,
    )


# ------------------------------------------------------------------------------------ apps


def _apps(app: object, request: Request, token: str, ip: str) -> Result:
    target = _target(app)
    if not target:
        return fail("no_device", 409)
    try:
        listed = app.adb.list_apps(target)
    except AdbError:
        return fail("adb_missing", 503)
    except ValueError:
        return fail("bad_target")
    return ok(apps=listed, count=len(listed))


def _app_action(name: str) -> Callable[[object, Request, str, str], Result]:
    """Build one package-scoped handler. The verb is ours; only the package comes from outside."""

    def run(app: object, request: Request, token: str, ip: str) -> Result:
        target = _target(app)
        if not target:
            return fail("no_device", 409)
        package = _package(request)
        if not package:
            return fail("bad_package")
        method = getattr(app.adb, name)
        return _adb(lambda: method(target, package), package=package)

    return run


def _launch(app: object, request: Request, token: str, ip: str) -> Result:
    target = _target(app)
    if not target:
        return fail("no_device", 409)
    package = _package(request)
    if not package:
        return fail("bad_package")
    activity = request.text("activity")
    return _adb(lambda: app.adb.launch(target, package, activity), package=package)


# --------------------------------------------------------------------------------- devices


def _discover(app: object, request: Request, token: str, ip: str) -> Result:
    """Sweep the LAN and cache what answered. Hosts never reach the browser as an instruction."""
    try:
        found = discovery.discover(app.config)
    except (OSError, RuntimeError):
        return fail("discover_failed", 502)
    with app.lock:
        app.registry.remember(found)
        listed = [item.public() for item in app.registry.candidates()]
    return ok(candidates=listed, count=len(listed))


def _join(app: object, request: Request, token: str, ip: str) -> Result:
    """Turn a candidate into a registered device: pair if asked, connect, then persist."""
    try:
        candidate_id = netguard.candidate_id(request.text("candidate_id"))
        pairing_code = netguard.validate_pair_code(request.text("pairing_code"))
    except netguard.TargetRejected:
        return fail("bad_candidate")

    with app.lock:
        candidate = app.registry.take(candidate_id)
    if candidate is None:
        return fail("unknown_candidate", 409)

    target = f"{candidate.host}:{candidate.port}"
    try:
        app.adb.validate_target(target)
    except ValueError:
        return fail("bad_target")

    try:
        if pairing_code:
            paired = app.adb.pair(candidate.host, candidate.port, pairing_code)
            if not paired.ok:
                return fail("pairing_failed", 502)
        connected = app.adb.connect(target)
    except AdbError:
        return fail("adb_missing", 503)
    except ValueError:
        return fail("bad_target")
    if not connected.ok:
        return fail("connect_failed", 502)

    try:
        with app.lock:
            device = app.registry.add(target, model=candidate.model)
    except RegistryError:
        return fail("device_limit", 409)
    return ok(action="joined", device=device.public())


def _device(app: object, request: Request, token: str, device_id: str, action: str) -> Result:
    """The four things that may happen to a registered device."""
    with app.lock:
        target = app.registry.target_for(device_id)
    if not target and action != "remove":
        return fail("unknown_device", 404)

    if action == "connect":
        result = _adb(lambda: app.adb.connect(target))
        if result.status == 200:
            with app.lock:
                app.registry.use(device_id)
        return result
    if action == "disconnect":
        return _adb(lambda: app.adb.disconnect(target))
    if action in {"remove", "forget"}:
        with app.lock:
            removed = app.registry.remove(device_id)
        return ok(action="forgotten") if removed else fail("unknown_device", 404)
    if action == "use":
        with app.lock:
            used = app.registry.use(device_id)
        return ok(action="in_use") if used else fail("unknown_device", 404)
    if action in {"set_nickname", "rename"}:
        with app.lock:
            renamed = app.registry.set_nickname(device_id, request.text("nickname"))
        return ok(action="renamed") if renamed else fail("unknown_device", 404)
    return fail("bad_action")


def _device_form(app: object, request: Request, token: str, ip: str) -> Result:
    """The no-JS path: the device id travels in the body, the action in the URL."""
    match = _DEVICE_FORM_PATH.match(request.path)
    if match is None:
        return fail("not_found", 404)
    try:
        device_id = netguard.candidate_id(request.text("id"))
    except netguard.TargetRejected:
        return fail("bad_device")
    return _device(app, request, token, device_id, match.group(1))


# --------------------------------------------------------------------------------- helpers


def _package(request: Request) -> str:
    """A package name the browser sent, or ''. Same shape adb.py insists on."""
    candidate = request.text("package").strip().lower()
    return candidate if _PACKAGE_RE.match(candidate) else ""


def _target(app: object) -> str:
    with app.lock:
        return app.registry.active_target()


def _adb(call: Callable[[], AdbResult], **fields: object) -> Result:
    """Run one adb call and turn its outcome into a stable code.

    Device output never reaches the browser: only whether it worked, and how long it took.
    """
    try:
        result = call()
    except AdbError:
        return fail("adb_missing", 503)
    except keys.InvalidKey:
        return fail("bad_key")
    except textentry.TextRejected:
        return fail("bad_text")
    except netguard.TargetRejected:
        return fail("bad_target")
    except ValueError:
        return fail("bad_request")

    if not result.ok:
        return fail("adb_failed", 502, code=result.status.name.lower(), elapsed_ms=result.elapsed_ms)
    payload: dict[str, object] = {"elapsed_ms": result.elapsed_ms}
    payload.update(fields)
    return ok(**payload)


_ROUTES: dict[str, Callable[[object, Request, str, str], Result]] = {
    "/api/login": _login,
    "/api/logout": _logout,
    "/api/change_password": _change_password,
    "/api/key": _key,
    "/api/text": _text,
    "/api/screenshot": _screenshot,
    "/api/apps": _apps,
    "/api/launch": _launch,
    "/api/stop": _app_action("stop"),
    "/api/appinfo": _app_action("app_info"),
    "/api/clear": _app_action("clear_data"),
    "/api/uninstall": _app_action("uninstall"),
    "/api/discover": _discover,
    "/api/join": _join,
    "/api/devices/use": _device_form,
    "/api/devices/set_nickname": _device_form,
    "/api/devices/remove": _device_form,
    "/api/devices/connect": _device_form,
    "/api/devices/disconnect": _device_form,
}

__all__ = ["Result", "handle", "fail", "ok"]
