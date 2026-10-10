"""JSON endpoints.

One function per endpoint, reached through a fixed table. Every handler:

- runs only for `POST` (design.md §8: `GET` is for HTML)
- authenticates with a session cookie **or** the `TVD_API_KEY` bearer token; when the key is
  used, `security.check_write_headers` skips the browser-origin checks that exist to stop a
  cross-site page (the key is the identity)
- passes through `security.check_write_headers`, which is where Host and, for browser callers,
  Origin and CSRF are decided
- takes its arguments from an allowlist or a validator, never from a string the browser composed
- returns a stable error code, never a device string and never the operator's own input

The same handlers serve the plain `<form>` fallback and `fetch()`. A form gets a redirect back to
the page it came from, a JSON caller gets JSON; nothing else differs. A script authenticating
with the API key never sends a form, so it never sees a redirect.

See `docs/design.md` §8 for the endpoint table, §8.2 for the scriptable API, and §8.1 for what
is deliberately absent.
"""

from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass, field
from typing import Callable

from . import discovery, keys, netguard, platforms, security, textentry, wol
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
    "/api/logout": "/login?e=signed_out",
    "/api/change_password": "/settings",
    "/api/join": "/settings?e=joined",
    "/api/devices/add": "/settings?e=joined",
    "/api/pair": "/setup?e=paired",
    "/api/discover": "/setup",
    "/api/prefs/quick_launch": "/settings",
}

#: Where a *failed* form POST lands, so a typo never ends on a page of raw JSON. The code
#: travels in `?e=` and `views.SETUP_NOTICES` decides the words.
_FAILURE_REDIRECT = {
    "/api/devices/add": "/setup",
    "/api/pair": "/setup",
    "/api/join": "/setup",
    "/api/discover": "/setup",
}

#: Failure codes a browser may be sent back to `/login` with. The page turns one of these into
#: a sentence; anything else becomes the generic one, so no handler can put a string on a page
#: by naming it here. `views.LOGIN_NOTICES` is the other half of this contract.
_LOGIN_NOTICE_CODES = frozenset(
    {"bad_credentials", "locked", "weak_password", "bad_request", "not_initialized", "signed_out"}
)


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

    token = security.authorize(app, request)
    #: A request that has no session but does carry the API key. It is its own identity, so it
    #: needs no CSRF token - there is no browser page to bind it to.
    with_key = token == "" and security.is_api_key(app, request)

    # `/api/login` is the one endpoint reachable without an identity, so it cannot carry a
    # session-bound CSRF token. Origin and Host still have to check out. A key-authenticated
    # request needs no CSRF at all.
    needs_csrf = path != "/api/login" and not with_key
    security.check_write_headers(app, request, csrf=token if needs_csrf else "")

    if not token and not with_key and path != "/api/login":
        return _finish(request, path, fail("unauthorized", 401))

    if device_action is not None:
        device_id, action = device_action
        return _finish(request, path, _device(app, request, token, device_id, action))

    return _finish(request, path, handler(app, request, token, ip))


def _finish(request: Request, path: str, result: Result) -> Result:
    """Give a form POST somewhere to land; leave a JSON caller alone.

    A failure needs a destination as much as a success does. Without one the browser is left
    displaying a page of JSON with no way back, which is the single most annoying thing a
    form can do - so a failed setup POST goes back to the page it came from, carrying a code
    the page turns into a sentence.
    """
    if result.redirect or not _is_form(request):
        return result
    if result.status >= 400:
        landing = _FAILURE_REDIRECT.get(path)
        if landing:
            code = result.payload.get("error", "")
            result.redirect = landing + "?e=" + (code if isinstance(code, str) else "")
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
    """Sign in, or create the one account when there is none yet (design.md §7).

    A wrong password is a normal thing to do, so it has to end somewhere you can type again.
    A form POST is sent back to `/login` with a code the page can explain; a `fetch()` caller
    still gets the same JSON it always did.
    """
    username = request.text("username")
    password = request.text("password")
    try:
        if not app.auth.is_initialized:
            opened = app.auth.bootstrap(username, password, ip)
        else:
            opened = app.auth.login(username, password, ip)
    except AuthError as exc:
        return _login_failed(request, exc.code, _auth_status(exc.code), exc.retry_after)
    except (ValueError, RegistryError):
        return _login_failed(request, "bad_request", 400)

    new_token = opened.get("token", "")
    result = ok(action=opened.get("action", "session_opened"))
    result.set_cookie = new_token if isinstance(new_token, str) else ""
    return result


def _login_failed(request: Request, code: str, status: int, retry_after: int = 0) -> Result:
    """A failed sign-in. JSON for a script, and another try for a browser."""
    payload: dict[str, object] = {"ok": False, "error": code}
    if retry_after:
        payload["retry_after"] = int(retry_after)
    result = Result(status, payload)
    if _is_form(request):
        notice = code if code in _LOGIN_NOTICE_CODES else "bad_request"
        result.redirect = "/login?e=" + notice
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
    result = _adb(lambda: app.adb.send_key(target, spec.alias), key=spec.alias)
    if result.status == 200:
        _learn_mac(app, target)
    return result


def _wake(app: object, request: Request, token: str, ip: str) -> Result:
    """Wake the most recently used TV with a Wake-on-LAN packet.

    adb cannot do this: a sleeping TV has no port open. The packet is aimed at the TV's network
    card instead, which the TV keeps powered in networked standby. Nothing here comes from the
    browser - the device, its address and its MAC are all the server's own.

    UDP gives no reply, so this reports that the packet was sent, not that the TV woke.
    """
    if not _KEYS.allow(token):
        return fail("rate_limited", 429, retry_after=int(KEY_WINDOW_SECONDS))
    with app.lock:
        device = app.registry.active_device()
    if device is None:
        return fail("no_device", 409)

    host = device.target.rsplit(":", 1)[0]
    # Not learned yet: a recently-used TV may still have a stale ARP entry worth trying.
    mac = device.mac or _learn_mac(app, device.target, force=True)
    if not mac:
        return fail("no_mac", 409)
    try:
        sent = wol.send(mac, host)
    except ValueError:
        return fail("no_mac", 409)
    if not sent:
        return fail("wake_failed", 502)
    return ok(action="wake_sent")


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


def _status(app: object, request: Request, token: str, ip: str) -> Result:
    """Read-only snapshot of what the dashboard knows, for scripts and dashboards.

    It changes nothing and touches the device at most to report whether the adb port is open.
    The TV's host is not echoed back: it is the operator's own registry, and a status read must
    not become a way to read an address out of the appliance.
    """
    devices = app.registry.list_public()
    with app.lock:
        active = app.registry.active_target()
    host, _, port_text = active.rpartition(":")
    awake = False
    if host:
        try:
            awake = wol.is_awake(host, int(port_text), _AWAKE_PROBE_SECONDS)
        except (TypeError, ValueError):
            awake = False
    return ok(
        api="scriptable",
        devices=devices,
        count=len(devices),
        active={"target": bool(active), "awake": awake},
        quick_launch=list(app.prefs.quick_launch),
    )


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
    _remember_installed(app, [item.get("package", "") for item in listed])
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


# ---------------------------------------------------------------------------- quick launch


def _quick_launch(app: object, request: Request, token: str, ip: str) -> Result:
    """Launch one catalogued streaming app by alias.

    The browser sends `netflix`, never a package: `platforms` owns the mapping. A service can
    ship under more than one package name, so a candidate the device does not have is followed
    by the next one rather than reported as a failure.

    A TV that is asleep is woken first (`_wake_if_asleep`), so one press lands in the app.
    """
    # A press can now send a broadcast and hold a thread for a few seconds, so it shares the
    # key budget.
    if not _KEYS.allow(token):
        return fail("rate_limited", 429, retry_after=int(KEY_WINDOW_SECONDS))
    # An alias we do not know is refused before any device lookup, the same way an unknown key
    # is: a typo in the browser is not a reason to go and ask the TV anything.
    try:
        platform = platforms.resolve(request.text("platform"))
    except platforms.UnknownPlatform:
        return fail("bad_platform")

    candidates = platforms.launch_candidates(platform, _installed(app))
    if not candidates:
        return fail("bad_platform")

    target = _target(app)
    if not target:
        return fail("no_device", 409)

    # One press: wake the TV first if it is asleep, then launch exactly as before.
    woke = _wake_if_asleep(app, target)

    attempt = fail("adb_failed", 502)
    for package in candidates:
        attempt = _adb(
            lambda pkg=package: app.adb.launch(target, pkg),
            platform=platform.alias,
            label=platform.label,
        )
        if attempt.status == 200:
            _remember_installed(app, [package])
            _learn_mac(app, target)
            break
        # adb itself being gone is not something the next package can fix.
        if attempt.payload.get("error") == "adb_missing":
            break
    attempt.payload["woke"] = woke
    return attempt


#: One quick-launch press should wake a sleeping TV and still land in the app. The pause is the
#: operator's figure for how long the TV takes to come back. If it is still not answering by
#: then, the launch keeps checking for a little longer rather than failing, and goes ahead the
#: moment the TV answers.
QUICK_LAUNCH_WAKE_PAUSE = 3.0
QUICK_LAUNCH_WAKE_GRACE = 10.0
_WAKE_POLL_SECONDS = 0.5
_AWAKE_PROBE_SECONDS = 1.0
#: Indirection so the tests can run the sequence without really waiting.
_sleep = time.sleep


def _wake_if_asleep(app: object, target: str) -> bool:
    """Before a launch: if the TV is asleep, wake it. Returns True when a packet was sent.

    The sequence: check whether the TV answers; if it does not, send Wake-on-LAN, pause, then
    wait (bounded) for it to answer before the launch goes ahead.

    Anything that stops the wake - no MAC learned yet, a send that fails - falls back to
    launching exactly as before rather than refusing. The check could be wrong, and a launch
    that fails reports itself.
    """
    host, _, port_text = target.rpartition(":")
    try:
        port = int(port_text)
    except ValueError:
        return False
    if wol.is_awake(host, port, _AWAKE_PROBE_SECONDS):
        return False

    mac = _learn_mac(app, target, force=True)
    if not mac:
        return False
    try:
        if not wol.send(mac, host):
            return False
    except ValueError:
        return False

    _sleep(QUICK_LAUNCH_WAKE_PAUSE)
    deadline = time.monotonic() + QUICK_LAUNCH_WAKE_GRACE
    while not wol.is_awake(host, port, _AWAKE_PROBE_SECONDS) and time.monotonic() < deadline:
        _sleep(_WAKE_POLL_SECONDS)
    return True


def _prefs_quick_launch(app: object, request: Request, token: str, ip: str) -> Result:
    """Show or hide one quick-launch tile. The choice is the operator's and it is persisted."""
    try:
        enabled = app.prefs.toggle_quick_launch(request.text("alias"), request.flag("on"))
    except platforms.UnknownPlatform:
        return fail("bad_platform")
    return ok(action="quick_launch_updated", quick_launch=list(enabled))


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


def _add_device(app: object, request: Request, token: str, ip: str) -> Result:
    """Add a TV by typing its address, for when discovery cannot see it.

    Discovery is a convenience, not the only way in: a TV on another subnet, behind a NATted
    container, or simply asleep during the sweep will never appear in a candidate list, and
    the operator usually knows the address anyway.

    The browser names a host here, which the candidate flow deliberately avoids - so the same
    guard does the deciding: dotted IPv4, RFC1918 only, and a configured adb port. It cannot
    be pointed at loopback, at link-local, or off the LAN.
    """
    raw = request.text("host").strip()
    port = request.text("port").strip()
    if port and ":" not in raw:
        raw = f"{raw}:{port}"
    try:
        target = netguard.normalize_target(raw, app.config.allowed_cidrs, app.config.device_ports)
    except netguard.TargetRejected as exc:
        return fail("bad_host", 400, detail=str(exc))

    try:
        connected = app.adb.connect(target)
    except AdbError:
        return fail("adb_missing", 503)
    if not connected.ok:
        # Android 11+ refuses an unpaired connect, and that is the common case here.
        return fail("connect_failed", 502)

    try:
        with app.lock:
            device = app.registry.add(target, model=_model_of(app, target))
    except RegistryError:
        return fail("device_limit", 409)
    return ok(action="joined", device=device.public())


def _pair(app: object, request: Request, token: str, ip: str) -> Result:
    """Pair with the address and code the TV shows under Wireless debugging.

    The pairing address is not the connect address: Android hands out a fresh random port for
    pairing and keeps 5555 (or its own random port) for the connection. They are asked for
    separately because the TV displays them separately.
    """
    try:
        pair_host, pair_port = netguard.normalize_pair_target(
            request.text("pair_address"), app.config.allowed_cidrs
        )
        code = netguard.validate_pair_code(request.text("pairing_code"))
    except netguard.TargetRejected as exc:
        return fail("bad_pair_address", 400, detail=str(exc))
    if not code:
        return fail("bad_pair_code")

    try:
        paired = app.adb.pair(pair_host, pair_port, code)
    except AdbError:
        return fail("adb_missing", 503)
    except ValueError:
        return fail("bad_pair_code")
    if not paired.ok:
        return fail("pairing_failed", 502)

    # Pairing does not connect. The connect port is the one the TV lists under its own name
    # in the wireless-debugging screen, which is usually 5555.
    connect_raw = request.text("host").strip() or pair_host
    try:
        target = netguard.normalize_target(
            connect_raw, app.config.allowed_cidrs, app.config.device_ports
        )
    except netguard.TargetRejected:
        return ok(action="paired", connected=False)

    try:
        connected = app.adb.connect(target)
    except AdbError:
        return fail("adb_missing", 503)
    if not connected.ok:
        return ok(action="paired", connected=False)

    try:
        with app.lock:
            device = app.registry.add(target, model=_model_of(app, target))
    except RegistryError:
        return fail("device_limit", 409)
    result = ok(action="joined", connected=True, device=device.public())
    result.redirect = "/settings?e=joined" if _is_form(request) else ""
    return result


def _model_of(app: object, target: str) -> str:
    """Ask the device what it is, for the label. A device that will not say is still added."""
    try:
        result = app.adb.run_on_device(target, ["shell", "getprop", "ro.product.model"])
    except (AdbError, ValueError):
        return ""
    if not result.ok:
        return ""
    lines = result.lines()
    return lines[0][:48] if lines else ""


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


def _installed(app: object) -> frozenset[str]:
    """Packages the device was last seen to have, or an empty set when nobody has looked.

    This is a hint for choosing between a service's package names, never a gate: an app that
    is not in it is still launched, because the list may simply be stale.
    """
    seen = getattr(app, "installed", None)
    return frozenset(seen) if isinstance(seen, (set, frozenset)) else frozenset()


def _remember_installed(app: object, packages: object) -> None:
    """Record what the device answered with. Best effort; a failure here changes nothing."""
    note = getattr(app, "note_installed", None)
    if callable(note):
        note(packages)


#: After a MAC lookup comes up empty, leave that device alone for this long, so a lookup that
#: keeps failing does not run on every key press.
_MAC_RETRY_SECONDS = 60.0
_MAC_MISSES: dict[str, float] = {}


def _learn_mac(app: object, target: str, *, force: bool = False) -> str:
    """Remember the MAC of a device that just answered, and return it ('' when unknown).

    The ARP table only holds a TV's MAC while the TV is awake, and the MAC is only needed once
    it is asleep - so it is picked up after a successful command and kept in the registry.
    Once a device has one, this is a dictionary lookup.
    """
    with app.lock:
        device = app.registry.get_by_target(target)
    if device is None:
        return ""
    if device.mac:
        return device.mac
    now = time.monotonic()
    last_miss = _MAC_MISSES.get(target)
    if not force and last_miss is not None and now - last_miss < _MAC_RETRY_SECONDS:
        return ""
    mac = wol.lookup_mac(target.rsplit(":", 1)[0])
    if not mac:
        _MAC_MISSES[target] = now
        return ""
    _MAC_MISSES.pop(target, None)
    with app.lock:
        app.registry.set_mac(device.id, mac)
    return mac


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
    "/api/wake": _wake,
    "/api/status": _status,
    "/api/text": _text,
    "/api/screenshot": _screenshot,
    "/api/apps": _apps,
    "/api/launch": _launch,
    "/api/quick_launch": _quick_launch,
    "/api/prefs/quick_launch": _prefs_quick_launch,
    "/api/stop": _app_action("stop"),
    "/api/appinfo": _app_action("app_info"),
    "/api/clear": _app_action("clear_data"),
    "/api/uninstall": _app_action("uninstall"),
    "/api/discover": _discover,
    "/api/join": _join,
    "/api/devices/add": _add_device,
    "/api/pair": _pair,
    "/api/devices/use": _device_form,
    "/api/devices/set_nickname": _device_form,
    "/api/devices/remove": _device_form,
    "/api/devices/connect": _device_form,
    "/api/devices/disconnect": _device_form,
}

__all__ = ["Result", "handle", "fail", "ok"]
