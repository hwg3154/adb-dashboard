"""HTTP server, routing and the application object.

The server is deliberately dull. It reads a bounded request, hands it to `security.build_request`,
looks the path up in a fixed table, and writes whatever the handler returned. It makes no security
decisions of its own: authentication is `security.authorize`, request hygiene is
`security.check_write_headers`, and every device command goes through `api`.

Routes are a table, not a dispatcher that turns a path into an attribute name: a browser can only
reach a handler that is written down here.

See `docs/design.md` §3 for the module map and §8 for the URL surface.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from . import api, platforms, security, storage, views
from .adb import AdbClient
from .auth import AuthService
from .config import COOKIE_NAME, Config
from .prefs import Prefs
from .registry import Registry
from .sessions import SessionStore

#: Largest request body we will read at all. `config.max_body_bytes` is the real limit; this is
#: the ceiling that stops a malicious Content-Length from allocating anything interesting.
_ABSOLUTE_MAX_BODY = 256 * 1024

#: Static assets, by URL path. Nothing is served from the filesystem by a browser-supplied name.
_STATIC: dict[str, tuple[str, str]] = {
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/placeholder.png": ("placeholder.png", "image/png"),
}

#: Quick-launch artwork, added from the catalogue rather than from the URL: the key is a path
#: we built, so a browser still cannot name a file.
_STATIC.update(platforms.logo_files())

_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

_SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    # NOT "no-referrer": that policy makes browsers send `Origin: null` on form navigations
    # and drop Referer entirely, which breaks the origin check and the form redirect.
    # "same-origin" keeps our URLs from ever reaching a third party, which is the point.
    ("Referrer-Policy", "same-origin"),
    # No CDN, no inline handlers: everything the page runs is served from this origin.
    (
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    ),
)


class Application:
    """Everything one process needs, built once at start-up and then read-mostly.

    The stores are shared across worker threads, so `lock` guards the mutating paths. adb calls
    are deliberately outside that lock: they are slow, and two key presses racing is a device
    problem, not a state problem.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.started_at = int(time.time())
        self.lock = threading.RLock()

        storage.ensure_data_dir(config.data_dir)
        self.sessions = SessionStore.load(config)
        self.auth = AuthService.load(config, self.sessions)
        self.registry = Registry.load(config)
        self.prefs = Prefs.load(config)
        self.adb = AdbClient.from_config(config)
        self.view = views.View(config)
        #: Packages the TV was last seen to have. A hint for picking between a streaming
        #: service's several package names, never a permission check. Not persisted: it is
        #: cheap to rebuild and wrong the moment someone installs something.
        self.installed: frozenset[str] = frozenset()

    @property
    def is_initialized(self) -> bool:
        return self.auth.is_initialized

    def csrf_for(self, token: str) -> str:
        return self.sessions.csrf_for(token)

    def note_installed(self, packages: object) -> None:
        """Merge freshly-seen package names into the hint set. Never raises."""
        if not isinstance(packages, (list, tuple, set, frozenset)):
            return
        seen = {
            item.strip().lower()
            for item in packages
            if isinstance(item, str) and 0 < len(item) <= 128
        }
        if not seen:
            return
        with self.lock:
            self.installed = frozenset(self.installed | seen)


# --------------------------------------------------------------------------------- routing


def _page(handler: Callable[[Application, security.Request, str], tuple[int, str]]):
    """Mark a route as an HTML page: GET only, and it renders through `views`."""
    handler.kind = "page"  # type: ignore[attr-defined]
    return handler


def _route_index(app: Application, request: security.Request, token: str) -> tuple[int, str]:
    with app.lock:
        return app.view.index(app.registry, app.csrf_for(token), tiles=app.prefs.tiles())


def _route_apps(app: Application, request: security.Request, token: str) -> tuple[int, str]:
    target = _active_target(app)
    apps: list[dict[str, str]] = []
    if target:
        try:
            apps = app.adb.list_apps(target)
        except (ValueError, OSError, RuntimeError):
            apps = []
    app.note_installed([item.get("package", "") for item in apps])
    return app.view.apps(apps, app.csrf_for(token))


def _route_settings(app: Application, request: security.Request, token: str) -> tuple[int, str]:
    with app.lock:
        return app.view.settings(
            app.registry,
            app.csrf_for(token),
            catalog=app.prefs.catalog(),
            installed=app.installed,
            notice=views.setup_notice(request.query.get("e", "")),
        )


def _route_setup(app: Application, request: security.Request, token: str) -> tuple[int, str]:
    """The wizard lists whatever the last discovery run found. Discovery itself is a POST."""
    with app.lock:
        candidates = [item.public() for item in app.registry.candidates()]
    return app.view.setup(
        candidates, app.csrf_for(token), views.setup_notice(request.query.get("e", ""))
    )


#: GET routes that need a session.
_PAGES: dict[str, Callable[[Application, security.Request, str], tuple[int, str]]] = {
    "/": _route_index,
    "/apps": _route_apps,
    "/settings": _route_settings,
    "/setup": _route_setup,
}


def _active_target(app: Application) -> str:
    with app.lock:
        return app.registry.active_target()


# ---------------------------------------------------------------------------------- handler


class Handler(BaseHTTPRequestHandler):
    """One request. Nothing here decides policy; it reads, dispatches and writes."""

    server_version = "tvdashboard"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------------------------ methods

    def do_GET(self) -> None:
        self._serve(read_body=False)

    def do_HEAD(self) -> None:
        self._serve(read_body=False, head=True)

    def do_POST(self) -> None:
        self._serve(read_body=True)

    # ------------------------------------------------------------------------------ plumbing

    def _serve(self, *, read_body: bool, head: bool = False) -> None:
        app: Application = self.server.app  # type: ignore[attr-defined]
        started = time.monotonic()
        request = security.build_request(self.command, self.path, dict(self.headers.items()), b"")
        status = 500
        try:
            body = self._read_body(app) if read_body else b""
            request = security.build_request(self.command, self.path, dict(self.headers.items()), body)
            status = self._dispatch(app, request, head=head)
        except security.RequestRejected as exc:
            status = _status_for(exc.code)
            self._write_json(status, {"ok": False, "error": exc.code}, retry_after=exc.retry_after)
        except BrokenPipeError:
            return
        except Exception:  # noqa: BLE001 - a handler bug must not take the server down
            # The browser gets a code; the operator gets the traceback, or a 500 is invisible.
            traceback.print_exc(file=sys.stderr)
            self._write_json(500, {"ok": False, "error": "internal"})
            status = 500
        finally:
            _log(app, request, status, int((time.monotonic() - started) * 1000), self.client_address)

    def _read_body(self, app: Application) -> bytes:
        """Read exactly as many bytes as declared, and never more than the cap."""
        try:
            declared = int(self.headers.get("Content-Length", "0") or "0")
        except (TypeError, ValueError):
            return b""
        if declared <= 0:
            return b""
        limit = min(max(app.config.max_body_bytes, 1), _ABSOLUTE_MAX_BODY)
        if declared > limit:
            # The body is never read, so this connection cannot carry another request.
            self.close_connection = True
            raise security.RequestRejected("payload_too_large")
        try:
            return self.rfile.read(declared)
        except (OSError, ValueError):
            return b""

    def _dispatch(self, app: Application, request: security.Request, *, head: bool) -> int:
        if not request.method:
            self._write_json(405, {"ok": False, "error": "bad_method"})
            return 405
        if not request.path:
            self._write_json(404, {"ok": False, "error": "not_found"})
            return 404

        if request.method in {"GET", "HEAD"}:
            return self._dispatch_get(app, request, head=head)
        return self._dispatch_post(app, request)

    def _dispatch_get(self, app: Application, request: security.Request, *, head: bool) -> int:
        path = request.path

        if path in _STATIC:
            return self._serve_static(path, head=head)
        if path == "/healthz":
            return self._write_json(200, {"ok": True, "uptime_s": int(time.time()) - app.started_at})

        token = security.authorize(app, request)

        # `?e=` is how a failed POST hands the page a reason. It is a code from a fixed set,
        # never a message: the words are chosen in `views`, so nothing a browser sends can
        # put a sentence on the sign-in page.
        notice = views.login_notice(request.query.get("e", ""))

        # Before an account exists there is exactly one thing to do, and one page to do it on.
        if not app.is_initialized:
            if path == "/login":
                return self._write_page(*app.view.login("", first_run=True, notice=notice))
            return self._redirect("/login")

        if not token:
            if path == "/login":
                return self._write_page(*app.view.login("", notice=notice))
            return self._redirect("/login")

        if path == "/login":
            return self._redirect("/")

        handler = _PAGES.get(path)
        if handler is None:
            return self._write_page(404, "<!doctype html><p>Not found.</p>")
        return self._write_page(*handler(app, request, token))

    def _dispatch_post(self, app: Application, request: security.Request) -> int:
        result = api.handle(app, request, security.client_address(self.client_address))
        headers: list[tuple[str, str]] = []
        if result.set_cookie:
            headers.append(("Set-Cookie", _cookie(app, result.set_cookie)))
        if result.clear_cookie:
            headers.append(("Set-Cookie", _expired_cookie(app)))
        if result.redirect:
            headers.append(("Location", result.redirect))
            self._write(303, b"", "text/plain; charset=utf-8", extra=headers)
            return 303
        if result.raw is not None:
            self._write(result.status, result.raw, result.content_type, extra=headers)
            return result.status
        return self._write_json(result.status, result.payload, extra=headers)

    # ------------------------------------------------------------------------------- writers

    def _serve_static(self, path: str, *, head: bool = False) -> int:
        name, content_type = _STATIC[path]
        try:
            with open(os.path.join(_STATIC_DIR, name), "rb") as handle:
                body = handle.read()
        except OSError:
            return self._write_json(404, {"ok": False, "error": "not_found"})
        # Assets are versioned by the process start, so a redeploy is picked up without a
        # hard refresh while a running page still caches.
        self._write(200, b"" if head else body, content_type, extra=[("Cache-Control", "no-cache")], length=len(body))
        return 200

    def _write_page(self, status: int, html: str) -> int:
        self._write(status, html.encode("utf-8"), "text/html; charset=utf-8")
        return status

    def _redirect(self, location: str) -> int:
        self._write(303, b"", "text/plain; charset=utf-8", extra=[("Location", location)])
        return 303

    def _write_json(
        self,
        status: int,
        payload: dict[str, object],
        *,
        retry_after: int = 0,
        extra: list[tuple[str, str]] | None = None,
    ) -> int:
        headers = list(extra or ())
        if retry_after > 0:
            headers.append(("Retry-After", str(int(retry_after))))
        try:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            body = b'{"ok":false,"error":"internal"}'
        self._write(status, body, "application/json; charset=utf-8", extra=headers)
        return status

    def _write(
        self,
        status: int,
        body: bytes,
        content_type: str,
        *,
        extra: list[tuple[str, str]] | None = None,
        length: int | None = None,
    ) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length if length is not None else len(body)))
            for name, value in _SECURITY_HEADERS:
                self.send_header(name, value)
            for name, value in extra or ():
                self.send_header(name, value)
            self.end_headers()
            if body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True

    # BaseHTTPRequestHandler logs to stderr in its own format; we log structured JSON instead.
    def log_message(self, fmt: str, *args: object) -> None:
        return


# ------------------------------------------------------------------------------------ cookies


def _cookie(app: Application, token: str) -> str:
    """Session cookie. `Secure` only when TLS terminates in front, per design.md §9."""
    parts = [
        f"{COOKIE_NAME}={token}",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        f"Max-Age={int(app.config.session_absolute_seconds)}",
    ]
    if not app.config.allow_insecure_http:
        parts.append("Secure")
    return "; ".join(parts)


def _expired_cookie(app: Application) -> str:
    parts = [f"{COOKIE_NAME}=", "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"]
    if not app.config.allow_insecure_http:
        parts.append("Secure")
    return "; ".join(parts)


# -------------------------------------------------------------------------------------- logs


def _status_for(code: str) -> int:
    return {
        "unauthorized": 401,
        "bad_csrf": 403,
        "bad_origin": 403,
        "forbidden": 403,
        "not_found": 404,
        "bad_method": 405,
        "payload_too_large": 413,
        "locked": 429,
        "rate_limited": 429,
        "adb_missing": 503,
        "no_device": 409,
    }.get(code, 400)


def _log(app: Application, request: security.Request, status: int, elapsed_ms: int, peer: object) -> None:
    """One structured line per request. No tokens, no passwords, no user-entered text."""
    record = {
        "ts": int(time.time()),
        "method": request.method or "?",
        "path": request.path or "?",
        "status": status,
        "ms": elapsed_ms,
        "ip": security.client_address(peer),
    }
    try:
        sys.stdout.write(json.dumps(record, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        pass


# ------------------------------------------------------------------------------------ server


class Server(ThreadingHTTPServer):
    """A threading server that does not hold the port after a restart."""

    daemon_threads = True
    allow_reuse_address = True
    # A slow client must not hold a worker thread forever.
    timeout = 30

    def __init__(self, config: Config, app: Application) -> None:
        self.app = app
        if ":" in config.listen_host and config.listen_host not in {"0.0.0.0", ""}:
            self.address_family = socket.AF_INET6
        super().__init__((config.listen_host, config.listen_port), Handler)


def build(config: Config) -> Server:
    """Build the application and its server. Raises if the data directory is unusable."""
    return Server(config, Application(config))


def serve(config: Config) -> int:
    """Run until interrupted. Returns the process exit code."""
    try:
        server = build(config)
    except storage.StorageError as exc:
        sys.stderr.write(f"tvdashboard: {exc}\n")
        return 1

    app: Application = server.app
    for warning in config.warnings:
        sys.stderr.write(f"tvdashboard: config: {warning}\n")
    if not app.adb.available():
        sys.stderr.write(
            f"tvdashboard: adb binary {config.adb_bin!r} was not found on PATH; "
            "device commands will fail until it is installed\n"
        )
    if not app.is_initialized:
        sys.stderr.write("tvdashboard: no account yet - open /login to create one\n")

    sys.stderr.write(f"tvdashboard: listening on http://{config.listen_host}:{config.listen_port}\n")
    sys.stderr.flush()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        sys.stderr.write("tvdashboard: stopping\n")
    finally:
        server.shutdown()
        server.server_close()
    return 0
