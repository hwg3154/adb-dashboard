"""Server-rendered pages.

The browser gets HTML it cannot argue with: every value is escaped here, and the only things the
browser may send back are an opaque id or an allowlisted alias. No page assembles a command, a
host, or a keycode out of browser input.

Templates are plain HTML files with `$var` placeholders in `tvdashboard/templates/`. Loops are
rendered here, one escaped row at a time, because `string.Template` has no loop of its own.

See `docs/design.md` §3 for the module map and §8 for the URL surface.
"""

from __future__ import annotations

import os
import re
import string

from . import registry
from .config import MAX_INPUT_CHARS, Config
from .security import CSRF_FIELD, render_attr, render_text

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

#: Static navigation. A browser cannot add to it and cannot hide it.
NAV: tuple[tuple[str, str], ...] = (
    ("Dashboard", "/"),
    ("Apps", "/apps"),
    ("Settings", "/settings"),
)

MAX_ROWS = 32
#: Every key in the allowlist gets a tile; the cap only stops an absurd map from filling a page.
MAX_TILES = 64
#: A rendered list of app rows can be long; anything longer is not a page we will send.
_MAX_RENDER_CHARS = 96 * 1024
_FALLBACK_PAGE = "<!doctype html><p class=\"error\">page is not available</p>"

_TEMPLATE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,15}$")
_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,15}$")
_ALIAS_RE = re.compile(r"^[a-z][a-z0-9_]{1,32}$")
_PACKAGE_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HEX_RE = re.compile(r"^[0-9a-f]{32}$")

#: The five things the launcher may do to an app. The path is the decision, not the browser.
_APP_ACTIONS = (
    ("/api/launch", "Launch", ""),
    ("/api/stop", "Force stop", "Force stop this app?"),
    ("/api/appinfo", "App info", ""),
    ("/api/clear", "Clear data", "Erase this app's data on the TV? This cannot be undone."),
    ("/api/uninstall", "Uninstall", "Uninstall this app from the TV? This cannot be undone."),
)

#: What each page fragment may contain. A template cannot ask for more than this.
_FRAGMENT_FIELDS = {
    "index": frozenset({"notice", "tiles", "text_field", "screenshot", "device"}),
    "apps": frozenset({"notice", "app_rows"}),
    "settings": frozenset({"notice", "device_rows", "password_form"}),
    "login": frozenset({"notice", "hint"}),
    "setup": frozenset({"notice", "candidate_rows"}),
}

#: Which nav entry is lit. Keyed by the page title, which we choose, not the browser.
_CURRENT = {
    "Dashboard": "nav-on",
    "Apps": "nav-on",
    "Settings": "nav-on",
    "Sign in": "nav",
    "Set up TV": "nav",
}


class ViewError(RuntimeError):
    """Raised when a page cannot be rendered. The caller answers with a code, not a stack trace."""


def load_template(name: str) -> str:
    """Read one template by name. Names come from a fixed set, never from the browser."""
    candidate = name.strip() if isinstance(name, str) else ""
    if not _TEMPLATE_NAME.match(candidate):
        raise ViewError("unknown template")
    try:
        with open(os.path.join(TEMPLATE_DIR, candidate + ".html"), "rb") as handle:
            return handle.read().decode("utf-8")
    except (OSError, ValueError):
        raise ViewError("template is not readable") from None


def render(name: str, values: dict[str, str]) -> str:
    """Render a template with a fixed set of string fields. Never raises on bad values."""
    safe: dict[str, str] = {}
    for key, value in values.items():
        if isinstance(key, str) and _FIELD_NAME.match(key) and isinstance(value, str):
            safe[key] = value
    try:
        return string.Template(load_template(name)).substitute(safe)
    except (KeyError, ValueError, OSError):
        return ""


class View:
    """Page renderers. Each one returns `(status, html)`; the caller only writes bytes."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def index(self, reg: registry.Registry, csrf: str) -> tuple[int, str]:
        """The remote: a focusable panel of key tiles, a text field, one screenshot."""
        return self._page("Dashboard", "index", {
            "tiles": self._tiles(csrf),
            "text_field": self._text_field(csrf),
            "screenshot": self._screenshot(),
            "device": self._devices(reg, csrf),
        }, csrf)

    def apps(self, apps: list[dict[str, str]], csrf: str) -> tuple[int, str]:
        """The launcher: one row per launchable app, and only the five actions we allow."""
        rows = [self._app_row(app, csrf) for app in apps[:MAX_ROWS]]
        body = self._fill("apps", {
            "app_rows": "\n".join(item for item in rows if item)
            or '<p class=muted>No launchable app was found.</p>',
        })
        return 200, self._wrap("Apps", body, csrf)

    def settings(self, reg: registry.Registry, csrf: str) -> tuple[int, str]:
        """Settings: the device list and the password. Nothing else."""
        rows = [self._device_row(device, csrf) for device in reg.list_public()[:MAX_ROWS]]
        body = self._fill("settings", {
            "device_rows": "\n".join(item for item in rows if item)
            or '<p class=muted>No device is paired yet. Use <a href="/setup">Set up TV</a>.</p>',
            "password_form": self._password_form(csrf),
        })
        return 200, self._wrap("Settings", body, csrf)

    def login(self, csrf: str = "", *, first_run: bool = False) -> tuple[int, str]:
        """Sign in, or the first-run password form. One page, one different hint."""
        body = self._fill("login", {"hint": _login_hint(first_run)}, csrf)
        return 200, self._wrap("Sign in", body, csrf)

    def setup(self, candidates: list[dict[str, object]], csrf: str) -> tuple[int, str]:
        """The wizard: candidates to pick, an optional pairing code, and nothing else."""
        rows = [self._candidate_row(candidate, csrf) for candidate in candidates[:MAX_ROWS]]
        body = self._fill("setup", {
            "candidate_rows": "\n".join(item for item in rows if item)
            or "<p class=muted>No device answered.</p>",
        })
        return 200, self._wrap("Set up TV", body, csrf)

    # --------------------------------------------------------------------------- components

    def _tiles(self, csrf: str = "") -> str:
        """A grid of key buttons. The alias is the only thing the browser ever names."""
        from .keys import KEY_ALIASES

        out: list[str] = []
        for spec in tuple(KEY_ALIASES.values())[:MAX_TILES]:
            alias = getattr(spec, "alias", "")
            label = getattr(spec, "label", "")
            if not isinstance(alias, str) or not _ALIAS_RE.match(alias):
                continue
            confirm = getattr(spec, "confirm", "")
            out.append(
                '<button class="tile ' + render_attr(getattr(spec, "group", "")) + '"'
                ' type=submit form=key-form name="key"'
                ' value="' + render_attr(alias) + '"'
                + (' data-confirm="' + render_attr(confirm) + '"' if confirm else "")
                + ">" + render_text(label) + "</button>"
            )
        return '<div class=keys>' + "".join(out) + "</div>" + _csrf_input(csrf)

    def _text_field(self, csrf: str = "") -> str:
        limit = min(self.config.max_text_chars, MAX_INPUT_CHARS)
        return (
            _csrf_input(csrf)
            + '<label for=text>Send to TV</label>'
            '<input id=text name=text type=text maxlength='
            + str(limit)
            + ' autocomplete=off placeholder="a search, a title, a URL">'
            '<button type=submit>Send</button>'
        )

    def _screenshot(self) -> str:
        return (
            "<p class=muted>The screen is never streamed. One screenshot, on request.</p>"
            '<img class=screen alt="TV screenshot (empty until requested)"'
            ' src="/static/placeholder.png">'
        )

    def _devices(self, reg: registry.Registry, csrf: str) -> str:
        devices = reg.list_public()
        if not devices:
            return '<p class=muted>No device yet. Start with <a href="/setup">Set up TV</a>.</p>'
        rows: list[str] = ['<ul class=devices>']
        for device in devices:
            rows.append(
                '<li><span class=label>'
                + render_text(device.get("label", ""))
                + '</span> <a href="/apps">Apps</a></li>'
            )
        rows.append("</ul>")
        return "".join(rows)

    def _app_row(self, app: dict[str, str], csrf: str) -> str:
        """One app: a package name, an activity, and five POST buttons."""
        package = app.get("package", "")
        if not _PACKAGE_RE.match(package):
            return '<li class="row muted">unrecognized package</li>'
        actions = "".join(
            _action_form(action, package, label, csrf, confirm)
            for action, label, confirm in _APP_ACTIONS
        )
        return (
            '<li class="row">'
            '<span class=pkg>' + render_text(package) + "</span>"
            '<span class=kind>' + render_text(app.get("kind", "")) + "</span>"
            '<span class=actions>' + actions + "</span>"
            "</li>"
        )

    def _device_row(self, device: dict[str, str], csrf: str) -> str:
        """One device: a label, a rename field, and Forget. The id is the only handle."""
        device_id = device.get("id", "")
        if not _HEX_RE.match(device_id):
            return '<li class="row muted">unrecognized device</li>'
        return (
            '<li class="row">'
            '<span class=label>' + render_text(device.get("label", "")) + "</span>"
            '<span class=model>' + render_text(device.get("model", "")) + "</span>"
            '<span class=actions>'
            '<form method=post action="/api/devices/use" class=inline'
            ' data-confirm="Use this TV">'
            '<input type=hidden name=id value="' + render_attr(device_id) + '">'
            + _csrf_input(csrf)
            + "<button type=submit>Use</button></form>"
            '<form method=post action="/api/devices/set_nickname" class=inline'
            ' data-confirm="Rename this device">'
            '<input type=hidden name=id value="' + render_attr(device_id) + '">'
            + '<input type=text name=nickname maxlength=32 autocomplete=off placeholder="nickname">'
            + _csrf_input(csrf)
            + "<button type=submit>Rename</button></form>"
            '<form method=post action="/api/devices/remove" class=inline'
            ' data-confirm="Forget this device">'
            '<input type=hidden name=id value="' + render_attr(device_id) + '">'
            + _csrf_input(csrf)
            + '<button type=submit class=danger>Forget</button></form>'
            "</span></li>"
        )

    def _candidate_row(self, candidate: dict[str, object], csrf: str) -> str:
        """One candidate: a model, a host to confirm it is yours, and one Join button."""
        candidate_id = candidate.get("id")
        if not isinstance(candidate_id, str) or not _HEX_RE.match(candidate_id):
            return '<li class="row muted">unrecognized device</li>'
        host = candidate.get("host", "")
        host = host if isinstance(host, str) and _HOST_RE.match(host) else ""
        score = candidate.get("score")
        return (
            '<li class="row">'
            '<span class=model>' + render_text(candidate.get("model", "") or "unknown model") + "</span>"
            '<span class=host>' + render_text(host) + "</span>"
            '<span class=score>' + render_text(score if isinstance(score, int) else "") + "</span>"
            '<form method=post action="/api/join" class=inline'
            ' data-confirm="Join this device? The TV may ask you to accept a pairing code">'
            '<input type=hidden name=candidate_id value="' + render_attr(candidate_id) + '">'
            '<input type=text name=pairing_code maxlength=10 autocomplete=off'
            ' placeholder="pairing code, if the TV shows one">'
            + _csrf_input(csrf)
            + "<button type=submit>Join</button></form>"
            "</li>"
        )

    def _password_form(self, csrf: str = "") -> str:
        return (
            '<form method=post action="/api/change_password" class=stack>'
            + _csrf_input(csrf)
            + '<label for=current>Current password</label>'
            '<input id=current name=current type=password autocomplete=current-password maxlength=128>'
            '<label for=password>New password</label>'
            '<input id=password name=password type=password autocomplete=new-password maxlength=128>'
            "<button type=submit>Change password</button>"
            "</form>"
        )

    # --------------------------------------------------------------------------------- internals

    def _page(
        self, title: str, name: str, values: dict[str, str], csrf: str = ""
    ) -> tuple[int, str]:
        """Compose one page: a filled fragment inside the shared shell."""
        return 200, self._wrap(title, self._fill(name, values, csrf), csrf)

    def _fill(self, name: str, values: dict[str, str], csrf: str = "") -> str:
        """Render one page fragment. Unknown keys and oversized values are dropped."""
        safe = {
            key: value[: _MAX_RENDER_CHARS]
            for key, value in values.items()
            if isinstance(key, str) and _FIELD_NAME.match(key) and isinstance(value, str)
            and key in _FRAGMENT_FIELDS.get(name, frozenset())
        }
        safe["csrf"] = _validated_token(csrf)
        body = _substitute(load_template(name), safe)
        return body or '<p class="error">page is not available</p>'

    def _wrap(self, title: str, body: str, csrf: str = "") -> str:
        """Compose a page: shell, nav, notice, and one rendered fragment."""
        page = _substitute(load_template("base"), {
            "title": title,
            "nav": _nav(),
            "notice": _notice(self.config),
            "csrf": _validated_token(csrf),
            "body": body,
        })
        return page or _FALLBACK_PAGE


# ------------------------------------------------------------------------------ internals


def _csrf_input(token: str) -> str:
    return '<input type=hidden name="' + CSRF_FIELD + '" value="' + render_attr(token) + '">'


def _substitute(template: str, values: dict[str, str]) -> str:
    try:
        return string.Template(template).substitute(values)
    except (KeyError, ValueError):
        return ""


def _nav() -> str:
    return "".join(
        '<a class="' + _CURRENT.get(title, "nav") + '" href="' + render_attr(href) + '">'
        + render_text(title)
        + "</a>"
        for title, href in NAV
    )


def _notice(config: Config) -> str:
    if config.allow_insecure_http:
        return ""
    return "Plain HTTP on a trusted LAN. No TLS, no cloud, no telemetry."


def _login_hint(first_run: bool) -> str:
    if first_run:
        return "Create the dashboard password. The TV does not ask for one."
    return "Sign in with the dashboard password, not the TV password."


def _action_form(action: str, package: str, label: str, csrf: str, confirm: str = "") -> str:
    """One app action. The action is a constant; the package is validated, never interpolated."""
    if not isinstance(package, str) or not _PACKAGE_RE.match(package):
        return ""
    return (
        '<form method=post action="'
        + render_attr(action)
        + '" class="inline action"'
        + (' data-confirm="' + render_attr(confirm) + '"' if confirm else "")
        + '>'
        + '<input type=hidden name=package value="'
        + render_attr(package)
        + '">'
        + _csrf_input(_validated_token(csrf))
        + '<button type=submit>'
        + render_text(label)
        + "</button></form>"
    )


def _validated_token(value: object) -> str:
    from .security import is_token

    candidate = value.strip() if isinstance(value, str) else ""
    return candidate if is_token(candidate) else ""
