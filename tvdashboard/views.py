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
#: A logo URL this server serves: our prefix, one safe filename, a known extension.
_LOGO_URL_RE = re.compile(r"^/static/logos/[a-z0-9_]{1,32}\.(?:png|jpe?g|webp)$")

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
    "index": frozenset({"notice", "keys", "quick", "text_field", "screenshot", "device"}),
    "apps": frozenset({"notice", "app_rows"}),
    "settings": frozenset({"notice", "device_rows", "password_form", "quick_launch"}),
    "login": frozenset({"notice", "hint", "error"}),
    "setup": frozenset({"notice", "candidate_rows"}),
}

#: The pad, drawn as it sits under a thumb: arrows around OK, and the four keys a remote puts
#: in the corners. "" would be a hole in the grid; there are none left.
_PAD_LAYOUT: tuple[tuple[str, ...], ...] = (
    ("back", "dpad_up", "home"),
    ("dpad_left", "dpad_center", "dpad_right"),
    ("menu", "dpad_down", "play_pause"),
)

#: Which of those are the pad proper. The rest are corners and are drawn quieter.
_PAD_CORE = frozenset({"dpad_up", "dpad_down", "dpad_left", "dpad_right", "dpad_center"})

#: The row under the pad. Everything else is one tap away in a group.
_ESSENTIAL_KEYS: tuple[str, ...] = (
    "volume_down",
    "volume_up",
    "volume_mute",
    "search",
)

#: Section titles for the keys that are not on the pad or in the essential row, in the order
#: the sections are drawn. A key whose group is missing here lands in "More".
_GROUP_TITLES: tuple[tuple[str, str], ...] = (
    ("media", "Media"),
    ("volume", "Volume"),
    ("tv", "TV"),
    ("nav", "Navigation"),
    ("system", "Power"),
)

#: What `/login?e=<code>` may say, and how loudly. The browser names the code; the sentence is
#: chosen here, so a crafted link cannot put words on the sign-in page. `api._LOGIN_NOTICE_CODES`
#: is the other half of this contract.
LOGIN_NOTICES: dict[str, tuple[str, str]] = {
    "bad_credentials": ("error", "That sign-in did not work. Check the password and try again."),
    "locked": ("error", "Too many attempts. Wait a moment, then try again."),
    "weak_password": ("error", "That password is too short - use at least 10 characters."),
    "bad_request": ("error", "That sign-in could not be read. Try again."),
    "not_initialized": ("error", "There is no account yet. Create the password below."),
    "signed_out": ("info", "Signed out."),
}


def login_notice(code: object) -> str:
    """Validate a `?e=` code against the notice table. Anything unknown becomes ''."""
    candidate = code.strip().lower() if isinstance(code, str) else ""
    return candidate if candidate in LOGIN_NOTICES else ""

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

    def index(
        self,
        reg: registry.Registry,
        csrf: str,
        tiles: list[dict[str, object]] | None = None,
    ) -> tuple[int, str]:
        """The remote: quick launch, a d-pad, the essential keys, then everything else.

        The order is the order a thumb needs it in, and the same markup serves a phone and a
        desktop - the layout is CSS, so there is one page to keep correct, not two.
        """
        return self._page("Dashboard", "index", {
            "quick": self._quick_launch(tiles, csrf),
            "keys": self._keys(csrf),
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

    def settings(
        self,
        reg: registry.Registry,
        csrf: str,
        catalog: list[dict[str, object]] | None = None,
        installed: object = None,
    ) -> tuple[int, str]:
        """Settings: the device list, the quick-launch checkboxes, and the password."""
        rows = [self._device_row(device, csrf) for device in reg.list_public()[:MAX_ROWS]]
        body = self._fill("settings", {
            "device_rows": "\n".join(item for item in rows if item)
            or '<p class=muted>No device is paired yet. Use <a href="/setup">Set up TV</a>.</p>',
            "quick_launch": self._quick_launch_choices(catalog, csrf, installed),
            "password_form": self._password_form(csrf),
        }, csrf)
        return 200, self._wrap("Settings", body, csrf)

    def login(
        self, csrf: str = "", *, first_run: bool = False, notice: str = ""
    ) -> tuple[int, str]:
        """Sign in, or the first-run password form.

        A failed attempt comes back here with a code, so a wrong password ends on a form that
        is ready for the next try rather than on a page of JSON.
        """
        body = self._fill("login", {
            "hint": _login_hint(first_run),
            "error": _login_banner(notice),
        }, csrf)
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

    def _keys(self, csrf: str = "") -> str:
        """The whole remote, in three tiers: the pad, the essentials, then the rest.

        Every button is the same thing it always was - a submit that names one alias - so the
        page still works with the script blocked, and the server still decides what an alias
        means. Only the arrangement is new.
        """
        from .keys import KEY_ALIASES

        specs = tuple(KEY_ALIASES.values())[:MAX_TILES]
        by_alias: dict[str, object] = {}
        for spec in specs:
            alias = getattr(spec, "alias", "")
            if isinstance(alias, str) and _ALIAS_RE.match(alias):
                by_alias[alias] = spec
        placed: set[str] = set()

        parts = [
            _csrf_input(csrf),
            self._pad(by_alias, placed),
            self._essentials(by_alias, placed),
            self._key_groups(by_alias, placed),
        ]
        return "".join(part for part in parts if part)

    def _pad(self, by_alias: dict[str, object], placed: set[str]) -> str:
        """The pad: four arrows around OK, with Back, Home, Menu and Play in the corners.

        Nine keys in one thumb-sized block is the whole remote most of the time, which is why
        it is the first thing on the page and the only thing that never collapses.
        """
        cells: list[str] = []
        for row in _PAD_LAYOUT:
            for alias in row:
                spec = by_alias.get(alias)
                if alias and spec is not None:
                    placed.add(alias)
                    cells.append(
                        _key_button(spec, extra="pad-key" if alias in _PAD_CORE else "pad-corner")
                    )
                else:
                    cells.append('<span class="pad-gap" aria-hidden="true"></span>')
        return '<div class="pad" role="group" aria-label="Direction pad">' + "".join(cells) + "</div>"

    def _essentials(self, by_alias: dict[str, object], placed: set[str]) -> str:
        """Back, Home and the handful of keys nobody wants to go looking for."""
        out: list[str] = []
        for alias in _ESSENTIAL_KEYS:
            spec = by_alias.get(alias)
            if spec is None:
                continue
            placed.add(alias)
            out.append(_key_button(spec, extra="essential-key"))
        if not out:
            return ""
        return '<div class="essentials" role="group" aria-label="Essential keys">' + "".join(out) + "</div>"

    def _key_groups(self, by_alias: dict[str, object], placed: set[str]) -> str:
        """Everything the pad and the essential row did not take, in one flat grid.

        No headings and no disclosure triangles: five labelled sections for twenty buttons is
        more chrome than content, and a remote is easier to scan when it is one field of keys.
        The `_GROUP_TITLES` order still decides the sequence, so related keys sit together
        without needing a title to say so.
        """
        buckets: dict[str, list[str]] = {}
        for alias, spec in by_alias.items():
            if alias in placed:
                continue
            group = getattr(spec, "group", "") or "other"
            buckets.setdefault(group if isinstance(group, str) else "other", []).append(
                _key_button(spec)
            )

        ordered: list[str] = []
        for group, _title in _GROUP_TITLES:
            ordered.extend(buckets.pop(group, []))
        for remaining in buckets.values():
            ordered.extend(remaining)
        if not ordered:
            return ""
        return '<div class="keys rest" role="group" aria-label="More keys">' + "".join(ordered) + "</div>"

    def _quick_launch(self, tiles: list[dict[str, object]] | None, csrf: str = "") -> str:
        """Quick-launch tiles. The browser names a platform alias, never a package."""
        rows: list[str] = []
        for tile in (tiles or [])[:MAX_TILES]:
            alias = tile.get("alias", "") if isinstance(tile, dict) else ""
            label = tile.get("label", "") if isinstance(tile, dict) else ""
            if not isinstance(alias, str) or not _ALIAS_RE.match(alias):
                continue
            rows.append(
                '<button class="tile app' + (" art" if _logo_of(tile) else "") + '"'
                ' type=submit form=quick-form name="platform"'
                ' value="' + render_attr(alias) + '">'
                + _logo_img(tile, label)
                + "</button>"
            )
        if not rows:
            return (
                '<p class=muted>No quick-launch app is switched on. '
                'Pick some in <a href="/settings">Settings</a>.</p>'
            )
        return (
            '<form id="quick-form" method=post action="/api/quick_launch">'
            + _csrf_input(csrf)
            + '<div class="keys apps-grid">'
            + "".join(rows)
            + "</div></form>"
        )

    def _quick_launch_choices(
        self, catalog: list[dict[str, object]] | None, csrf: str, installed: object = None
    ) -> str:
        """One checkbox per catalogued app: on shows a tile, off hides it.

        Each row is its own tiny form, so the page works without the script and so one POST
        carries one decision - there is no list of names to parse on the way in.
        """
        seen = installed if isinstance(installed, (set, frozenset)) else frozenset()
        rows: list[str] = []
        for item in (catalog or [])[:MAX_TILES]:
            if not isinstance(item, dict):
                continue
            alias = item.get("alias", "")
            label = item.get("label", "")
            package = item.get("package", "")
            if not isinstance(alias, str) or not _ALIAS_RE.match(alias):
                continue
            on = bool(item.get("on"))
            detected = isinstance(package, str) and package in seen
            rows.append(
                '<form method=post action="/api/prefs/quick_launch" class="choice'
                + (" on" if on else "")
                + '" data-alias="' + render_attr(alias) + '">'
                + '<input type=hidden name=alias value="' + render_attr(alias) + '">'
                + '<input type=hidden name=on value="' + ("0" if on else "1") + '">'
                + _csrf_input(csrf)
                + '<button type=submit class="check" role="switch" aria-checked="'
                + ("true" if on else "false")
                + '"><span class="box" aria-hidden="true">'
                + ("&#10003;" if on else "")
                + "</span>"
                + _logo_thumb(item)
                + "<span class=name>"
                + render_text(label)
                + "</span>"
                + ('<span class="pill">on this TV</span>' if detected else "")
                + "</button></form>"
            )
        if not rows:
            return "<p class=muted>The quick-launch catalogue is empty.</p>"
        return '<div class="choices">' + "".join(rows) + "</div>"

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
    return '<p class="banner warn">Plain HTTP on a trusted LAN. No TLS, no cloud, no telemetry.</p>'


def _login_hint(first_run: bool) -> str:
    if first_run:
        return "Create the dashboard password. The TV does not ask for one."
    return "Sign in with the dashboard password, not the TV password."


def _login_banner(code: object) -> str:
    """Render one notice on the sign-in page, from the table and never from the browser."""
    notice = login_notice(code)
    if not notice:
        return ""
    tone, message = LOGIN_NOTICES[notice]
    return (
        '<p class="banner '
        + render_attr(tone)
        + '" role="status">'
        + render_text(message)
        + "</p>"
    )


def _logo_of(tile: object) -> str:
    """The logo URL on a tile projection, if it is one of ours.

    `platforms` builds these from the catalogue, but the check is cheap and this is the last
    place before the value reaches an attribute, so it is made here too.
    """
    if not isinstance(tile, dict):
        return ""
    logo = tile.get("logo", "")
    if not isinstance(logo, str) or not _LOGO_URL_RE.match(logo):
        return ""
    return logo


def _logo_img(tile: object, label: str) -> str:
    """A quick-launch tile's face: the artwork, or the service's name.

    The logo carries the name as its `alt`, so the button reads the same to a screen reader
    either way, and a logo that fails to load still leaves a usable button.
    """
    logo = _logo_of(tile)
    if not logo:
        return '<span class="name">' + render_text(label) + "</span>"
    return (
        '<img class="logo" src="' + render_attr(logo) + '"'
        ' alt="' + render_attr(label) + '" loading="lazy" decoding="async">'
    )


def _logo_thumb(item: object) -> str:
    """A small logo for a Settings row. Decorative: the row already says the name."""
    logo = _logo_of(item)
    if not logo:
        return '<span class="thumb none" aria-hidden="true"></span>'
    return (
        '<img class="thumb" src="' + render_attr(logo) + '" alt="" aria-hidden="true"'
        ' loading="lazy" decoding="async">'
    )


def _key_button(spec: object, extra: str = "") -> str:
    """One key tile. The alias is the only thing that travels; the keycode stays here."""
    alias = getattr(spec, "alias", "")
    if not isinstance(alias, str) or not _ALIAS_RE.match(alias):
        return ""
    # The group is prefixed because a bare group name ("nav", "media", "system") is exactly the
    # sort of word a page-level class already uses, and a key tile must not inherit page layout.
    group = getattr(spec, "group", "")
    classes = "tile" + (" g-" + render_attr(group) if isinstance(group, str) and group else "")
    if extra:
        classes += " " + render_attr(extra)
    confirm = getattr(spec, "confirm", "")
    return (
        '<button class="' + classes + '"'
        ' type=submit form=key-form name="key"'
        ' value="' + render_attr(alias) + '"'
        + (' data-confirm="' + render_attr(confirm) + '"' if confirm else "")
        + ">"
        + render_text(getattr(spec, "label", ""))
        + "</button>"
    )


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
