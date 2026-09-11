"""Quick-launch catalogue for the streaming apps people actually use.

The browser names a short alias (`netflix`); this module decides which package that means.
A package name is never assembled from browser input, and an alias that is not in the
catalogue below simply does not exist.

Each platform carries more than one candidate package because the same service ships under
different names on different devices (a phone build side-loaded onto a TV, a regional
variant, an OEM port). `launch_candidates` returns them most-likely-first, and the launcher
tries the next one only when the device says the previous is not there.

Package names are validated against the same shape `adb.py` insists on: lower-case dotted
identifiers, nothing else. A real package that cannot pass that check (ITV's
`air.ITVMobilePlayer`, for instance) is deliberately absent rather than special-cased.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Aliases are ours, not the browser's, but they still get a shape check on the way in.
ALIAS_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
PACKAGE_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")

#: How many packages one quick-launch press may try before giving up. A miss costs one
#: `am start` that fails immediately, so this stays small.
MAX_LAUNCH_ATTEMPTS = 3


@dataclass(frozen=True)
class Platform:
    """One entry in the quick-launch catalogue."""

    alias: str
    label: str
    #: Candidate packages, most likely first. Android TV builds lead; phone builds follow.
    packages: tuple[str, ...]
    #: On for a fresh install. Everything else is one checkbox away in Settings.
    default_on: bool = False

    @property
    def package(self) -> str:
        return self.packages[0] if self.packages else ""


def _platform(alias: str, label: str, *packages: str, default_on: bool = False) -> Platform:
    return Platform(alias=alias, label=label, packages=tuple(packages), default_on=default_on)


#: The catalogue. Add a line here to add a button; nothing else needs to change.
CATALOG: dict[str, Platform] = {
    platform.alias: platform
    for platform in (
        _platform("netflix", "Netflix", "com.netflix.ninja", "com.netflix.mediaclient", default_on=True),
        _platform("disney", "Disney+", "com.disney.disneyplus", "com.disneyplus.mea", default_on=True),
        _platform(
            "prime_video",
            "Prime Video",
            "com.amazon.amazonvideo.livingroom",
            "com.amazon.avod.thirdpartyclient",
            default_on=True,
        ),
        _platform(
            "youtube",
            "YouTube",
            "com.google.android.youtube.tv",
            "com.google.android.youtube",
            default_on=True,
        ),
        _platform("hbo_max", "HBO Max", "com.wbd.stream", "com.hbo.hbonow", default_on=True),
        _platform("hulu", "Hulu", "com.hulu.livingroomplus", "com.hulu.plus"),
        _platform(
            "apple_tv",
            "Apple TV",
            "com.apple.atve.androidtv.appletv",
            "com.apple.atve.sony.appletv",
        ),
        _platform("paramount", "Paramount+", "com.cbs.ott", "com.cbs.ca"),
        _platform("peacock", "Peacock", "com.peacocktv.peacockandroid"),
        _platform("discovery", "discovery+", "com.discovery.discoveryplus.androidtv"),
        _platform("crunchyroll", "Crunchyroll", "com.crunchyroll.crunchyroid"),
        _platform("twitch", "Twitch", "tv.twitch.android.app"),
        _platform("iplayer", "BBC iPlayer", "bbc.iplayer.android", "com.nvidia.bbciplayer"),
        _platform("itvx", "ITVX", "com.itv.itvplayer"),
        _platform("channel4", "Channel 4", "com.channel4.ondemand"),
        _platform("spotify", "Spotify", "com.spotify.tv.android", "com.spotify.music"),
        _platform("plex", "Plex", "com.plexapp.android"),
        _platform("jellyfin", "Jellyfin", "org.jellyfin.androidtv"),
        _platform("kodi", "Kodi", "org.xbmc.kodi"),
    )
}

#: Aliases that are on before anyone touches Settings.
DEFAULT_ALIASES: tuple[str, ...] = tuple(
    platform.alias for platform in CATALOG.values() if platform.default_on
)


class UnknownPlatform(ValueError):
    """Raised when the browser names a platform that is not in the catalogue."""


def clean_alias(value: object) -> str:
    """Normalize an alias, or return '' when it is not one we know."""
    if not isinstance(value, str):
        return ""
    candidate = value.strip().lower()
    if not ALIAS_RE.match(candidate) or candidate not in CATALOG:
        return ""
    return candidate


def resolve(alias: object) -> Platform:
    """Map an alias to its catalogue entry. Unknown names raise `UnknownPlatform`."""
    candidate = clean_alias(alias)
    if not candidate:
        raise UnknownPlatform("unknown platform")
    return CATALOG[candidate]


def launch_candidates(platform: Platform, installed: object = None) -> tuple[str, ...]:
    """Packages to try for one platform, best first.

    `installed` is an optional set of package names the device is known to have. When a
    candidate is in it, that candidate is tried first and nothing else needs trying; when
    the set is unknown or says nothing useful, the catalogue order stands.
    """
    candidates = tuple(pkg for pkg in platform.packages if PACKAGE_RE.match(pkg))
    if isinstance(installed, (set, frozenset)) and installed:
        present = tuple(pkg for pkg in candidates if pkg in installed)
        if present:
            return present[:1]
    return candidates[:MAX_LAUNCH_ATTEMPTS]


def listing(enabled: object = None) -> list[dict[str, object]]:
    """The whole catalogue, marked with whether each entry is switched on.

    Used by Settings to draw the checkboxes, so it always lists everything - a platform you
    turned off has to stay visible, or you cannot turn it back on.
    """
    chosen = _as_alias_set(enabled)
    return [
        {
            "alias": platform.alias,
            "label": platform.label,
            "package": platform.package,
            "on": platform.alias in chosen,
        }
        for platform in CATALOG.values()
    ]


def enabled_platforms(enabled: object = None) -> list[Platform]:
    """The catalogue entries that are switched on, in catalogue order."""
    chosen = _as_alias_set(enabled)
    return [platform for platform in CATALOG.values() if platform.alias in chosen]


def _as_alias_set(enabled: object) -> frozenset[str]:
    if enabled is None:
        return frozenset(DEFAULT_ALIASES)
    if isinstance(enabled, str):
        enabled = (enabled,)
    if not isinstance(enabled, (list, tuple, set, frozenset)):
        return frozenset()
    return frozenset(alias for alias in (clean_alias(item) for item in enabled) if alias)


__all__ = [
    "CATALOG",
    "DEFAULT_ALIASES",
    "Platform",
    "UnknownPlatform",
    "clean_alias",
    "enabled_platforms",
    "launch_candidates",
    "listing",
    "resolve",
]
