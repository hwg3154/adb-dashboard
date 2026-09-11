"""Operator preferences: the small set of choices that outlive a browser tab.

Today that is one thing - which quick-launch tiles are shown. It lives on the server rather
than in the browser so the phone and the laptop agree about what the remote looks like, and
because there is exactly one operator to have an opinion.

The file holds aliases from `platforms.CATALOG` and nothing else: an alias that is not in the
catalogue is dropped on the way in and on the way out, so a hand-edited file cannot introduce
a package name.
"""

from __future__ import annotations

import threading
from pathlib import Path

from . import platforms, storage
from .config import Config

PREFS_FILE = "prefs.json"
PREFS_VERSION = 1

#: A ceiling on the stored list. The catalogue is smaller than this; the cap is for the file.
MAX_ENABLED = 32


class Prefs:
    """Preferences, read once at start-up and written through on every change."""

    def __init__(self, config: Config, enabled: tuple[str, ...] | None = None) -> None:
        self.config = config
        self._lock = threading.RLock()
        self._enabled: tuple[str, ...] = (
            platforms.DEFAULT_ALIASES if enabled is None else _clean(enabled)
        )

    @classmethod
    def load(cls, config: Config) -> "Prefs":
        """Read the preferences file. A missing or broken file means 'the defaults'."""
        payload = storage.read_json(Path(config.data_dir) / PREFS_FILE)
        raw = payload.get("quick_launch")
        if not isinstance(raw, list):
            return cls(config, None)
        return cls(config, _clean(raw))

    # ------------------------------------------------------------------- quick launch

    @property
    def quick_launch(self) -> tuple[str, ...]:
        """Enabled aliases, in catalogue order so the tiles never reshuffle themselves."""
        with self._lock:
            enabled = frozenset(self._enabled)
        return tuple(alias for alias in platforms.CATALOG if alias in enabled)

    def is_on(self, alias: object) -> bool:
        return platforms.clean_alias(alias) in self.quick_launch

    def set_quick_launch(self, aliases: object) -> tuple[str, ...]:
        """Replace the whole selection. Unknown aliases are dropped, not an error."""
        cleaned = _clean(aliases)
        with self._lock:
            self._enabled = cleaned
        self._save()
        return self.quick_launch

    def toggle_quick_launch(self, alias: object, on: bool) -> tuple[str, ...]:
        """Switch one platform on or off. An unknown alias changes nothing."""
        candidate = platforms.clean_alias(alias)
        if not candidate:
            raise platforms.UnknownPlatform("unknown platform")
        with self._lock:
            current = [item for item in self._enabled if item != candidate]
            if on:
                current.append(candidate)
            self._enabled = _clean(current)
        self._save()
        return self.quick_launch

    def tiles(self) -> list[dict[str, object]]:
        """What the dashboard draws: label plus alias, only for what is switched on."""
        return [
            {
                "alias": platform.alias,
                "label": platform.label,
                "logo": platforms.logo_url(platform.alias),
            }
            for platform in platforms.enabled_platforms(self.quick_launch)
        ]

    def catalog(self) -> list[dict[str, object]]:
        """The whole catalogue with its on/off state, for the Settings checkboxes."""
        return platforms.listing(self.quick_launch)

    # ------------------------------------------------------------------------ storage

    def _save(self) -> None:
        with self._lock:
            payload = {"version": PREFS_VERSION, "quick_launch": list(self._enabled)}
        try:
            storage.write_json_atomic(Path(self.config.data_dir) / PREFS_FILE, payload)
        except storage.StorageError:
            # A read-only data directory must not take the dashboard down: the choice simply
            # does not survive a restart, and every other page keeps working.
            pass


def _clean(aliases: object) -> tuple[str, ...]:
    """Validated, de-duplicated aliases in catalogue order, capped."""
    if isinstance(aliases, str):
        aliases = aliases.split(",")
    if not isinstance(aliases, (list, tuple, set, frozenset)):
        return ()
    chosen = {alias for alias in (platforms.clean_alias(item) for item in aliases) if alias}
    ordered = tuple(alias for alias in platforms.CATALOG if alias in chosen)
    return ordered[:MAX_ENABLED]


__all__ = ["MAX_ENABLED", "PREFS_FILE", "Prefs"]
