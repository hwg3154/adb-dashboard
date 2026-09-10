"""Forwarded remote-control keys.

The client sends short, opaque aliases. The server never accepts a keycode string from the
browser: the name is looked up in this allowlist and passed as one argv element.

See docs/remote-key-press.md for the semantics of each key.
"""

from __future__ import annotations

from dataclasses import dataclass


class InvalidKey(ValueError):
    """Raised when the browser asks for a key we do not know."""


@dataclass(frozen=True)
class KeySpec:
    alias: str
    keycode: str
    label: str
    group: str
    confirm: str = ""
    repeatable: bool = True

    @property
    def is_destructive(self) -> bool:
        return bool(self.confirm)


def _spec(alias: str, keycode: str, label: str, group: str, *, confirm: str = "", repeatable: bool = True) -> KeySpec:
    return KeySpec(alias=alias, keycode=keycode, label=label, group=group, confirm=confirm, repeatable=repeatable)


#: The only keys this dashboard can send. Add an entry here to add a button.
KEY_ALIASES: dict[str, KeySpec] = {
    spec.alias: spec
    for spec in (
        _spec("dpad_up", "KEYCODE_DPAD_UP", "Up", "nav"),
        _spec("dpad_down", "KEYCODE_DPAD_DOWN", "Down", "nav"),
        _spec("dpad_left", "KEYCODE_DPAD_LEFT", "Left", "nav"),
        _spec("dpad_right", "KEYCODE_DPAD_RIGHT", "Right", "nav"),
        _spec("dpad_center", "KEYCODE_DPAD_CENTER", "OK", "nav"),
        _spec("enter", "KEYCODE_ENTER", "Enter", "nav"),
        _spec("back", "KEYCODE_BACK", "Back", "nav"),
        _spec("home", "KEYCODE_HOME", "Home", "nav"),
        _spec("menu", "KEYCODE_MENU", "Menu", "nav"),
        _spec("search", "KEYCODE_SEARCH", "Search", "nav"),
        _spec("channel_up", "KEYCODE_CHANNEL_UP", "Channel +", "tv"),
        _spec("channel_down", "KEYCODE_CHANNEL_DOWN", "Channel -", "tv"),
        _spec("guide", "KEYCODE_GUIDE", "Guide", "tv"),
        _spec("info", "KEYCODE_INFO", "Info", "tv"),
        _spec("captions", "KEYCODE_CAPTIONS", "Captions", "tv"),
        _spec("content", "KEYCODE_TV_CONTENTS_MENU", "Contents", "tv"),
        _spec("tv", "KEYCODE_TV", "TV", "tv"),
        _spec("aspect_ratio", "KEYCODE_TV_ZOOM_MODE", "Aspect", "tv"),
        _spec("play_pause", "KEYCODE_MEDIA_PLAY_PAUSE", "Play / Pause", "media"),
        _spec("media_play", "KEYCODE_MEDIA_PLAY", "Play", "media"),
        _spec("media_pause", "KEYCODE_MEDIA_PAUSE", "Pause", "media"),
        _spec("media_stop", "KEYCODE_MEDIA_STOP", "Stop", "media"),
        _spec("media_next", "KEYCODE_MEDIA_NEXT", "Next", "media"),
        _spec("media_previous", "KEYCODE_MEDIA_PREVIOUS", "Previous", "media"),
        _spec("seek_backward", "KEYCODE_MEDIA_REWIND", "Rewind", "media"),
        _spec("seek_forward", "KEYCODE_MEDIA_FAST_FORWARD", "Fast forward", "media"),
        _spec("volume_up", "KEYCODE_VOLUME_UP", "Volume +", "volume"),
        _spec("volume_down", "KEYCODE_VOLUME_DOWN", "Volume -", "volume"),
        _spec("volume_mute", "KEYCODE_VOLUME_MUTE", "Mute", "volume"),
        _spec("mic", "KEYCODE_VOICE_ASSIST", "Mic", "media"),
        _spec("power", "KEYCODE_POWER", "Power", "system", confirm="Put the TV to sleep? Audio and video keep running for anyone else in the room."),
        _spec("sleep", "KEYCODE_SLEEP", "Sleep", "system", confirm="Send the TV to sleep? A sleeping TV ignores the remote until it wakes."),
        _spec("wake", "KEYCODE_WAKEUP", "Wake", "system"),
    )
}

#: Browser KeyboardEvent.key -> alias. Lower-cased before lookup.
KEYBOARD_ALIASES: dict[str, str] = {
    "arrowup": "dpad_up",
    "arrowdown": "dpad_down",
    "arrowleft": "dpad_left",
    "arrowright": "dpad_right",
    "enter": "enter",
    " ": "dpad_center",
    "backspace": "back",
    "contextmenu": "menu",
    "mediatrack": "content",
    "channelup": "channel_up",
    "channeldown": "channel_down",
    "volumeup": "volume_up",
    "volumedown": "volume_down",
    "volumemute": "volume_mute",
    "mediaplaypause": "play_pause",
    "mediaplay": "media_play",
    "mediapause": "media_pause",
    "mediastop": "media_stop",
    "f11": "aspect_ratio",
}


def resolve_key(alias: object) -> KeySpec:
    """Map a browser-supplied alias to a keycode. Unknown names raise ``InvalidKey``."""
    if not isinstance(alias, str):
        raise InvalidKey("unknown key")
    normalized = alias.strip().lower()
    if not normalized:
        raise InvalidKey("unknown key")
    spec = KEY_ALIASES.get(normalized)
    if spec is not None:
        return spec
    mapped = KEYBOARD_ALIASES.get(normalized)
    if mapped:
        spec = KEY_ALIASES.get(mapped)
        if spec is not None:
            return spec
    raise InvalidKey("unknown key")


def render_key_tiles() -> list[dict[str, str]]:
    """Tile descriptors for the template: label + alias, grouped."""
    tiles: list[dict[str, str]] = []
    for spec in KEY_ALIASES.values():
        tiles.append({"alias": spec.alias, "label": spec.label, "group": spec.group})
    return tiles
