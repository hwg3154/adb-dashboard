"""Device registry: the small set of TVs this appliance is allowed to touch.

The browser addresses devices by an opaque id. Hosts, ports, models and nicknames live here and
are only ever sent to the browser as display text, never accepted back as an instruction.

Candidate devices found by discovery are held in a short-lived TTL cache: the browser receives a
`candidate_id`, and only this module can turn it into a target.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, replace
from pathlib import Path

from . import storage
from .config import Config
from .netguard import normalize_target

REGISTRY_FILE = "devices.json"
DOC_VERSION = 1

MAX_DEVICES = 8
MAX_NICKNAME_CHARS = 32
MAX_MODEL_CHARS = 48
_MAX_TEXT_CHARS = 64
_MAX_LIST_ITEMS = 16

#: Candidate ids are opaque handles into the candidate cache, never an address.
_ID_CHARS = "0123456789abcdef"


class RegistryError(RuntimeError):
    """Raised when the registry cannot be used at all."""


@dataclass(frozen=True)
class Device:
    """One known TV. `target` is a canonical `host:port` and never leaves the server as input."""

    id: str
    target: str
    nickname: str
    model: str
    added_at: int
    last_used: int

    @property
    def label(self) -> str:
        """What the UI shows. The nickname wins; otherwise the model, never the raw host."""
        if self.nickname:
            return self.nickname
        if self.model:
            return self.model
        return "Android TV"

    def public(self) -> dict[str, str]:
        """The browser-facing projection. Deliberately no target and no timestamps."""
        return {"id": self.id, "label": self.label, "nickname": self.nickname, "model": self.model}

    def as_row(self) -> dict[str, str]:
        """Row for a settings table: a label and a stable id, nothing more."""
        return {"id": self.id, "label": render_device_label(self), "target": ""}

    def as_record(self) -> dict[str, object]:
        return {
            "id": self.id,
            "target": self.target,
            "nickname": self.nickname,
            "model": self.model,
            "added_at": self.added_at,
            "last_used": self.last_used,
        }


@dataclass(frozen=True)
class Candidate:
    """A device that answered discovery and answered for the right properties."""

    id: str
    host: str
    port: int
    score: int
    added_at: int
    model: str = ""

    def public(self) -> dict[str, object]:
        return {"id": self.id, "host": self.host, "port": self.port, "model": self.model, "score": self.score}

    def as_record(self) -> dict[str, object]:
        return {
            "id": self.id,
            "host": self.host,
            "port": self.port,
            "score": self.score,
            "model": self.model,
            "added_at": self.added_at,
        }


class Registry:
    """Devices and pending candidates, with a TTL cache and atomic persistence."""

    def __init__(
        self,
        config: Config,
        *,
        devices: dict[str, Device],
        candidates: dict[str, Candidate],
    ) -> None:
        self.config = config
        self._devices = devices
        self._candidates = candidates

    @classmethod
    def load(cls, config: Config) -> "Registry":
        """Read state from disk. A missing or half-written file is 'no devices', never a crash."""
        payload = storage.read_json(Path(config.data_dir) / REGISTRY_FILE)
        devices: dict[str, Device] = {}
        raw_devices = payload.get("devices", {})
        if isinstance(raw_devices, dict):
            for device_id, record in raw_devices.items():
                device = _device_from_storage(device_id, record, config)
                if device is not None:
                    devices[device.id] = device

        candidates: dict[str, Candidate] = {}
        raw_candidates = payload.get("candidates", {})
        if isinstance(raw_candidates, dict):
            now = time.time()
            for candidate_id, record in raw_candidates.items():
                candidate = _candidate_from_storage(candidate_id, record, now, config.candidate_ttl_seconds)
                if candidate is not None:
                    candidates[candidate.id] = candidate

        return cls(config, devices=devices, candidates=candidates)

    # -------------------------------------------------------------------------------- devices

    def list(self) -> list[Device]:
        return [device for device in self._devices.values() if isinstance(device, Device)]

    def list_public(self) -> list[dict[str, str]]:
        """Stable-order browser payload: label first, then the oldest device."""
        devices = sorted(self.list(), key=lambda item: (item.added_at, item.id))
        return [device.public() for device in devices]

    def get(self, device_id: object) -> Device | None:
        if not isinstance(device_id, str):
            return None
        return self._devices.get(device_id.strip())

    def target_for(self, device_id: object) -> str:
        """Resolve a device id to a canonical target. This is the only path to a target."""
        device = self.get(device_id)
        return device.target if device is not None else ""

    def active_target(self) -> str:
        """The one device the remote controls. The first join wins until it is forgotten."""
        for device in sorted(self.list(), key=lambda item: (item.last_used, item.added_at), reverse=True):
            if device.target:
                return device.target
        return ""

    def use(self, device_id: object) -> bool:
        """Mark a device as the active one. v1 drives exactly one TV."""
        device = self.get(device_id)
        if device is None:
            return False
        touched = replace(device, last_used=int(time.time()))
        self._devices[touched.id] = touched
        self._save()
        return True

    def set_nickname(self, device_id: object, nickname: object) -> bool:
        """Rename a device. Anything odd becomes an empty nickname, not an error."""
        device = self.get(device_id)
        if device is None:
            return False
        cleaned = _clean_nickname(nickname)
        self._devices[device.id] = replace(device, nickname=cleaned)
        self._save()
        return True

    def remove(self, device_id: object) -> bool:
        """Forget a device. The only way a device leaves the registry."""
        if not _valid_id(device_id):
            return False
        if self._devices.pop(device_id.strip(), None) is None:
            return False
        self._save()
        return True

    def add(self, target: str, *, nickname: str = "", model: str = "") -> Device:
        """Adjoin a verified target. Existing devices are reused, never duplicated."""
        existing = self.get_by_target(target)
        if existing is not None:
            return existing
        if len(self._devices) >= MAX_DEVICES:
            raise RegistryError("device limit reached")

        device = Device(
            id=new_device_id(),
            target=target,
            nickname=_clean_nickname(nickname),
            model=_clean_text(model, MAX_MODEL_CHARS),
            added_at=int(time.time()),
            last_used=int(time.time()),
        )
        self._devices[device.id] = device
        self._save()
        return device

    def get_by_target(self, target: object) -> Device | None:
        for device in self._devices.values():
            if isinstance(device, Device) and device.target == target:
                return device
        return None

    def touch(self, device_id: object) -> None:
        """Record that a device was just used, so the next call can find it."""
        device = self.get(device_id)
        if device is None:
            return
        self._devices[device.id] = replace(device, last_used=int(time.time()))
        self._save()

    # ---------------------------------------------------------------------------- candidates

    def remember(self, candidates: list[Candidate]) -> int:
        """Store discovery output under opaque ids. Replaces the previous batch."""
        now = time.time()
        now = time.time()
        stored: dict[str, Candidate] = {}
        for candidate in candidates[:_MAX_LIST_ITEMS]:
            if isinstance(candidate, Candidate) and _valid_id(candidate.id):
                stored[candidate.id] = candidate
        self._candidates = {key: value for key, value in stored.items() if now - value.added_at <= self.config.candidate_ttl_seconds}
        return len(self._candidates)

    def candidates(self) -> list[Candidate]:
        """Live candidates only. Expired ones are dropped rather than repaired."""
        now = time.time()
        live: dict[str, Candidate] = {}
        for key, value in self._candidates.items():
            if not isinstance(value, Candidate):
                continue
            if now - value.added_at > self.config.candidate_ttl_seconds:
                continue
            live[key] = value
        self._candidates = live
        return list(live.values())

    def take(self, candidate_id: object) -> Candidate | None:
        """Take one candidate out of the cache. A candidate can be joined once."""
        if not _valid_id(candidate_id):
            return None
        key = candidate_id.strip()
        candidate = self._candidates.pop(key, None)
        if not isinstance(candidate, Candidate):
            return None
        return candidate

    def save(self) -> None:
        self._save()

    # -------------------------------------------------------------------------------- private

    def _save(self) -> None:
        payload = {
            "version": DOC_VERSION,
            "devices": {device.id: device.as_record() for device in self._devices.values()},
            "candidates": {key: value.as_record() for key, value in self._candidates.items()},
        }
        storage.write_json_atomic(Path(self.config.data_dir) / REGISTRY_FILE, payload)


def new_device_id() -> str:
    """A fresh opaque device id: random, hex, and meaningful only as a key."""
    return hashlib.sha256(f"{time.time_ns()}:{id(object())}".encode("utf-8")).hexdigest()[:32]


def candidate_key(host: str, port: int) -> str:
    """Derive a candidate id from a host and port. Ids are server-side keys, never browser input."""
    return hashlib.sha256(f"{host}:{port}".encode("utf-8")).hexdigest()[:32]


def render_device_label(device: Device) -> str:
    """A label built only from validated, plain-text fields."""
    if device.nickname:
        return device.nickname
    if device.model:
        return device.model
    return "Android TV"


def _valid_id(value: object) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value.strip().lower()
    return len(candidate) == 32 and all(char in _ID_CHARS for char in candidate)


def _clean_text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    out: list[str] = []
    for char in value:
        code = ord(char)
        if code < 0x20 or code == 0x7F:
            continue
        out.append(char)
    return "".join(out).strip()[:limit]


def _clean_nickname(value: object) -> str:
    if not isinstance(value, str):
        return ""
    candidate = _clean_text(value, MAX_NICKNAME_CHARS)
    if any(char in candidate for char in "<>\"'\\`$|&;(){}[]"):
        return ""
    return candidate


def _to_int(value: object, default: int = 0) -> int:
    return value if isinstance(value, int) and 0 <= value < 2_000_000_000 else default


def _device_from_storage(device_id: object, record: object, config: Config) -> Device | None:
    """Rebuild a device from disk, re-running the target guard on the way in."""
    if not _valid_id(device_id) or not isinstance(record, dict):
        return None
    raw_target = record.get("target")
    if not isinstance(raw_target, str):
        return None
    try:
        target = normalize_target(raw_target, config.allowed_cidrs, config.device_ports)
    except ValueError:
        return None

    device_id = device_id.strip().lower()
    if not _valid_id(device_id):
        return None
    return Device(
        id=device_id,
        target=target,
        nickname=_clean_nickname(record.get("nickname")),
        model=_clean_text(record.get("model"), MAX_MODEL_CHARS),
        added_at=_to_int(record.get("added_at")),
        last_used=_to_int(record.get("last_used")),
    )


def _candidate_from_storage(candidate_id: object, record: object, now: float, ttl: float) -> Candidate | None:
    """Rebuild a candidate, re-validating host and port and dropping anything stale."""
    if not _valid_id(candidate_id) or not isinstance(record, dict):
        return None
    host = record.get("host")
    port = record.get("port")
    added_at = record.get("added_at")
    if not isinstance(host, str) or not host.strip():
        return None
    if not isinstance(port, int) or port not in config_ports():
        return None
    if not isinstance(added_at, int) or (now - added_at) > ttl or added_at > now + 5:
        return None
    return Candidate(
        id=candidate_id.strip().lower(),
        host=host.strip(),
        port=port,
        score=_to_int(record.get("score"), 0),
        model=_clean_text(record.get("model"), MAX_MODEL_CHARS),
    )


def config_ports() -> tuple[int, ...]:
    from .config import DEVICE_PORTS

    return DEVICE_PORTS
