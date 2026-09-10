"""Atomic JSON storage helpers.

One document per file, written with temp-file + `os.replace` so a crash mid-write cannot leave a
half-written registry or account file behind.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

_DIR_MODE = 0o700
_FILE_MODE = 0o600
_MAX_DOCUMENT_BYTES = 1024 * 1024


class StorageError(RuntimeError):
    """Raised when the data directory cannot be used at all."""


def ensure_data_dir(path: str) -> str:
    """Create (or accept) the data directory with tight permissions."""
    if not isinstance(path, str) or not path:
        raise StorageError("data dir is not configured")
    root = Path(path)
    if not root.is_absolute():
        root = Path.cwd() / root
    try:
        root.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        os.chmod(root, _DIR_MODE)
    except OSError as exc:
        raise StorageError("data dir is not usable") from exc
    return str(root)


def read_json(path: Path) -> dict[str, Any]:
    """Read a JSON object. A missing or broken file is an empty document, never a crash."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {}
    except OSError:
        return {}
    if len(raw) > _MAX_DOCUMENT_BYTES:
        return {}
    try:
        parsed = json.loads(raw.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Write `payload` through a temp file, then `os.replace`. Never in place."""
    directory = path.parent
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    except OSError as exc:
        raise StorageError("data dir is not writable") from exc

    try:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise StorageError("cannot serialize state") from exc

    fd, tmp_name = tempfile.mkstemp(prefix=".tvd-", suffix=".tmp", dir=str(directory))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, _FILE_MODE)
        os.replace(tmp, path)
        os.chmod(path, _FILE_MODE)
        os.chmod(directory, _DIR_MODE)
    except OSError as exc:
        _remove(tmp)
        raise StorageError("cannot write state") from exc
    except BaseException:
        _remove(tmp)
        raise


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass
