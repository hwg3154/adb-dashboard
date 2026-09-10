"""The only adb caller in the process.

Every command is built here from a fixed template plus a validated value, passed as an argv list
with `shell=False`. Nothing coming from the browser is interpolated into a command string: the
browser names a key or a package, this module decides what adb actually runs.

Command and flag reference: docs/adb-command-reference.md
Key/text semantics:         docs/remote-key-press.md
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from enum import IntEnum

from . import keys, netguard, textentry
from .config import DEFAULT_ALLOWED_CIDRS, DEVICE_PORTS, MAX_TEXT_CHARS
from .config import Config

#: Package names are dotted identifiers, nothing else. No paths, no URLs, no shell words.
_PACKAGE_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
#: Java class name for an activity, without a leading dot.
_CLASS_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_$]*(?:\.[A-Za-z][A-Za-z0-9_$]*)*$")

_PACKAGE_FLAGS = ("-3",)
_PACKAGE_LIST_LIMIT = 80
_ACTIVITY_LIMIT = 80
_LAUNCH_CATEGORY = "android.intent.action.MAIN"
_LAUNCH_CATEGORIES = (
    "android.intent.category.LEANBACK_LAUNCHER",
    "android.intent.category.LAUNCHER",
)
_PROP_KEY = "ro.product."
_SCREENCAP_ARGS = ("screencap", "-p")

_OUTPUT_MARKERS = {
    "error",
    "failed",
    "failure",
    "exception",
    "no activity found",
    "does not exist",
    "inaccessible",
    "unknown",
    "adb: no",
    "command not found",
    "permission denied",
    "cannot find",
    "unable to",
}


class AdbStatus(IntEnum):
    OK = 0
    FAILED = 1
    REJECTED = 2
    TIMEOUT = 3
    MISSING = 4


@dataclass(frozen=True)
class AdbResult:
    """Outcome of one adb call. stdout is the only payload we hand to the browser."""

    status: AdbStatus
    returncode: int
    stdout: str
    stderr: str
    elapsed_ms: int
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.status is AdbStatus.OK

    def lines(self) -> list[str]:
        return [line.strip() for line in self.stdout.splitlines() if line.strip()]

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "code": self.status.name.lower(),
            "returncode": self.returncode,
            "elapsed_ms": self.elapsed_ms,
            "truncated": self.truncated,
        }


class AdbError(RuntimeError):
    """Raised when adb itself is unusable (missing binary, OS-level failure)."""


def _is_safe_arg(value: object) -> bool:
    """Belt-and-braces check on every argument handed to adb."""
    if not isinstance(value, str) or not value or len(value) > 512:
        return False
    if any(char in value for char in " \t\r\n\x00"):
        # Only the quoted text payload may contain spaces, and it must be quoted exactly once.
        if not (value.startswith("'") and value.endswith("'") and value.count("'") == 2):
            return False
    forbidden = "\"`$;&|<>(){}[]*?!\\~#^="
    return not any(char in value for char in forbidden)


class AdbClient:
    """Thin, auditable wrapper around the `adb` binary."""

    def __init__(
        self,
        adb_bin: str = "adb",
        *,
        timeout_seconds: float = 8.0,
        max_output_bytes: int = 4 * 1024 * 1024,
        allowed_cidrs: tuple[str, ...] = DEFAULT_ALLOWED_CIDRS,
        device_ports: tuple[int, ...] = DEVICE_PORTS,
        max_text_chars: int = MAX_TEXT_CHARS,
    ) -> None:
        self._argv0 = adb_bin or "adb"
        self._timeout = max(0.5, float(timeout_seconds))
        self._max_output = max(1024, int(max_output_bytes))
        self._allowed_cidrs = tuple(allowed_cidrs or DEFAULT_ALLOWED_CIDRS)
        self._device_ports = tuple(sorted(int(port) for port in (device_ports or DEVICE_PORTS)))
        self._max_text = max(1, int(max_text_chars))

    @classmethod
    def from_config(cls, config: Config) -> "AdbClient":
        return cls(
            config.adb_bin,
            timeout_seconds=config.adb_timeout_seconds,
            max_output_bytes=config.max_adb_output_bytes,
            allowed_cidrs=config.allowed_cidrs,
            device_ports=config.device_ports,
            max_text_chars=config.max_text_chars,
        )

    def available(self) -> bool:
        return shutil.which(self._argv0) is not None

    def run(self, argv: list[str]) -> AdbResult:
        """Execute a pre-built argv list. This is the single entry point."""
        if not isinstance(argv, list) or not argv or not all(_is_safe_arg(a) for a in argv):
            return AdbResult(AdbStatus.REJECTED, -1, "", "rejected argv", 0)

        started = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 - argv is built from constants and validated values
                [self._argv0, *argv],
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self._timeout,
                close_fds=True,
            )
        except subprocess.TimeoutExpired:
            return AdbResult(AdbStatus.TIMEOUT, -1, "", "adb timed out", _elapsed(started))
        except FileNotFoundError as exc:
            raise AdbError("adb binary not found") from exc
        except OSError as exc:
            raise AdbError("cannot run adb") from exc

        raw = proc.stdout or b""
        truncated = len(raw) > self._max_output
        payload = raw[: self._max_output]
        result = AdbResult(
            status=AdbStatus.OK if proc.returncode == 0 else AdbStatus.FAILED,
            returncode=proc.returncode,
            stdout=payload.decode("utf-8", "replace"),
            stderr=(proc.stderr or b"")[: self._max_output // 4].decode("utf-8", "replace"),
            elapsed_ms=_elapsed(started),
            truncated=truncated,
        )
        if result.ok and _looks_failed(result):
            return AdbResult(AdbStatus.FAILED, proc.returncode, "", "adb reported a failure", result.elapsed_ms)
        return result

    # -------------------------------------------------------------------------- lifecycle

    def pair(self, host: str, port: int, code: str) -> AdbResult:
        return self.run(["pair", f"{host}:{port}", _validate_code(code)])

    def connect(self, target: str) -> AdbResult:
        return self.run(["connect", target])

    def disconnect(self, target: str) -> AdbResult:
        return self.run(["disconnect", target])

    def validate_target(self, target: str) -> str:
        """Re-check a stored target before it is used. Never trusts the registry to stay clean."""
        from .netguard import TargetRejected, normalize_target

        try:
            return normalize_target(target, self._allowed_cidrs, self._device_ports)
        except (TargetRejected, ValueError) as exc:
            raise ValueError("target is not usable") from exc

    def list_targets(self) -> AdbResult:
        return self.run(["devices"])

    def discover(self) -> AdbResult:
        return self.run(["discover"])

    # ------------------------------------------------------------------------------ input

    def send_key(self, target: str, alias: str) -> AdbResult:
        target = self.validate_target(target)
        spec = keys.resolve_key(alias)
        return self.run(["-s", target, "shell", "input", "keyevent", spec.keycode])

    def send_text(self, target: str, text: str, *, submit: bool = False) -> AdbResult:
        """Type into the focused field; optionally follow the text with an Enter key."""
        target = self.validate_target(target)
        payload = textentry.encode_text_arg(textentry.sanitize_text(text, self._max_text))
        result = self.run(["-s", target, "shell", "input", "text", payload])
        if not result.ok:
            return result
        if submit:
            self.run(["-s", target, "shell", "input", "keyevent", "KEYCODE_ENTER"])
        return result

    # -------------------------------------------------------------------------------- apps

    def list_apps(self, target: str) -> list[dict[str, str]]:
        """List apps that resolve a `LEANBACK_LAUNCHER` or `LAUNCHER` activity."""
        apps: list[dict[str, str]] = []
        seen: set[str] = set()

        for category in _LAUNCH_CATEGORIES:
            listed = self.run(["-s", target, "shell", "pm", "list", "packages", *_PACKAGE_FLAGS])
            if not listed.ok:
                continue
            result = self.run(
                [
                    "-s",
                    target,
                    "shell",
                    "cmd",
                    "package",
                    "query-activities",
                    "-a",
                    _LAUNCH_ACTION,
                    "-c",
                    category,
                ]
            )
            if not result.ok:
                continue
            for line in result.lines():
                parsed = _parse_activity_line(line)
                if parsed is None:
                    continue
                package, activity = parsed
                if package in seen:
                    continue
                seen.add(package)
                apps.append({"package": package, "activity": activity, "kind": _category_kind(category)})
                if len(apps) >= _ACTIVITY_LIMIT:
                    return apps
            if apps:
                break

        if apps:
            return apps

        listed = self.run(["-s", target, "shell", "pm", "list", "packages", *_PACKAGE_FLAGS])
        for line in listed.lines():
            package = line.removeprefix("package:").strip()
            if not _PACKAGE_RE.match(package) or package in seen:
                continue
            seen.add(package)
            apps.append({"package": package, "activity": "", "kind": "LAUNCHER"})
            if len(apps) >= _PACKAGE_LIST_LIMIT:
                break
        return apps

    def launch(self, target: str, package: str, activity: str = "") -> AdbResult:
        pkg = _validated_package(package)
        if activity:
            component = f"{pkg}/{_validated_activity(activity)}"
            return self.run(["-s", target, "shell", "am", "start", "-n", component])
        return self.run(["-s", target, "shell", "am", "start", "-a", _LAUNCH_ACTION, "-c", _LAUNCH_CATEGORIES[0]])

    def stop(self, target: str, package: str) -> AdbResult:
        return self.run(["-s", target, "shell", "am", "force-stop", _validated_package(package)])

    def app_info(self, target: str, package: str) -> AdbResult:
        return self.run(
            [
                "-s",
                target,
                "shell",
                "am",
                "start",
                "-a",
                "android.settings.APPLICATION_DISPLAY_SETTINGS",
                "--user",
                "0",
                "-d",
                f"package:{_validated_package(package)}",
            ]
        )

    def clear_data(self, target: str, package: str) -> AdbResult:
        return self.run(["-s", target, "shell", "pm", "clear", _validated_package(package)])

    def uninstall(self, target: str, package: str) -> AdbResult:
        return self.run(["-s", target, "shell", "pm", "uninstall", _validated_package(package)])

    # -------------------------------------------------------------------------- diagnostics

    def screenshot(self, target: str) -> tuple[bytes, AdbResult]:
        """Grab one PNG. Binary-safe: `exec-out`, never `shell`."""
        result = self.run(["-s", target, "exec-out", *_SCREENCAP_ARGS])
        if not result.ok:
            return b"", result
        return _png_payload(result.stdout), result


def _validate_code(code: object) -> str:
    from .netguard import validate_pair_code

    return validate_pair_code(code)


def _validated_package(package: object) -> str:
    if not isinstance(package, str):
        raise ValueError("package must be a string")
    candidate = package.strip().lower()
    if not _PACKAGE_RE.match(candidate):
        raise ValueError("package name is not valid")
    return candidate


def _validated_activity(activity: object) -> str:
    if not isinstance(activity, str):
        raise ValueError("activity must be a string")
    candidate = activity.strip().lstrip(".")
    if not candidate or len(candidate) > 256 or not _CLASS_RE.fullmatch(candidate):
        raise ValueError("activity name is not valid")
    return candidate


def _parse_activity_line(line: str) -> tuple[str, str] | None:
    """Extract `package` + class name from one `query-activities` line."""
    token = line.strip()
    if "=" in token:
        token = token.partition("=")[2].strip()
    if "/" not in token:
        return None
    package, _, activity = token.partition("/")
    if not _PACKAGE_RE.match(package):
        return None
    activity = activity.lstrip(".")
    if not _CLASS_RE.fullmatch(activity):
        return None
    return package, activity


def _category_kind(category: str) -> str:
    return "TV" if category.endswith("LEANBACK_LAUNCHER") else "PHONE"


def _png_payload(payload: str) -> bytes:
    data = payload.encode("utf-8", "surrogateescape")
    marker = b"\x89PNG\r\n\x1a\n"
    offset = data.find(marker)
    if offset > 0:
        data = data[offset:]
    return data


def _elapsed(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
