"""Server-side sessions.

Tokens are 256 random bits given to the browser as hex; only the SHA-256 of a token is stored, so a
leaked state file cannot be replayed as a session. Both the idle window and the absolute lifetime are
enforced here, and every authenticated request slides the idle window forward.

The CSRF token is issued with the session and is the only value the browser may echo back on a
state-changing request.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, replace
from pathlib import Path

from . import storage
from .config import Config
from .credentials import clean_ip, issue_token, is_token


@dataclass(frozen=True)
class Session:
    user_id: str
    token_hash: str
    csrf: str
    created_at: int
    last_seen: int
    ip: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "user_id": self.user_id,
            "token_hash": self.token_hash,
            "csrf": self.csrf,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "ip": self.ip,
        }


class SessionStore:
    """Active sessions, keyed by token. The browser never sees a user id or a hash."""

    def __init__(
        self,
        data_dir: str,
        *,
        idle_seconds: int,
        absolute_seconds: int,
        max_sessions: int,
        sessions: dict[str, dict[str, object]] | None = None,
    ) -> None:
        self._path = str(Path(data_dir) / "sessions.json")
        self._idle = max(60, int(idle_seconds))
        self._absolute = max(300, int(absolute_seconds))
        self._max_sessions = max(1, int(max_sessions))
        self._sessions: dict[str, dict[str, object]] = {
            key: dict(value)
            for key, value in (sessions or {}).items()
            if isinstance(key, str) and isinstance(value, dict)
        }

    @classmethod
    def load(cls, config: Config) -> "SessionStore":
        payload = storage.read_json(Path(config.data_dir) / "sessions.json")
        raw = payload.get("sessions", {})
        stored: dict[str, dict[str, object]] = {}
        if isinstance(raw, dict):
            for key, value in raw.items():
                if isinstance(key, str) and is_token(key) and isinstance(value, dict):
                    stored[key] = dict(value)
        return cls(
            config.data_dir,
            idle_seconds=config.session_idle_seconds,
            absolute_seconds=config.session_absolute_seconds,
            max_sessions=config.max_sessions_per_user,
            sessions=stored,
        )

    # ------------------------------------------------------------------------------------ reads

    def is_valid(self, token: object) -> bool:
        return bool(self.authorize(token))

    def authorize(self, token: object) -> str:
        """Validate a token, slide the idle window, and return the token or ''.

        This is the only place that decides whether a request is authenticated. A broken or
        expired record is dropped instead of repaired.
        """
        candidate = token.strip() if isinstance(token, str) else ""
        if not is_token(candidate):
            return ""

        record = self._sessions.get(candidate)
        if not isinstance(record, dict):
            return ""

        user_id = record.get("user_id")
        csrf = record.get("csrf")
        created_at = record.get("created_at")
        last_seen = record.get("last_seen") or created_at
        if not is_token(user_id) or not is_token(csrf):
            return ""
        if not isinstance(created_at, int) or not isinstance(last_seen, int):
            return ""

        now = time.time()
        if (now - created_at) > self._absolute:
            self._sessions.pop(candidate, None)
            return ""
        if (last_seen and (now - last_seen) > self._idle) or last_seen > now:
            self._sessions.pop(candidate, None)
            return ""

        record["last_seen"] = int(now)
        return candidate

    def verify_csrf(self, token: object, csrf: object) -> bool:
        """Compare the request's CSRF token with the session record, in constant time."""
        candidate = token.strip() if isinstance(token, str) else ""
        supplied = csrf.strip() if isinstance(csrf, str) else ""
        if not is_token(candidate) or not is_token(supplied):
            return False
        record = self._sessions.get(candidate)
        if not isinstance(record, dict):
            return False
        expected = record.get("csrf")
        if not isinstance(expected, str):
            return False
        return hmac.compare_digest(supplied, expected)

    def csrf_for(self, token: object) -> str:
        """Return the session's CSRF token, validated. The browser receives it in a page, once."""
        record = self._sessions.get(token.strip() if isinstance(token, str) else "")
        if not isinstance(record, dict):
            return ""
        csrf = record.get("csrf")
        return csrf if is_token(csrf) else ""

    # ----------------------------------------------------------------------------------- writes

    def issue(self, user_id: str, ip: str = "", *, now: int | None = None) -> str:
        """Open a session and hand out its token. Never returns a token that was not stored."""
        if not is_token(user_id):
            raise ValueError("user id is not valid")

        token = issue_token()
        if not is_token(token):
            raise RuntimeError("could not create session")

        moment = int(now if now is not None else time.time())
        self._sessions[token] = {
            "user_id": user_id,
            "token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "csrf": issue_token(),
            "created_at": moment,
            "last_seen": 0,
            "ip": clean_ip(ip),
        }
        self._trim(moment)
        self._save()
        return token

    def logout(self, token: object) -> None:
        """Revoke one session. An unknown token is not an error."""
        candidate = token.strip() if isinstance(token, str) else ""
        if not is_token(candidate):
            return
        if self._sessions.pop(candidate, None) is not None:
            self._save()

    def revoke_all(self) -> None:
        """Drop every session. Used when the password is replaced."""
        self._sessions.clear()
        self._save()

    def save(self) -> None:
        self._save()

    # -------------------------------------------------------------------------------- private

    def _trim(self, now: int) -> None:
        live: dict[str, dict[str, object]] = {}
        for token, record in self._sessions.items():
            if not isinstance(token, str) or not is_token(token) or not isinstance(record, dict):
                continue
            created_at = record.get("created_at")
            last_seen = record.get("last_seen") or created_at
            if not isinstance(created_at, int) or not isinstance(last_seen, int):
                continue
            if (now - created_at) > self._absolute:
                continue
            if last_seen and (now - last_seen) > self._idle:
                continue
            live[token] = record
            if len(live) >= self._max_sessions:
                break
        self._sessions = live

    def _save(self) -> None:
        payload = {"version": 1, "sessions": dict(self._sessions)}
        storage.write_json_atomic(Path(self._path), payload)


def empty_session() -> Session:
    return Session(user_id="", token_hash="", csrf="", created_at=0, last_seen=0, ip="")


def session_from_storage(token: str, raw: object) -> Session | None:
    """Project a stored record into a `Session`, rejecting anything malformed."""
    if not isinstance(raw, dict):
        return None
    user_id = raw.get("user_id")
    csrf = raw.get("csrf")
    stored_hash = raw.get("token_hash")
    created_at = raw.get("created_at")
    last_seen = raw.get("last_seen") or created_at
    ip = raw.get("ip", "")
    if not isinstance(ip, str):
        ip = ""
    if not is_token(token) or not is_token(user_id) or not is_token(csrf):
        return None
    if not isinstance(stored_hash, str) or not is_token(stored_hash):
        return None
    if not isinstance(created_at, int) or not isinstance(last_seen, int) or last_seen > created_at + _CLOCK_SLACK:
        return None
    expected = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(stored_hash, expected):
        return None
    return Session(
        user_id=user_id,
        token_hash=stored_hash,
        csrf=csrf,
        created_at=created_at,
        last_seen=last_seen,
        ip=ip[:45],
    )


_CLOCK_SLACK = 5
