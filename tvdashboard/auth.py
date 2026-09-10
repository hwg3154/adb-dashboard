"""Account bootstrap, login and logout for the single operator account.

v1 has exactly one account, created by the first-run wizard. There is no registration and no
password recovery: if the password is lost, the operator resets the data directory.

Rules this module enforces:
- the account file is created once, by `/setup`, and afterwards only `/api/login` reads it
- a failed login always returns the same message, and costs the same work, whether or not the
  username exists
- the rate limiter is a budget per IP and per username, with a global cap and a backoff

Passwords are never returned, never echoed into a page, and never logged.
"""

from __future__ import annotations

import secrets
import threading
import time
from pathlib import Path
from dataclasses import dataclass

from . import storage
from .config import Config
from .credentials import (
    DEFAULT_USERNAME,
    LOGIN_ERROR_MESSAGE,
    USERNAME_PATTERN,
    check_password_strength,
    check_username,
    hash_password,
    is_token,
    issue_token,
    verify_password,
)
from .sessions import SessionStore

ACCOUNTS_FILE = "accounts.json"
ACCOUNTS_VERSION = 1
MAX_PASSWORD_CHARS = 128

ERROR_INVALID = "bad_request"
ERROR_BAD_CREDENTIALS = "bad_credentials"
ERROR_WEAK_PASSWORD = "weak_password"
ERROR_LOCKED = "locked"
ERROR_NOT_INITIALIZED = "not_initialized"
ERROR_ALREADY_INITIALIZED = "already_initialized"
ERROR_UNAUTHORIZED = "unauthorized"
ERROR_INTERNAL = "internal"

_ZERO_HASH_CACHE: list[str] = []


def _zero_hash() -> str:
    """A decoy hash verified when the username is unknown, so a miss costs what a hit costs.

    It is generated in whatever scheme this build actually uses: a hard-coded argon2 string
    returns instantly on a build without `argon2-cffi`, which times the answer out loud.
    """
    if not _ZERO_HASH_CACHE:
        _ZERO_HASH_CACHE.append(hash_password(secrets.token_hex(16)))
    return _ZERO_HASH_CACHE[0]

_DEFAULT_MESSAGES = {
    ERROR_INVALID: "bad request",
    ERROR_BAD_CREDENTIALS: LOGIN_ERROR_MESSAGE,
    ERROR_WEAK_PASSWORD: "password does not meet the policy",
    ERROR_LOCKED: "too many attempts",
    ERROR_NOT_INITIALIZED: "no account yet",
    ERROR_ALREADY_INITIALIZED: "already set up",
    ERROR_UNAUTHORIZED: "not signed in",
    ERROR_INTERNAL: "internal error",
}


class AuthError(RuntimeError):
    """A login failure the browser can act on. The message is deliberately generic."""

    def __init__(self, code: str = ERROR_INVALID, message: str = "", retry_after: int = 0) -> None:
        self.code = code if isinstance(code, str) and code.isidentifier() else ERROR_INVALID
        self.message = message or _DEFAULT_MESSAGES.get(self.code, "request failed")
        self.retry_after = max(0, int(retry_after))
        super().__init__(self.code)

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"ok": False, "error": self.code}
        if self.retry_after:
            payload["retry_after"] = self.retry_after
        return payload


@dataclass(frozen=True)
class Account:
    """One operator account. Only `username` and the hash are stored."""

    user_id: str
    username: str
    password_hash: str
    created_at: int

    def as_dict(self) -> dict[str, object]:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "password_hash": self.password_hash,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class LoginBudget:
    """Result of the rate-limit check. `allowed` is the only field the caller needs."""

    allowed: bool
    retry_after: int = 0


class LoginRateLimiter:
    """Fixed-window login budget, per IP and per username, with a global cap.

    Failures are counted, successes are not: a correct password always gets through while the
    budget for guesses is still spent.
    """

    def __init__(
        self,
        *,
        per_ip: int = 5,
        per_user: int = 5,
        global_budget: int = 30,
        backoff_seconds: int = 30,
        window_seconds: int = 300,
    ) -> None:
        self._per_ip = max(1, int(per_ip))
        self._per_user = max(1, int(per_user))
        self._global = max(1, int(global_budget))
        self._backoff = max(1, int(backoff_seconds))
        self._window = max(10, int(window_seconds))
        self._ip: dict[str, list[float]] = {}
        self._user: dict[str, list[float]] = {}
        self._global_hits: list[float] = []
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls, config: Config) -> "LoginRateLimiter":
        return cls(
            per_ip=config.login_budget_per_ip,
            per_user=config.login_budget_per_user,
            global_budget=config.login_budget_global,
            backoff_seconds=config.login_backoff_seconds,
            window_seconds=config.login_window_seconds,
        )

    def check(self, ip: str, username: str) -> LoginBudget:
        """Return whether a login attempt may proceed. Never reveals which budget is spent."""
        with self._lock:
            now = time.time()
            self._prune(now)
            if len(self._global_hits) >= self._global:
                return LoginBudget(False, self._retry_after(self._global_hits, now))
            if len(self._ip.get(ip, ())) >= self._per_ip:
                return LoginBudget(False, self._retry_after(self._ip.get(ip, ()), now))
            if len(self._user.get(username, ())) >= self._per_user:
                return LoginBudget(False, self._retry_after(self._user.get(username, ()), now))
            return LoginBudget(True)

    def record_failure(self, ip: str, username: str) -> None:
        """Count a failed attempt against every budget it belongs to."""
        now = time.time()
        with self._lock:
            if ip:
                self._ip.setdefault(ip, []).append(now)
            if username:
                self._user.setdefault(username, []).append(now)
            self._global_hits.append(now)

    def record_success(self, ip: str, username: str) -> None:
        """Clear the budgets a successful login exhausted, so the operator is not locked out."""
        with self._lock:
            if ip:
                self._ip.pop(ip, None)
            if username:
                self._user.pop(username, None)

    def snapshot(self) -> dict[str, int]:
        """Counts for diagnostics. Never a username, never an IP."""
        with self._lock:
            return {
                "ip_attempts": len(self._ip),
                "user_attempts": len(self._user),
                "global_attempts": len(self._global_hits),
            }

    def _prune(self, now: float) -> None:
        self._drop_old(self._global_hits, now, self._window)
        for bucket in self._ip.values():
            self._drop_old(bucket, now, self._window)
        for bucket in self._user.values():
            self._drop_old(bucket, now, self._window)
        self._ip = {key: bucket for key, bucket in self._ip.items() if bucket}
        self._user = {key: bucket for key, bucket in self._user.items() if bucket}

    @staticmethod
    def _drop_old(bucket: list[float], now: float, window: int) -> None:
        """Discard timestamps that fell out of the window, in place."""
        cutoff = now - window
        keep = [stamp for stamp in bucket if isinstance(stamp, float) and stamp > cutoff]
        bucket[:] = keep

    def _retry_after(self, bucket: list[float], now: float) -> int:
        if not bucket:
            return self._backoff
        oldest = min(item for item in bucket if isinstance(item, float))
        return max(self._backoff, min(int(self._window - (now - oldest)), self._window))


class AuthService:
    """Accounts and login. The browser sees tokens and aliases, never user ids or hashes."""

    def __init__(self, config: Config, sessions: SessionStore, accounts: dict[str, Account]) -> None:
        self.config = config
        self.sessions = sessions
        self._accounts = accounts
        self._limiter = LoginRateLimiter.from_config(config)

    @property
    def is_initialized(self) -> bool:
        return bool(self._accounts)

    @classmethod
    def load(cls, config: Config, sessions: SessionStore) -> "AuthService":
        """Read the account file once. A missing or broken file means 'not initialized'."""
        payload = storage.read_json(Path(config.data_dir) / ACCOUNTS_FILE)
        accounts: dict[str, Account] = {}
        raw = payload.get("accounts", {})
        if isinstance(raw, dict):
            for user_id, record in raw.items():
                account = _account_from_storage(user_id, record)
                if account is not None:
                    accounts[account.user_id] = account
        return cls(config, sessions, accounts)

    def bootstrap(self, username: str, password: str, ip: str = "") -> dict[str, object]:
        """Create the one account, from the wizard. Succeeds at most once."""
        if self.is_initialized:
            raise AuthError(ERROR_ALREADY_INITIALIZED)
        if len(password) > MAX_PASSWORD_CHARS:
            raise AuthError(ERROR_INVALID)
        if check_password_strength(password):
            raise AuthError(ERROR_WEAK_PASSWORD)

        account = Account(
            user_id=issue_token(),
            username=check_username(username),
            password_hash=hash_password(password),
            created_at=int(time.time()),
        )
        self._accounts = {account.user_id: account}
        self._save()
        return self._session(account, ip)

    def login(self, username: str, password: str, ip: str = "") -> dict[str, object]:
        """Verify credentials and open a session. Always the same shape, always one code."""
        if not self.is_initialized:
            raise AuthError(ERROR_NOT_INITIALIZED)
        if len(password) > MAX_PASSWORD_CHARS:
            raise AuthError(ERROR_INVALID)

        try:
            name = check_username(username)
        except ValueError:
            name = DEFAULT_USERNAME
        if not self._limiter.check(ip, name).allowed:
            raise AuthError(ERROR_LOCKED, retry_after=self._limiter._backoff)  # noqa: SLF001

        account = self._by_username(name)
        if account is None:
            # Spend the same work a real verify costs, so a missing user is not faster.
            verify_password(_zero_hash(), password)
            self._limiter.record_failure(ip, name)
            raise AuthError(ERROR_BAD_CREDENTIALS, LOGIN_ERROR_MESSAGE)

        if not verify_password(account.password_hash, password):
            self._limiter.record_failure(ip, name)
            raise AuthError(ERROR_BAD_CREDENTIALS, LOGIN_ERROR_MESSAGE)

        self._limiter.record_success(ip, name)
        return self._session(account, ip)

    def logout(self, token: str) -> dict[str, object]:
        """Revoke one session. An unknown token is still a successful logout."""
        self.sessions.logout(token)
        return {"ok": True, "action": "logged_out"}

    def change_password(self, token: str, current: str, password: str) -> dict[str, object]:
        """Replace the password and revoke every session, so an old cookie cannot linger."""
        account = self._account_for_token(token)
        if account is None:
            raise AuthError(ERROR_UNAUTHORIZED)
        if not verify_password(account.password_hash, current):
            raise AuthError(ERROR_BAD_CREDENTIALS, LOGIN_ERROR_MESSAGE)
        if check_password_strength(password):
            raise AuthError(ERROR_WEAK_PASSWORD)

        updated = Account(
            user_id=account.user_id,
            username=account.username,
            password_hash=hash_password(password),
            created_at=account.created_at,
        )
        self._accounts[updated.user_id] = updated
        self._save()
        self.sessions.revoke_all()
        token = self.sessions.issue(updated.user_id, "")
        return {"ok": True, "action": "password_changed", "token": token, "csrf": self.sessions.csrf_for(token)}

    def verify_csrf(self, request: object) -> bool:
        from .security import CSRF_FIELD

        return self.sessions.verify_csrf(getattr(request, "token", ""), request.json.get(CSRF_FIELD, ""))

    def _by_username(self, username: str) -> Account | None:
        for account in self._accounts.values():
            if account.username == username:
                return account
        return None

    def _account_for_token(self, token: str) -> Account | None:
        if not self.sessions.authorize(token):
            return None
        user_id = self.sessions.user_for(token)
        if not user_id:
            return None
        account = self._accounts.get(user_id)
        return account if isinstance(account, Account) else None

    def _session(self, account: Account, ip: str) -> dict[str, object]:
        token = self.sessions.issue(account.user_id, ip)
        return {"ok": True, "action": "session_opened", "token": token, "csrf": self.sessions.csrf_for(token)}

    def _save(self) -> None:
        # Account is a dataclass, not JSON; as_dict() is the projection storage can write.
        payload = {
            "version": ACCOUNTS_VERSION,
            "accounts": {user_id: account.as_dict() for user_id, account in self._accounts.items()},
        }
        storage.write_json_atomic(Path(self.config.data_dir) / ACCOUNTS_FILE, payload)


def _account_from_storage(user_id: object, record: object) -> Account | None:
    if not isinstance(user_id, str) or not is_token(user_id):
        return None
    if not isinstance(record, dict):
        return None
    username = record.get("username")
    password_hash = record.get("password_hash")
    created_at = record.get("created_at")
    if not isinstance(username, str) or not USERNAME_PATTERN.match(username or ""):
        return None
    if not isinstance(password_hash, str) or not password_hash or len(password_hash) > 256:
        return None
    if not isinstance(created_at, int):
        return None
    return Account(user_id=user_id, username=username, password_hash=password_hash, created_at=created_at)
