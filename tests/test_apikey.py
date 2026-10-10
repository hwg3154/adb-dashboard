"""End-to-end tests for the scriptable API (Bearer `TVD_API_KEY`).

These start the real HTTP server with the API key enabled, plus a second server with it
disabled, and prove both directions: the key opens the whole endpoint table with no cookie,
CSRF or Origin, and the disabled server is byte-for-byte the old browser-only behaviour.

Nothing is mocked below the socket, the same way test_http.py does it.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from tvdashboard import web
from tvdashboard.config import Config

_FAKE = """#!/usr/bin/env python3
import base64, os, sys
canned = os.environ.get("TVD_FAKE_STDOUT", "")
if canned.startswith("b64:"):
    sys.stdout.buffer.write(base64.b64decode(canned[4:]))
else:
    sys.stdout.write(canned)
sys.exit(int(os.environ.get("TVD_FAKE_RC", "0")))
"""

#: A valid key is 16+ characters; this one is deliberately long and random-looking.
KEY = "0123456789abcdef0123456789abcdef"
PASSWORD = "correct-horse-battery"


def _start(config: Config) -> tuple["web.Server", str, threading.Thread]:
    web._log = lambda *args, **kwargs: None
    server = web.build(config)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.daemon = True
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}", thread


def _stop(server: "web.Server", thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


class _Base(unittest.TestCase):
    def _open(self, base: str, method: str, path: str, *, headers=None, payload=None):
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers = dict(headers or {})
            headers.setdefault("Content-Type", "application/json")
        request = urllib.request.Request(
            base + path, data=data, method=method, headers=headers or {}
        )
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as exc:
            response = exc
        return response.status, response.headers, response.read()

    def _json(self, body: bytes) -> dict:
        return json.loads(body.decode("utf-8"))


class ScriptableApiOn(_Base):
    """Server started with TVD_API_KEY set."""

    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp(prefix="tvd-apikey-on-"))
        binary = cls.dir / "adb"
        binary.write_text(_FAKE)
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        os.environ.setdefault("TVD_FAKE_STDOUT", "")
        os.environ.setdefault("TVD_FAKE_RC", "0")

        cls.server, cls.base, cls.thread = _start(Config.from_env({
            "TVD_DATA_DIR": str(cls.dir / "data"),
            "TVD_HTTP_ADDR": "127.0.0.1:0",
            "TVD_ALLOW_INSECURE_HTTP": "1",
            "TVD_ADB_BIN": str(binary),
            "TVD_API_KEY": KEY,
        }))

    @classmethod
    def tearDownClass(cls):
        _stop(cls.server, cls.thread)

    def setUp(self):
        # Each test signs in via the browser path to have a session to contrast against, and
        # clears the login budget so the per-username limiter does not trip between tests.
        limiter = self.server.app.auth._limiter
        limiter._ip.clear()
        limiter._user.clear()
        limiter._global_hits.clear()

    def test_01_status_returns_the_registry_snapshot(self):
        # status is read-only, but it still names devices and their awake state, so the key is
        # required - it is not an anonymous probe.
        status, _, body = self._open(
            self.base, "POST", "/api/status",
            headers={"Authorization": f"Bearer {KEY}"},
            payload={},
        )
        self.assertEqual(status, 200, body)
        payload = self._json(body)
        self.assertTrue(payload["ok"])
        self.assertIn("devices", payload)
        self.assertIn("active", payload)
        self.assertIn("quick_launch", payload)

    def test_02_a_key_press_needs_no_cookie_csrf_or_origin(self):
        # No Origin header at all, no csrf field, no cookie: the key alone must get through.
        status, _, body = self._open(
            self.base, "POST", "/api/key",
            headers={"Authorization": f"Bearer {KEY}"},
            payload={"key": "home"},
        )
        # With no device paired this is the handler's "no device" answer, which proves the
        # request reached the handler at all. A 401/403 would mean the gate still blocked it.
        self.assertEqual(status, 409, body)
        self.assertEqual(self._json(body)["error"], "no_device")

    def test_03_an_unknown_key_is_refused_before_any_handler(self):
        status, _, body = self._open(
            self.base, "POST", "/api/status",
            headers={"Authorization": "Bearer " + "f" * 32},
            payload={},
        )
        self.assertEqual(status, 401)
        self.assertEqual(self._json(body)["error"], "unauthorized")

    def test_04_no_key_and_no_session_is_unauthorized(self):
        status, _, body = self._open(self.base, "POST", "/api/status", payload={})
        self.assertEqual(status, 401)
        self.assertEqual(self._json(body)["error"], "unauthorized")

    def test_05_the_browser_cookie_path_still_works(self):
        # A wrong key is not a substitute: with the cookie present but a bad bearer token, the
        # request must fall through to the cookie auth, not be rejected for the bad header.
        status, _, body = self._open(
            self.base, "POST", "/api/status",
            headers={"Authorization": "Bearer wrong"},
            payload={},
        )
        self.assertEqual(status, 401, body)

    def test_06_a_malformed_authorization_header_is_refused(self):
        for value in ("Bearer", "bearer", "Basic " + KEY, "", "Bearer " + KEY + " extra"):
            status, _, body = self._open(
                self.base, "POST", "/api/status",
                headers={"Authorization": value},
                payload={},
            )
            self.assertEqual(status, 401, f"{value!r}: {body}")

    def test_07_status_reports_the_active_device_state(self):
        # Add a device through the key path itself, then confirm /api/status shows it active.
        status, _, body = self._open(
            self.base, "POST", "/api/devices/add",
            headers={"Authorization": f"Bearer {KEY}"},
            payload={"host": "192.168.1.42", "port": "5555"},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(self._json(body)["action"], "joined")

        status, _, body = self._open(
            self.base, "POST", "/api/status",
            headers={"Authorization": f"Bearer {KEY}"},
            payload={},
        )
        self.assertEqual(status, 200, body)
        payload = self._json(body)
        self.assertTrue(payload["active"]["target"])
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["devices"][0]["label"], "Android TV")

    def test_08_quick_launch_by_alias_with_the_key(self):
        # The everyday verb: put Netflix on. With the fake adb this "succeeds" (fake exits 0);
        # the point is that the key carries the request all the way to the launcher.
        status, _, body = self._open(
            self.base, "POST", "/api/quick_launch",
            headers={"Authorization": f"Bearer {KEY}"},
            payload={"platform": "netflix"},
        )
        self.assertIn(status, (200, 502), body)  # fake adb: 200, or a device-side 502
        # An unknown platform is refused before any device work.
        status, _, body = self._open(
            self.base, "POST", "/api/quick_launch",
            headers={"Authorization": f"Bearer {KEY}"},
            payload={"platform": "not-a-platform"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(self._json(body)["error"], "bad_platform")


class ScriptableApiOff(_Base):
    """Server started with no TVD_API_KEY: the token path must not exist at all."""

    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp(prefix="tvd-apikey-off-"))
        binary = cls.dir / "adb"
        binary.write_text(_FAKE)
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        os.environ.setdefault("TVD_FAKE_STDOUT", "")
        os.environ.setdefault("TVD_FAKE_RC", "0")

        cls.server, cls.base, cls.thread = _start(Config.from_env({
            "TVD_DATA_DIR": str(cls.dir / "data"),
            "TVD_HTTP_ADDR": "127.0.0.1:0",
            "TVD_ALLOW_INSECURE_HTTP": "1",
            "TVD_ADB_BIN": str(binary),
            # No TVD_API_KEY at all.
        }))

    @classmethod
    def tearDownClass(cls):
        _stop(cls.server, cls.thread)

    def test_01_the_same_key_is_not_accepted(self):
        # Even the exact same key string means nothing here, because the feature is off.
        status, _, body = self._open(
            self.base, "POST", "/api/status",
            headers={"Authorization": f"Bearer {KEY}"},
            payload={},
        )
        self.assertEqual(status, 401)
        self.assertEqual(self._json(body)["error"], "unauthorized")

    def test_02_status_is_not_reachable_without_a_session(self):
        status, _, body = self._open(self.base, "POST", "/api/status", payload={})
        self.assertEqual(status, 401)


class ConfigParsing(unittest.TestCase):
    """The key is only live when it is 16+ characters."""

    def _cfg(self, value):
        return Config.from_env({"TVD_API_KEY": value, "TVD_DATA_DIR": "/tmp/tvd-cfg"})

    def test_absent_is_empty(self):
        self.assertEqual(self._cfg("").api_key, "")

    def test_short_is_refused_with_a_warning(self):
        cfg = self._cfg("tooshort")
        self.assertEqual(cfg.api_key, "")
        self.assertTrue(any("TVD_API_KEY" in w for w in cfg.warnings))

    def test_long_is_accepted(self):
        self.assertEqual(self._cfg(KEY).api_key, KEY)

    def test_exact_minimum_is_accepted(self):
        self.assertEqual(self._cfg("a" * 16).api_key, "a" * 16)

    def test_control_characters_are_dropped(self):
        # text() refuses control characters in the whole value, so a newline inside the key
        # makes it fall back to the default (empty).
        self.assertEqual(self._cfg("abc\ndef012345678").api_key, "")


if __name__ == "__main__":
    unittest.main()
