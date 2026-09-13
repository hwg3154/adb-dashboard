"""End-to-end tests through the real HTTP server.

These start `tvdashboard.web` on a loopback port with a fake adb, and drive it the way a browser
would: first run, sign in, CSRF, session cookie, the key path, and the guards that are supposed
to refuse. Nothing is mocked below the socket.
"""

from __future__ import annotations

import base64
import json
import os
import re
import stat
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

from tvdashboard import api, web
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

PASSWORD = "correct-horse-battery"


class _Base(unittest.TestCase):
    """Harness only: no test methods, so unittest never runs this class on its own."""

    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp(prefix="tvd-http-"))
        binary = cls.dir / "adb"
        binary.write_text(_FAKE)
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        os.environ.setdefault("TVD_FAKE_STDOUT", "")
        os.environ.setdefault("TVD_FAKE_RC", "0")

        config = Config.from_env({
            "TVD_DATA_DIR": str(cls.dir / "data"),
            "TVD_HTTP_ADDR": "127.0.0.1:0",
            "TVD_ALLOW_INSECURE_HTTP": "1",
            "TVD_ADB_BIN": str(binary),
        })
        # The server logs one JSON line per request to stdout; that is correct in a container
        # and unreadable in a test run.
        cls._log = web._log
        web._log = lambda *args, **kwargs: None
        cls.server = web.build(config)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05})
        cls.thread.daemon = True
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        web._log = cls._log
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        # Every test signs in, and the login budget is per-username; without a reset the
        # sixth test would be locked out by the first five.
        limiter = self.server.app.auth._limiter  # noqa: SLF001 - test isolation
        limiter._ip.clear()  # noqa: SLF001
        limiter._user.clear()  # noqa: SLF001
        limiter._global_hits.clear()  # noqa: SLF001
        self.jar = CookieJar()
        self.http = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            _NoRedirect(),
        )

    # ------------------------------------------------------------------------------ helpers

    def get(self, path: str):
        return self._open(urllib.request.Request(self.base + path, method="GET"))

    def post_json(self, path: str, payload: dict, *, origin: str | None = "self", csrf: str = ""):
        body = dict(payload)
        if csrf:
            body["csrf"] = csrf
        request = urllib.request.Request(
            self.base + path,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        if origin == "self":
            request.add_header("Origin", self.base)
        elif origin:
            request.add_header("Origin", origin)
        return self._open(request)

    def post_form(self, path: str, payload: dict):
        from urllib.parse import urlencode

        request = urllib.request.Request(
            self.base + path,
            data=urlencode(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": self.base},
        )
        return self._open(request)

    def _open(self, request):
        try:
            response = self.http.open(request, timeout=10)
        except urllib.error.HTTPError as exc:
            response = exc
        body = response.read()
        return response.status, response.headers, body

    def body_json(self, body: bytes) -> dict:
        return json.loads(body.decode("utf-8"))

    def sign_in(self) -> str:
        """Create the account on first run (or sign in), and return the page's CSRF token."""
        status, _, body = self.post_json(
            "/api/login", {"username": "operator", "password": PASSWORD}
        )
        self.assertEqual(status, 200, body)
        status, _, page = self.get("/")
        self.assertEqual(status, 200)
        match = re.search(rb'name="tvd-csrf" content="([0-9a-f]{64})"', page)
        self.assertIsNotNone(match, "no CSRF token in the page")
        return match.group(1).decode("ascii")


class Live(_Base):
    """The server with an empty registry."""

    def test_01_first_run_redirects_everything_to_login(self):
        status, headers, _ = self.get("/")
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("Location"), "/login")
        status, _, page = self.get("/login")
        self.assertEqual(status, 200)
        self.assertIn(b"Create the dashboard password", page)

    def test_01b_the_sign_in_form_does_not_prefill_a_username(self):
        _, _, page = self.get("/login")
        body = page.decode("utf-8")
        self.assertIn("name=username", body)
        self.assertNotIn('value="operator"', body)

    def test_02_static_assets_are_served(self):
        for path, kind in (
            ("/static/app.css", "text/css"),
            ("/static/app.js", "text/javascript"),
            ("/static/placeholder.png", "image/png"),
        ):
            status, headers, body = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn(kind, headers.get("Content-Type", ""))
            self.assertTrue(body)

    def test_02b_quick_launch_logos_are_served(self):
        from tvdashboard import platforms

        self.assertTrue(platforms.LOGOS, "no logo shipped with the package")
        for url, (_relative, content_type) in platforms.logo_files().items():
            status, headers, body = self.get(url)
            self.assertEqual(status, 200, url)
            self.assertEqual(headers.get("Content-Type"), content_type, url)
            self.assertTrue(body, url)

    def test_02c_only_catalogued_logos_are_reachable(self):
        for bad in (
            "/static/logos/nope.jpg",
            "/static/logos/app.css",
            "/static/logos/",
        ):
            status, _, _ = self.get(bad)
            self.assertIn(status, (303, 404), bad)

    def test_03_security_headers_are_present(self):
        _, headers, _ = self.get("/login")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("frame-ancestors 'none'", headers.get("Content-Security-Policy", ""))

    def test_04_weak_password_is_refused_on_first_run(self):
        status, _, body = self.post_json("/api/login", {"username": "operator", "password": "short"})
        self.assertEqual(status, 400)
        self.assertEqual(self.body_json(body)["error"], "weak_password")

    def test_05_sign_in_sets_an_httponly_session_cookie(self):
        status, headers, _ = self.post_json(
            "/api/login", {"username": "operator", "password": PASSWORD}
        )
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie", "")
        self.assertIn("tvd_session=", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_06_pages_render_once_signed_in(self):
        self.sign_in()
        for path, marker in (
            ("/", b"remote-panel"),
            ("/apps", b"Launchable apps"),
            ("/settings", b"Devices"),
            ("/setup", b"Set up the TV"),
        ):
            status, _, page = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn(marker, page, path)

    def test_07_a_request_without_a_session_is_refused(self):
        status, _, body = self.post_json("/api/key", {"key": "home"}, csrf="0" * 64)
        self.assertEqual(status, 401)
        self.assertEqual(self.body_json(body)["error"], "unauthorized")

    def test_08_a_missing_or_wrong_csrf_token_is_refused(self):
        self.sign_in()
        status, _, body = self.post_json("/api/key", {"key": "home"})
        self.assertEqual(status, 403)
        self.assertEqual(self.body_json(body)["error"], "bad_csrf")
        status, _, body = self.post_json("/api/key", {"key": "home"}, csrf="1" * 64)
        self.assertEqual(status, 403)

    def test_09_a_cross_origin_post_is_refused(self):
        csrf = self.sign_in()
        status, _, body = self.post_json(
            "/api/key", {"key": "home"}, origin="http://evil.example", csrf=csrf
        )
        self.assertEqual(status, 403)
        self.assertEqual(self.body_json(body)["error"], "bad_origin")

    def test_10_a_key_press_without_a_device_reports_no_device(self):
        csrf = self.sign_in()
        status, _, body = self.post_json("/api/key", {"key": "home"}, csrf=csrf)
        self.assertEqual(status, 409)
        self.assertEqual(self.body_json(body)["error"], "no_device")

    def test_11_an_unknown_key_is_refused_before_any_device_lookup(self):
        csrf = self.sign_in()
        status, _, body = self.post_json("/api/key", {"key": "KEYCODE_POWER"}, csrf=csrf)
        self.assertEqual(status, 400)
        self.assertEqual(self.body_json(body)["error"], "bad_key")

    def test_12_the_browser_cannot_name_a_host(self):
        csrf = self.sign_in()
        status, _, body = self.post_json(
            "/api/join", {"candidate_id": "8.8.8.8:5555", "pairing_code": ""}, csrf=csrf
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.body_json(body)["error"], "bad_candidate")

    def test_12b_a_cross_site_fetch_is_refused_even_without_origin(self):
        csrf = self.sign_in()
        request = urllib.request.Request(
            self.base + "/api/key",
            data=json.dumps({"key": "home", "csrf": csrf}).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"},
        )
        status, _, body = self._open(request)
        self.assertEqual(status, 403)
        self.assertEqual(self.body_json(body)["error"], "bad_origin")

    def test_12c_a_null_origin_falls_back_to_sec_fetch_site(self):
        """`Origin: null` names no origin, so Sec-Fetch-Site has to settle it.

        Regression: a "no-referrer" Referrer-Policy made real browsers send `Origin: null`
        on the sign-in form, and refusing it outright made the app impossible to log into.
        """
        csrf = self.sign_in()
        # Our own page: allowed.
        request = urllib.request.Request(
            self.base + "/api/key",
            data=json.dumps({"key": "home", "csrf": csrf}).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Origin": "null",
                "Sec-Fetch-Site": "same-origin",
            },
        )
        status, _, body = self._open(request)
        self.assertEqual(status, 409, body)  # reached the handler: no device paired

        # Someone else's page: still refused.
        request = urllib.request.Request(
            self.base + "/api/key",
            data=json.dumps({"key": "home", "csrf": csrf}).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Origin": "null",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        status, _, body = self._open(request)
        self.assertEqual(status, 403)
        self.assertEqual(self.body_json(body)["error"], "bad_origin")

    def test_12d_referrer_policy_does_not_null_the_origin(self):
        """`Referrer-Policy: no-referrer` makes browsers send `Origin: null` on form
        navigations and drop Referer, which breaks sign-in and the form redirect. Pin it."""
        _, headers, _ = self.get("/login")
        policy = headers.get("Referrer-Policy", "")
        self.assertTrue(policy, "Referrer-Policy is missing")
        self.assertNotIn("no-referrer", policy)
        self.assertEqual(policy, "same-origin")

    def test_12e_every_form_on_a_page_carries_a_real_csrf_token(self):
        """A form rendered with an empty token is a button that always fails.

        Regression: the Sign out form on /settings used `$csrf`, but settings() did not pass
        the token down to _fill, so it rendered value="" next to a password form that had one.
        """
        import re as _re

        self.sign_in()
        for path in ("/", "/apps", "/settings", "/setup"):
            _, _, page = self.get(path)
            body = page.decode("utf-8")
            for match in _re.finditer(r'name="csrf" value="([0-9a-f]*)"', body):
                self.assertRegex(
                    match.group(1), r"^[0-9a-f]{64}$", f"empty/short csrf on {path}"
                )

    def test_12f_a_tile_with_artwork_renders_an_image_with_the_name_as_alt(self):
        from tvdashboard import platforms

        self.sign_in()
        _, _, page = self.get("/")
        body = page.decode("utf-8")
        alias = next(iter(platforms.LOGOS))
        label = platforms.CATALOG[alias].label
        if alias in self.server.app.prefs.quick_launch:
            self.assertIn(platforms.logo_url(alias), body)
            self.assertIn(f'alt="{label}"', body)
        # A platform with no artwork shows its name instead, so the button is never blank.
        plain = [a for a in self.server.app.prefs.quick_launch if a not in platforms.LOGOS]
        for missing in plain:
            self.assertIn(platforms.CATALOG[missing].label, body)

    def test_12g_a_tv_can_be_added_by_typing_its_address(self):
        csrf = self.sign_in()
        status, _, body = self.post_json(
            "/api/devices/add", {"host": "192.168.1.42", "port": "5555"}, csrf=csrf
        )
        self.assertEqual(status, 200, body)
        payload = self.body_json(body)
        self.assertEqual(payload["action"], "joined")
        with self.server.app.lock:
            targets = [d.target for d in self.server.app.registry.list()]
            for device in self.server.app.registry.list():
                self.server.app.registry.remove(device.id)
        self.assertIn("192.168.1.42:5555", targets)

    def test_12h_a_typed_address_is_held_to_the_same_guard(self):
        csrf = self.sign_in()
        for bad in (
            "8.8.8.8",              # off the LAN
            "127.0.0.1",            # loopback
            "169.254.169.254",      # cloud metadata
            "tv.local",             # hostname
            "192.168.1.5; reboot",
            "",
        ):
            status, _, body = self.post_json(
                "/api/devices/add", {"host": bad, "port": "5555"}, csrf=csrf
            )
            self.assertEqual(status, 400, f"{bad}: {body}")
            self.assertEqual(self.body_json(body)["error"], "bad_host", bad)

    def test_12i_a_typed_port_must_be_an_adb_port(self):
        csrf = self.sign_in()
        status, _, body = self.post_json(
            "/api/devices/add", {"host": "192.168.1.42", "port": "22"}, csrf=csrf
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.body_json(body)["error"], "bad_host")

    def test_12j_pairing_rejects_an_address_outside_the_lan(self):
        csrf = self.sign_in()
        for bad in ("8.8.8.8:37831", "127.0.0.1:37831", "192.168.1.5", "192.168.1.5:80"):
            status, _, body = self.post_json(
                "/api/pair", {"pair_address": bad, "pairing_code": "123456"}, csrf=csrf
            )
            self.assertEqual(status, 400, f"{bad}: {body}")
            self.assertEqual(self.body_json(body)["error"], "bad_pair_address", bad)

    def test_12k_pairing_needs_a_code(self):
        csrf = self.sign_in()
        status, _, body = self.post_json(
            "/api/pair", {"pair_address": "192.168.1.42:37831", "pairing_code": ""}, csrf=csrf
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.body_json(body)["error"], "bad_pair_code")

    def test_12l_the_setup_page_offers_both_manual_paths(self):
        self.sign_in()
        _, _, page = self.get("/setup")
        body = page.decode("utf-8")
        self.assertIn('action="/api/devices/add"', body)
        self.assertIn('action="/api/pair"', body)
        self.assertIn("name=pair_address", body)
        self.assertIn("name=pairing_code", body)

    def test_12m_a_failed_form_post_lands_back_on_the_page_not_on_json(self):
        """Regression: typing a bad address used to leave the browser on raw JSON."""
        csrf = self.sign_in()
        status, headers, _ = self.post_form(
            "/api/devices/add", {"host": "8.8.8.8", "port": "5555", "csrf": csrf}
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("Location"), "/setup?e=bad_host")
        # and the page turns that code into a sentence it owns
        _, _, page = self.get("/setup?e=bad_host")
        self.assertIn(b"your own network", page)

    def test_12n_a_crafted_notice_code_cannot_put_words_on_a_page(self):
        self.sign_in()
        _, _, page = self.get("/setup?e=%3Cscript%3Ealert(1)%3C/script%3E")
        body = page.decode("utf-8")
        self.assertNotIn("<script>alert", body)
        self.assertNotIn("alert(1)", body)

    def test_13_an_unknown_endpoint_is_not_found(self):
        csrf = self.sign_in()
        status, _, body = self.post_json("/api/reboot", {}, csrf=csrf)
        self.assertEqual(status, 404)

    def test_14_a_form_post_redirects_back_to_a_page(self):
        csrf = self.sign_in()
        status, headers, _ = self.post_form("/api/logout", {"csrf": csrf})
        self.assertEqual(status, 303)
        # The page it lands on says what happened, rather than looking like a failed sign-in.
        self.assertEqual(headers.get("Location"), "/login?e=signed_out")

    def test_14b_a_wrong_password_sends_the_browser_back_to_a_usable_form(self):
        """v1: a failed sign-in used to end on a page of JSON with no way back."""
        self.sign_in()  # make sure the account exists
        self.jar.clear()
        status, headers, body = self.post_form(
            "/api/login", {"username": "operator", "password": "not-the-password"}
        )
        self.assertEqual(status, 303, body)
        self.assertEqual(headers.get("Location"), "/login?e=bad_credentials")

        status, _, page = self.get("/login?e=bad_credentials")
        self.assertEqual(status, 200)
        self.assertIn(b"Check the password and try again", page)
        # The form is still there, so the next attempt costs one keystroke, not a URL edit.
        self.assertIn(b'action="/api/login"', page)
        self.assertIn(b'name=password', page)

    def test_14c_a_json_caller_still_gets_json(self):
        self.sign_in()
        self.jar.clear()
        status, _, body = self.post_json(
            "/api/login", {"username": "operator", "password": "not-the-password"}
        )
        self.assertEqual(status, 401)
        self.assertEqual(self.body_json(body)["error"], "bad_credentials")

    def test_14d_an_invented_notice_code_puts_nothing_on_the_page(self):
        self.sign_in()
        self.jar.clear()
        status, _, page = self.get("/login?e=%3Cb%3Eboom%3C/b%3E")
        self.assertEqual(status, 200)
        self.assertNotIn(b"boom", page)
        self.assertNotIn(b'class="banner', page)

    def test_14e_the_correct_password_works_after_a_failure(self):
        self.sign_in()
        self.jar.clear()
        self.post_form("/api/login", {"username": "operator", "password": "not-the-password"})
        status, headers, _ = self.post_form(
            "/api/login", {"username": "operator", "password": PASSWORD}
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("Location"), "/")
        self.assertIn("tvd_session=", headers.get("Set-Cookie", ""))

    def test_15_logout_revokes_the_session(self):
        csrf = self.sign_in()
        self.post_json("/api/logout", {}, csrf=csrf)
        status, headers, _ = self.get("/")
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("Location"), "/login")

    def test_16_an_oversized_body_is_refused(self):
        csrf = self.sign_in()
        status, _, _ = self.post_json("/api/text", {"text": "x" * 200_000}, csrf=csrf)
        self.assertEqual(status, 413)

    def test_17_key_presses_are_rate_limited_per_session(self):
        csrf = self.sign_in()
        codes = [
            self.post_json("/api/key", {"key": "home"}, csrf=csrf)[0]
            for _ in range(api.KEY_BUDGET + 5)
        ]
        self.assertIn(429, codes, "the key budget never engaged")

    def test_18_healthz_needs_no_session(self):
        status, _, body = self.get("/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(self.body_json(body)["ok"])

    def test_19_get_is_refused_for_state_changing_paths(self):
        self.sign_in()
        status, _, _ = self.get("/api/key")
        self.assertEqual(status, 404)


class WithDevice(_Base):
    """The same server, with one device in the registry, so the device paths actually run."""

    def setUp(self):
        super().setUp()
        with self.server.app.lock:
            self.device = self.server.app.registry.add("192.168.1.5:5555", model="Test TV")

    def tearDown(self):
        with self.server.app.lock:
            self.server.app.registry.remove(self.device.id)
        os.environ["TVD_FAKE_STDOUT"] = ""

    def test_90_a_key_press_reaches_adb(self):
        csrf = self.sign_in()
        status, _, body = self.post_json("/api/key", {"key": "dpad_up"}, csrf=csrf)
        self.assertEqual(status, 200, body)
        payload = self.body_json(body)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["key"], "dpad_up")

    def test_91_text_is_sent_and_never_echoed_back(self):
        csrf = self.sign_in()
        status, _, body = self.post_json("/api/text", {"text": "some search"}, csrf=csrf)
        self.assertEqual(status, 200, body)
        payload = self.body_json(body)
        self.assertEqual(payload["chars"], len("some search"))
        self.assertNotIn("some search", body.decode("utf-8"))

    def test_92_unsendable_text_is_refused(self):
        csrf = self.sign_in()
        status, _, body = self.post_json("/api/text", {"text": "$$$"}, csrf=csrf)
        self.assertEqual(status, 400)
        self.assertEqual(self.body_json(body)["error"], "bad_text")

    def test_93_a_screenshot_comes_back_as_base64_png(self):
        png = b"\x89PNG\r\n\x1a\n" + bytes(range(256))
        os.environ["TVD_FAKE_STDOUT"] = "b64:" + base64.b64encode(png).decode("ascii")
        csrf = self.sign_in()
        status, _, body = self.post_json("/api/screenshot", {}, csrf=csrf)
        self.assertEqual(status, 200, body)
        payload = self.body_json(body)
        self.assertEqual(base64.b64decode(payload["png"])[:8], b"\x89PNG\r\n\x1a\n")

    def test_94_the_app_list_is_parsed(self):
        os.environ["TVD_FAKE_STDOUT"] = "Activity #0:\n  com.example.tv/.MainActivity\n"
        csrf = self.sign_in()
        status, _, body = self.post_json("/api/apps", {}, csrf=csrf)
        self.assertEqual(status, 200, body)
        self.assertEqual(self.body_json(body)["apps"][0]["package"], "com.example.tv")

    def test_95_a_bad_package_never_reaches_adb(self):
        csrf = self.sign_in()
        for bad in ("com.example.app; reboot", "../etc", "nodots"):
            status, _, body = self.post_json("/api/launch", {"package": bad}, csrf=csrf)
            self.assertEqual(status, 400, bad)
            self.assertEqual(self.body_json(body)["error"], "bad_package")

    def test_95b_quick_launch_takes_an_alias_and_never_a_package(self):
        csrf = self.sign_in()
        status, _, body = self.post_json("/api/quick_launch", {"platform": "netflix"}, csrf=csrf)
        self.assertEqual(status, 200, body)
        payload = self.body_json(body)
        self.assertEqual(payload["platform"], "netflix")
        # The answer names the platform, not what was actually run on the device.
        self.assertNotIn("package", payload)

    def test_95c_an_unknown_platform_is_refused_before_any_device_lookup(self):
        csrf = self.sign_in()
        for bad in ("com.netflix.ninja", "netflix; reboot", "../etc", ""):
            status, _, body = self.post_json("/api/quick_launch", {"platform": bad}, csrf=csrf)
            self.assertEqual(status, 400, bad)
            self.assertEqual(self.body_json(body)["error"], "bad_platform", bad)

    def test_95d_the_dashboard_shows_the_chosen_tiles_and_nothing_else(self):
        csrf = self.sign_in()
        status, _, page = self.get("/")
        self.assertEqual(status, 200)
        for label in (b"Netflix", b"Disney+", b"Prime Video", b"YouTube", b"HBO Max"):
            self.assertIn(label, page)
        self.assertNotIn(b"Crunchyroll", page)
        self.assertNotIn(b"com.netflix", page)

        status, _, body = self.post_json(
            "/api/prefs/quick_launch", {"alias": "netflix", "on": "0"}, csrf=csrf
        )
        self.assertEqual(status, 200, body)
        self.assertNotIn("netflix", self.body_json(body)["quick_launch"])

        _, _, page = self.get("/")
        self.assertNotIn(b"Netflix", page)
        # And it is still offered in Settings, or it could never be switched back on.
        _, _, settings = self.get("/settings")
        self.assertIn(b'data-alias="netflix"', settings)

        status, _, body = self.post_json(
            "/api/prefs/quick_launch", {"alias": "netflix", "on": "1"}, csrf=csrf
        )
        self.assertEqual(status, 200, body)
        _, _, page = self.get("/")
        self.assertIn(b"Netflix", page)

    def test_95e_an_unknown_alias_cannot_be_switched_on(self):
        csrf = self.sign_in()
        status, _, body = self.post_json(
            "/api/prefs/quick_launch", {"alias": "com.evil.app", "on": "1"}, csrf=csrf
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.body_json(body)["error"], "bad_platform")

    def test_96_a_device_can_be_forgotten_by_id(self):
        csrf = self.sign_in()
        status, _, body = self.post_json(
            f"/api/devices/{self.device.id}/forget", {}, csrf=csrf
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(self.body_json(body)["action"], "forgotten")
        with self.server.app.lock:
            self.assertIsNone(self.server.app.registry.get(self.device.id))


    def test_97_wake_is_refused_until_the_mac_is_known(self):
        from tvdashboard import wol

        original = wol.lookup_mac
        wol.lookup_mac = lambda host: ""
        try:
            csrf = self.sign_in()
            status, _, body = self.post_json("/api/wake", {}, csrf=csrf)
        finally:
            wol.lookup_mac = original
        self.assertEqual(status, 409, body)
        self.assertEqual(self.body_json(body)["error"], "no_mac")

    def test_98_wake_goes_to_the_last_used_tv_and_ignores_anything_the_browser_adds(self):
        from tvdashboard import wol

        sent = []
        original = wol.send
        wol.send = lambda mac, host: sent.append((mac, host)) or 3
        with self.server.app.lock:
            self.server.app.registry.set_mac(self.device.id, "d0:65:b3:27:38:0b")
        try:
            csrf = self.sign_in()
            status, _, body = self.post_json(
                "/api/wake", {"mac": "ff:ff:ff:ff:ff:ff", "host": "8.8.8.8"}, csrf=csrf
            )
        finally:
            wol.send = original
        self.assertEqual(status, 200, body)
        self.assertEqual(self.body_json(body)["action"], "wake_sent")
        self.assertEqual(sent, [("d0:65:b3:27:38:0b", "192.168.1.5")])

    def test_99_a_successful_key_press_learns_the_mac_exactly_once(self):
        from tvdashboard import api as api_module
        from tvdashboard import wol

        lookups = []
        original = wol.lookup_mac
        wol.lookup_mac = lambda host: lookups.append(host) or "d0:65:b3:27:38:0b"
        api_module._MAC_MISSES.clear()  # noqa: SLF001 - test isolation
        try:
            csrf = self.sign_in()
            for _ in range(3):
                status, _, body = self.post_json("/api/key", {"key": "home"}, csrf=csrf)
                self.assertEqual(status, 200, body)
        finally:
            wol.lookup_mac = original
        self.assertEqual(lookups, ["192.168.1.5"])
        with self.server.app.lock:
            self.assertEqual(self.server.app.registry.get(self.device.id).mac, "d0:65:b3:27:38:0b")

    def test_99b_wake_needs_a_csrf_token(self):
        self.sign_in()
        status, _, body = self.post_json("/api/wake", {})
        self.assertEqual(status, 403)
        self.assertEqual(self.body_json(body)["error"], "bad_csrf")

    def test_99c_the_remote_has_sleep_and_wake_and_no_power(self):
        self.sign_in()
        _, _, page = self.get("/")
        body = page.decode("utf-8")
        self.assertIn('formaction="/api/wake"', body)
        self.assertIn('value="sleep"', body)
        self.assertNotIn('value="power"', body)


    def _patch_wake(self, awake_answers, mac="d0:65:b3:27:38:0b"):
        """Drive the quick-launch wake path with no network and no real waiting.

        Records every probe, send and pause in order, so a test can assert the sequence.
        """
        from tvdashboard import api as api_module
        from tvdashboard import wol

        calls = []
        answers = list(awake_answers)
        saved = (wol.is_awake, wol.send, wol.lookup_mac, api_module._sleep)

        def is_awake(host, port, timeout=1.0):
            calls.append(("probe", host, port))
            return answers.pop(0) if answers else True

        wol.is_awake = is_awake
        wol.send = lambda m, h: calls.append(("send", m, h)) or 3
        wol.lookup_mac = lambda host: ""
        api_module._sleep = lambda seconds: calls.append(("sleep", seconds))

        def restore():
            wol.is_awake, wol.send, wol.lookup_mac, api_module._sleep = saved

        self.addCleanup(restore)
        if mac:
            with self.server.app.lock:
                self.server.app.registry.set_mac(self.device.id, mac)
        return calls

    def _quick_launch(self):
        csrf = self.sign_in()
        return self.post_json("/api/quick_launch", {"platform": "netflix"}, csrf=csrf)

    def test_99d_quick_launch_on_an_awake_tv_just_launches(self):
        calls = self._patch_wake([True])
        status, _, body = self._quick_launch()
        self.assertEqual(status, 200, body)
        self.assertFalse(self.body_json(body)["woke"])
        self.assertEqual([call[0] for call in calls], ["probe"])

    def test_99e_quick_launch_on_a_sleeping_tv_wakes_pauses_then_launches(self):
        calls = self._patch_wake([False, True])
        status, _, body = self._quick_launch()
        self.assertEqual(status, 200, body)
        self.assertTrue(self.body_json(body)["woke"])
        self.assertEqual(
            calls,
            [
                ("probe", "192.168.1.5", 5555),
                ("send", "d0:65:b3:27:38:0b", "192.168.1.5"),
                ("sleep", 3.0),
                ("probe", "192.168.1.5", 5555),
            ],
        )

    def test_99f_a_tv_slower_than_the_pause_is_waited_for_rather_than_failed(self):
        calls = self._patch_wake([False, False, False, True])
        status, _, body = self._quick_launch()
        self.assertEqual(status, 200, body)
        pauses = [call[1] for call in calls if call[0] == "sleep"]
        self.assertEqual(pauses[0], 3.0)
        self.assertGreater(len(pauses), 1, "stopped waiting at the 3 s pause")

    def test_99g_a_sleeping_tv_with_no_learned_mac_still_launches_as_before(self):
        calls = self._patch_wake([False], mac="")
        status, _, body = self._quick_launch()
        self.assertEqual(status, 200, body)
        self.assertFalse(self.body_json(body)["woke"])
        self.assertNotIn("send", [call[0] for call in calls])


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Follow nothing: these tests assert on the redirect itself."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


if __name__ == "__main__":
    unittest.main()
