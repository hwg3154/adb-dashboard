"""Contract tests against a fake `adb`.

design.md §12: a fake adb executable returning canned output, asserting the argv shape and that
no browser string is ever interpolated into a command.

The fake records every invocation as one JSON line, so a test can inspect exactly what argv the
real binary would have received.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from tvdashboard import adb
from tvdashboard.config import Config

_FAKE = """#!/usr/bin/env python3
import json, os, sys
with open(os.environ["TVD_FAKE_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\\n")
canned = os.environ.get("TVD_FAKE_STDOUT", "")
if canned.startswith("b64:"):
    import base64
    sys.stdout.buffer.write(base64.b64decode(canned[4:]))
else:
    sys.stdout.write(canned)
sys.exit(int(os.environ.get("TVD_FAKE_RC", "0")))
"""


class FakeAdb(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="tvd-fake-"))
        self.binary = self.dir / "adb"
        self.binary.write_text(_FAKE)
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        self.log = self.dir / "calls.jsonl"
        os.environ["TVD_FAKE_LOG"] = str(self.log)
        os.environ["TVD_FAKE_RC"] = "0"
        os.environ["TVD_FAKE_STDOUT"] = ""
        self.client = adb.AdbClient.from_config(
            Config.from_env({"TVD_ADB_BIN": str(self.binary), "TVD_DATA_DIR": str(self.dir)})
        )

    def tearDown(self):
        for name in ("TVD_FAKE_LOG", "TVD_FAKE_RC", "TVD_FAKE_STDOUT"):
            os.environ.pop(name, None)

    def calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def last(self) -> list[str]:
        calls = self.calls()
        self.assertTrue(calls, "adb was never called")
        return calls[-1]

    # ------------------------------------------------------------------------- argv shape

    def test_a_key_press_is_a_fixed_argv_with_one_allowlisted_keycode(self):
        self.client.send_key("192.168.1.5:5555", "dpad_up")
        self.assertEqual(
            self.last(),
            ["-s", "192.168.1.5:5555", "shell", "input", "keyevent", "KEYCODE_DPAD_UP"],
        )

    def test_the_browser_cannot_choose_a_keycode(self):
        with self.assertRaises(Exception):
            self.client.send_key("192.168.1.5:5555", "KEYCODE_POWER")
        self.assertEqual(self.calls(), [])

    def test_text_travels_as_one_quoted_argument(self):
        self.client.send_text("192.168.1.5:5555", "hello world")
        argv = self.last()
        self.assertEqual(argv[:5], ["-s", "192.168.1.5:5555", "shell", "input", "text"])
        self.assertEqual(len(argv), 6, argv)
        self.assertEqual(argv[5], "'hello%sworld'")

    def test_text_cannot_smuggle_a_second_command(self):
        self.client.send_text("192.168.1.5:5555", "a; reboot && rm -rf /")
        payload = self.last()[5]
        for char in ";&|`$<>":
            self.assertNotIn(char, payload)

    def test_a_package_name_is_validated_not_interpolated(self):
        for bad in ("com.example.app; reboot", "../../etc/passwd", "com.example.app rm", "no-dots"):
            with self.assertRaises(ValueError, msg=bad):
                self.client.stop("192.168.1.5:5555", bad)
        self.assertEqual(self.calls(), [])

    def test_an_off_lan_target_never_reaches_adb(self):
        for bad in ("8.8.8.8:5555", "127.0.0.1:5555", "169.254.169.254:5555"):
            with self.assertRaises(ValueError, msg=bad):
                self.client.send_key(bad, "home")
        self.assertEqual(self.calls(), [])

    def test_pairing_code_is_digits_only(self):
        self.client.pair("192.168.1.5", 5555, "123456")
        self.assertEqual(self.last(), ["pair", "192.168.1.5:5555", "123456"])
        with self.assertRaises(ValueError):
            self.client.pair("192.168.1.5", 5555, "12; reboot")

    def test_mdns_uses_a_real_adb_subcommand(self):
        # `adb discover` does not exist; browsing is `adb mdns services`.
        self.client.mdns_services()
        self.assertEqual(self.last(), ["mdns", "services"])

    # ------------------------------------------------------------------------ canned output

    def test_launchable_apps_are_parsed_from_query_activities(self):
        os.environ["TVD_FAKE_STDOUT"] = (
            "Activity #0:\n"
            "  com.example.tv/.MainActivity\n"
            "Activity #1:\n"
            "  com.example.other/.Launcher\n"
        )
        apps = self.client.list_apps("192.168.1.5:5555")
        self.assertEqual([item["package"] for item in apps], ["com.example.tv", "com.example.other"])
        self.assertEqual(apps[0]["kind"], "TV")

    def test_a_screenshot_survives_as_bytes(self):
        # Regression: stdout used to be decoded as UTF-8 with "replace", destroying the PNG.
        png = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4
        import base64

        os.environ["TVD_FAKE_STDOUT"] = "b64:" + base64.b64encode(png).decode("ascii")
        payload, result = self.client.screenshot("192.168.1.5:5555")
        self.assertTrue(result.ok)
        self.assertEqual(payload, png)
        self.assertEqual(self.last(), ["-s", "192.168.1.5:5555", "exec-out", "screencap", "-p"])

    def test_query_activities_asks_for_brief_output(self):
        os.environ["TVD_FAKE_STDOUT"] = "Activity #0:\n  com.example.tv/.MainActivity\n"
        self.client.list_apps("192.168.1.5:5555")
        self.assertIn("--brief", self.calls()[0])

    def test_a_nonzero_exit_is_a_failure(self):
        os.environ["TVD_FAKE_RC"] = "1"
        result = self.client.send_key("192.168.1.5:5555", "home")
        self.assertFalse(result.ok)

    def test_device_side_failure_is_detected_despite_exit_zero(self):
        os.environ["TVD_FAKE_STDOUT"] = "Error: Activity not started, unable to resolve Intent\n"
        result = self.client.send_key("192.168.1.5:5555", "home")
        self.assertFalse(result.ok)

    def test_ordinary_output_is_not_mistaken_for_a_failure(self):
        # A package whose name contains "error", and a getprop that answers "unknown", are
        # both perfectly normal and must not be read as errors.
        os.environ["TVD_FAKE_STDOUT"] = "package:com.example.errorreporter\nunknown\n"
        result = self.client.run(["-s", "192.168.1.5:5555", "shell", "getprop", "ro.product.model"])
        self.assertTrue(result.ok, result.stderr)

    def test_a_missing_binary_raises_adb_error(self):
        client = adb.AdbClient("/nonexistent/adb")
        self.assertFalse(client.available())
        with self.assertRaises(adb.AdbError):
            client.run(["devices"])


if __name__ == "__main__":
    unittest.main()
