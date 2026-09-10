"""Unit tests for the pieces design.md §12 names: keycode map, text sanitizer, argv builder,
the RFC1918/loopback guard, and candidate dedupe."""

from __future__ import annotations

import tempfile
import unittest

from tvdashboard import keys, netguard, registry, textentry
from tvdashboard.config import DEFAULT_ALLOWED_CIDRS, DEVICE_PORTS, Config


def _config(**env: str) -> Config:
    base = {"TVD_DATA_DIR": tempfile.mkdtemp(prefix="tvd-test-")}
    base.update(env)
    return Config.from_env(base)


class KeycodeMap(unittest.TestCase):
    def test_every_alias_resolves_to_a_real_keycode_name(self):
        for alias, spec in keys.KEY_ALIASES.items():
            self.assertEqual(spec.alias, alias)
            self.assertTrue(spec.keycode.startswith("KEYCODE_"), spec.keycode)
            self.assertRegex(spec.keycode, r"^KEYCODE_[A-Z0-9_]+$")

    def test_browser_aliases_point_at_known_keys(self):
        for browser_key, alias in keys.KEYBOARD_ALIASES.items():
            self.assertIn(alias, keys.KEY_ALIASES, f"{browser_key} -> {alias}")

    def test_unknown_key_is_rejected(self):
        for bad in ("", "  ", "KEYCODE_POWER", "../etc", "power; reboot", None, 7):
            with self.assertRaises(keys.InvalidKey):
                keys.resolve_key(bad)

    def test_destructive_keys_carry_a_confirmation(self):
        for alias in ("power", "sleep"):
            self.assertTrue(keys.KEY_ALIASES[alias].is_destructive)

    def test_escape_is_not_forwarded(self):
        # design.md §4: Esc releases the panel; it must not reach the TV as Back.
        self.assertNotIn("escape", keys.KEYBOARD_ALIASES)


class TextSanitizer(unittest.TestCase):
    def test_shell_metacharacters_are_dropped(self):
        cleaned = textentry.sanitize_text("rm -rf / ; echo $HOME & `id`")
        for char in "`|&;<>(){}[]$\\\"'":
            self.assertNotIn(char, cleaned)

    def test_control_characters_are_dropped(self):
        self.assertEqual(textentry.sanitize_text("a\x00b\x1bc"), "abc")

    def test_empty_and_oversized_are_rejected(self):
        for bad in ("", "   ", "\x00", None, 42):
            with self.assertRaises(textentry.TextRejected):
                textentry.sanitize_text(bad)
        with self.assertRaises(textentry.TextRejected):
            textentry.sanitize_text("a" * 40, max_chars=8)

    def test_spaces_travel_as_percent_s(self):
        encoded = textentry.encode_text_arg(textentry.sanitize_text("hello world"))
        self.assertNotIn(" ", encoded)
        self.assertIn("%s", encoded)

    def test_encoded_argument_is_quoted_exactly_once(self):
        encoded = textentry.encode_text_arg(textentry.sanitize_text("a search term"))
        self.assertTrue(encoded.startswith("'") and encoded.endswith("'"))
        self.assertEqual(encoded.count("'"), 2)


class TargetGuard(unittest.TestCase):
    def test_rfc1918_targets_are_accepted(self):
        for host in ("192.168.1.5", "10.0.0.9", "172.16.4.4"):
            self.assertEqual(
                netguard.normalize_target(f"{host}:5555", DEFAULT_ALLOWED_CIDRS, DEVICE_PORTS),
                f"{host}:5555",
            )

    def test_off_lan_and_special_addresses_are_refused(self):
        for bad in (
            "127.0.0.1:5555",       # loopback
            "169.254.169.254:5555",  # cloud metadata
            "0.0.0.0:5555",
            "224.0.0.1:5555",       # multicast
            "8.8.8.8:5555",         # public
            "100.64.0.1:5555",      # CGNAT
            "192.168.1.5:22",       # not an adb port
            "tv.local:5555",        # hostname
            "http://192.168.1.5:5555",
            "192.168.1.5:5555/../x",
            "[::1]:5555",
            "",
            None,
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                netguard.normalize_target(bad, DEFAULT_ALLOWED_CIDRS, DEVICE_PORTS)

    def test_pairing_code_must_be_digits(self):
        self.assertEqual(netguard.validate_pair_code("123456"), "123456")
        self.assertEqual(netguard.validate_pair_code(""), "")
        for bad in ("12345", "abcdef", "123456; reboot", "1234567890123"):
            with self.assertRaises(netguard.TargetRejected):
                netguard.validate_pair_code(bad)

    def test_candidate_id_shape(self):
        self.assertEqual(netguard.candidate_id("a" * 32), "a" * 32)
        for bad in ("a" * 31, "g" * 32, "", None):
            with self.assertRaises(netguard.TargetRejected):
                netguard.candidate_id(bad)


class CandidateCache(unittest.TestCase):
    def setUp(self):
        self.config = _config()
        self.reg = registry.Registry(self.config, devices={}, candidates={})

    def _candidate(self, host: str, port: int = 5555, age: int = 0) -> registry.Candidate:
        import time

        return registry.Candidate(
            id=registry.candidate_key(host, port),
            host=host,
            port=port,
            score=100,
            added_at=int(time.time()) - age,
            model="Test TV",
        )

    def test_the_same_host_and_port_dedupe_to_one_entry(self):
        found = [self._candidate("192.168.1.5"), self._candidate("192.168.1.5")]
        self.assertEqual(self.reg.remember(found), 1)

    def test_a_candidate_can_only_be_joined_once(self):
        candidate = self._candidate("192.168.1.5")
        self.reg.remember([candidate])
        self.assertIsNotNone(self.reg.take(candidate.id))
        self.assertIsNone(self.reg.take(candidate.id))

    def test_expired_candidates_are_dropped(self):
        stale = self._candidate("192.168.1.6", age=int(self.config.candidate_ttl_seconds) + 60)
        self.reg.remember([stale])
        self.assertEqual(self.reg.candidates(), [])

    def test_persisted_candidates_survive_a_reload(self):
        # Regression: Candidate.added_at has no default, so rebuilding one used to raise.
        self.reg.remember([self._candidate("192.168.1.7")])
        reloaded = registry.Registry.load(self.config)
        self.assertEqual(len(reloaded.candidates()), 1)

    def test_a_device_is_never_added_twice(self):
        first = self.reg.add("192.168.1.5:5555", model="TV")
        second = self.reg.add("192.168.1.5:5555", model="TV")
        self.assertEqual(first.id, second.id)
        self.assertEqual(len(self.reg.list()), 1)

    def test_device_ids_are_unpredictable(self):
        ids = {registry.new_device_id() for _ in range(200)}
        self.assertEqual(len(ids), 200)
        self.assertTrue(all(len(item) == 32 for item in ids))


if __name__ == "__main__":
    unittest.main()
