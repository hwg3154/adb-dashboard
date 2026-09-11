"""Unit tests for the pieces design.md §12 names: keycode map, text sanitizer, argv builder,
the RFC1918/loopback guard, candidate dedupe, and the quick-launch catalogue."""

from __future__ import annotations

import pathlib
import re
import tempfile
import unittest

from tvdashboard import adb, api, keys, netguard, platforms, prefs, registry, textentry, views
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

    def test_escape_is_the_back_key(self):
        # design.md §4: Esc is Back, the way it is on a remote. Shift+Esc releases the panel,
        # and the client never sends that combination, so it has no alias here.
        for name in ("escape", "esc"):
            self.assertEqual(keys.resolve_key(name).keycode, "KEYCODE_BACK")


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


class QuickLaunchLogos(unittest.TestCase):
    """Artwork is data on disk, so the wiring between the two has to be checked."""

    def test_every_logo_file_belongs_to_a_catalogue_alias(self):
        # A file named after nothing is a file nobody will ever see; more importantly it
        # proves the scan is keyed by the catalogue and not by whatever is in the directory.
        for alias in platforms.LOGOS:
            self.assertIn(alias, platforms.CATALOG, alias)

    def test_a_platform_without_artwork_has_no_url(self):
        without = [a for a in platforms.CATALOG if a not in platforms.LOGOS]
        self.assertTrue(without, "every platform has a logo; pick a different fixture")
        self.assertEqual(platforms.logo_url(without[0]), "")

    def test_a_logo_url_is_one_we_built(self):
        for alias in platforms.LOGOS:
            url = platforms.logo_url(alias)
            self.assertRegex(url, r"^/static/logos/[a-z0-9_]+\.(?:png|jpe?g|webp)$")

    def test_the_browser_cannot_name_a_logo_file(self):
        # A filename or a path is not an alias, so it resolves to nothing at all.
        for bad in ("../config", "netflix.jpg", "/etc/passwd", "logos/netflix", "", None, 7):
            self.assertEqual(platforms.logo_url(bad), "", repr(bad))

    def test_an_alias_is_matched_without_regard_to_case(self):
        # clean_alias normalizes before it looks up, the same way resolve() does, so the
        # catalogue answers consistently wherever an alias arrives from.
        alias = next(iter(platforms.LOGOS))
        self.assertEqual(platforms.logo_url(alias.upper()), platforms.logo_url(alias))

    def test_every_advertised_file_exists_and_is_typed(self):
        for url, (relative, content_type) in platforms.logo_files().items():
            path = platforms.LOGO_DIR.parent / relative
            self.assertTrue(path.is_file(), relative)
            self.assertIn(content_type, set(platforms.LOGO_TYPES.values()))
            self.assertTrue(url.endswith(path.name))

    def test_a_missing_directory_is_not_an_error(self):
        self.assertEqual(platforms.scan_logos(pathlib.Path("/nonexistent/logos")), {})

    def test_svg_is_not_served(self):
        # An SVG is a document that can carry script; a logo does not need to be one.
        self.assertNotIn(".svg", platforms.LOGO_TYPES)

    def test_tiles_and_catalogue_rows_both_carry_the_logo(self):
        store = prefs.Prefs(_config(), ("netflix",))
        for row in store.tiles() + store.catalog():
            self.assertIn("logo", row)


class PlatformCatalog(unittest.TestCase):
    """The quick-launch catalogue is data, and it has to keep the same promises as the code."""

    def test_every_package_is_one_adb_would_accept(self):
        # adb.py has its own package pattern; a catalogue entry that cannot pass it is a tile
        # that fails at the last moment, on the TV, for no reason the operator can see.
        pattern = re.compile(adb._PACKAGE_RE.pattern)  # noqa: SLF001 - that is the contract
        for platform in platforms.CATALOG.values():
            self.assertTrue(platform.packages, platform.alias)
            for package in platform.packages:
                self.assertRegex(package, pattern, f"{platform.alias}: {package}")

    def test_aliases_are_short_opaque_names(self):
        for alias, platform in platforms.CATALOG.items():
            self.assertEqual(alias, platform.alias)
            self.assertRegex(alias, platforms.ALIAS_RE)

    def test_the_defaults_are_the_five_that_were_asked_for(self):
        self.assertEqual(
            set(platforms.DEFAULT_ALIASES),
            {"netflix", "disney", "prime_video", "youtube", "hbo_max"},
        )

    def test_an_unknown_alias_is_not_a_platform(self):
        for bad in ("", "  ", "netflix; reboot", "../etc", "com.netflix.ninja", None, 7):
            self.assertEqual(platforms.clean_alias(bad), "")
            with self.assertRaises(platforms.UnknownPlatform):
                platforms.resolve(bad)

    def test_a_known_installed_package_wins_over_catalogue_order(self):
        platform = platforms.CATALOG["netflix"]
        self.assertEqual(
            platforms.launch_candidates(platform, {"com.netflix.mediaclient"}),
            ("com.netflix.mediaclient",),
        )

    def test_with_nothing_known_the_candidates_stay_in_order_and_bounded(self):
        platform = platforms.CATALOG["netflix"]
        candidates = platforms.launch_candidates(platform, frozenset())
        self.assertEqual(candidates[0], "com.netflix.ninja")
        self.assertLessEqual(len(candidates), platforms.MAX_LAUNCH_ATTEMPTS)


class QuickLaunchPrefs(unittest.TestCase):
    def setUp(self):
        self.config = _config()
        self.prefs = prefs.Prefs.load(self.config)

    def test_a_fresh_install_shows_the_defaults(self):
        self.assertEqual(self.prefs.quick_launch, tuple(platforms.DEFAULT_ALIASES))

    def test_a_choice_survives_a_reload(self):
        self.prefs.toggle_quick_launch("netflix", False)
        self.prefs.toggle_quick_launch("kodi", True)
        reloaded = prefs.Prefs.load(self.config)
        self.assertNotIn("netflix", reloaded.quick_launch)
        self.assertIn("kodi", reloaded.quick_launch)

    def test_the_stored_file_can_only_hold_catalogue_aliases(self):
        # A hand-edited file must not be able to introduce a package name or a shell word.
        self.prefs.set_quick_launch(["netflix", "not_a_platform", "com.evil.app", "", None])
        self.assertEqual(self.prefs.quick_launch, ("netflix",))

    def test_an_unknown_alias_cannot_be_toggled(self):
        with self.assertRaises(platforms.UnknownPlatform):
            self.prefs.toggle_quick_launch("not_a_platform", True)

    def test_tiles_are_drawn_in_catalogue_order_however_they_were_added(self):
        self.prefs.set_quick_launch(["kodi", "netflix", "disney"])
        self.assertEqual([tile["alias"] for tile in self.prefs.tiles()], ["netflix", "disney", "kodi"])

    def test_the_settings_list_always_offers_everything(self):
        self.prefs.set_quick_launch([])
        catalog = self.prefs.catalog()
        self.assertEqual(len(catalog), len(platforms.CATALOG))
        self.assertTrue(all(item["on"] is False for item in catalog))


class LoginNotices(unittest.TestCase):
    """`?e=` is a contract between api (which redirects) and views (which chooses the words)."""

    def test_the_two_halves_agree(self):
        self.assertEqual(api._LOGIN_NOTICE_CODES, frozenset(views.LOGIN_NOTICES))  # noqa: SLF001

    def test_an_invented_code_says_nothing(self):
        for bad in ("", "boom", "<script>", "bad_credentials!", None, 7):
            self.assertEqual(views.login_notice(bad), "")
        # Surrounding space is normalized away, not treated as a different code.
        self.assertEqual(views.login_notice(" bad_credentials "), "bad_credentials")

    def test_a_real_code_never_reflects_browser_text(self):
        for code, (tone, message) in views.LOGIN_NOTICES.items():
            self.assertIn(tone, {"error", "info"})
            self.assertTrue(message and "<" not in message, code)


if __name__ == "__main__":
    unittest.main()
