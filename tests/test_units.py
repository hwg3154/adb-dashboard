"""Unit tests for the pieces design.md §12 names: keycode map, text sanitizer, argv builder,
the RFC1918/loopback guard, candidate dedupe, and the quick-launch catalogue."""

from __future__ import annotations

import json
import pathlib
import re
import tempfile
import unittest

from tvdashboard import adb, api, keys, netguard, platforms, prefs, registry, textentry, views, wol
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
        # Sleep switches the TV off for everyone in the room, so it asks first.
        self.assertTrue(keys.KEY_ALIASES["sleep"].is_destructive)

    def test_power_is_gone_and_wake_is_not_a_keycode(self):
        # Power toggles, so it could turn off a TV you meant to turn on. Wake is a network
        # packet, not a key, so it must not exist in the key map at all.
        self.assertNotIn("power", keys.KEY_ALIASES)
        self.assertNotIn("wake", keys.KEY_ALIASES)
        self.assertEqual(keys.KEY_ALIASES["sleep"].keycode, "KEYCODE_SLEEP")

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


class WakeOnLan(unittest.TestCase):
    MAC = "d0:65:b3:27:38:0b"

    def test_a_mac_is_canonicalized_from_the_forms_tools_print(self):
        for raw in ("D0:65:B3:27:38:0B", "d0-65-b3-27-38-0b", "d065b327380b", "d0:65:b3:27:38:b"):
            self.assertEqual(netguard.normalize_mac(raw), self.MAC, raw)

    def test_a_mac_a_packet_must_not_be_built_from_is_refused(self):
        for bad in (
            "", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01",
            "d0:65:b3:27:38", "d0:65:b3:27:38:0b:aa", "zz:65:b3:27:38:0b",
            "d0:65-b3:27:38:0b", "(incomplete)", None, 42,
        ):
            self.assertEqual(netguard.normalize_mac(bad), "", repr(bad))

    def test_the_magic_packet_has_the_standard_shape(self):
        packet = wol.magic_packet(self.MAC)
        self.assertEqual(len(packet), 102)
        self.assertEqual(packet[:6], b"\xff" * 6)
        self.assertEqual(packet[6:], bytes.fromhex("d065b327380b") * 16)
        with self.assertRaises(ValueError):
            wol.magic_packet("ff:ff:ff:ff:ff:ff")

    def test_it_is_aimed_only_at_the_device_and_its_own_network(self):
        self.assertEqual(
            wol.destinations("192.168.12.42"),
            ("192.168.12.42", "192.168.12.255", "255.255.255.255"),
        )
        for bad in ("8.8.8.8", "127.0.0.1", "169.254.169.254", "not-an-ip", ""):
            self.assertEqual(wol.destinations(bad), (), bad)

    def test_the_mac_is_read_from_a_linux_arp_table(self):
        table = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.12.1     0x1         0x2         aa:bb:cc:dd:ee:02     *        eth0\n"
            "192.168.12.42    0x1         0x2         d0:65:b3:27:38:0b     *        eth0\n"
            "192.168.12.99    0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        )
        self.assertEqual(wol.parse_proc_arp(table, "192.168.12.42"), self.MAC)
        # An unresolved entry, or an address with no entry at all, yields nothing.
        self.assertEqual(wol.parse_proc_arp(table, "192.168.12.99"), "")
        self.assertEqual(wol.parse_proc_arp(table, "192.168.12.7"), "")

    def test_the_router_is_never_mistaken_for_the_tv(self):
        table = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.12.1     0x1         0x2         aa:bb:cc:dd:ee:02     *        eth0\n"
        )
        self.assertEqual(wol.parse_proc_arp(table, "192.168.12.42"), "")

    def test_the_mac_is_read_from_ip_neigh_and_from_macos_arp(self):
        self.assertEqual(
            wol.parse_ip_neigh("192.168.12.42 dev eth0 lladdr d0:65:b3:27:38:0b STALE\n", "192.168.12.42"),
            self.MAC,
        )
        self.assertEqual(wol.parse_ip_neigh("192.168.12.42 dev eth0 FAILED\n", "192.168.12.42"), "")
        # macOS drops an octet's leading zero.
        self.assertEqual(
            wol.parse_bsd_arp("? (192.168.12.42) at d0:65:b3:27:38:b on en0 ifscope [ethernet]\n", "192.168.12.42"),
            self.MAC,
        )
        self.assertEqual(
            wol.parse_bsd_arp("? (192.168.12.42) at (incomplete) on en0 ifscope [ethernet]\n", "192.168.12.42"),
            "",
        )

    def test_the_awake_check_only_ever_connects_to_a_private_address(self):
        attempts = []
        original = wol.socket.create_connection
        wol.socket.create_connection = lambda addr, timeout=None: attempts.append(addr) or _FakeConnection()
        try:
            for bad in ("8.8.8.8", "127.0.0.1", "169.254.169.254", "", "tv.local"):
                self.assertFalse(wol.is_awake(bad, 5555), bad)
            self.assertFalse(wol.is_awake("192.168.12.42", 0))
            self.assertFalse(wol.is_awake("192.168.12.42", True))
            self.assertEqual(attempts, [], "a refused address was still connected to")
            self.assertTrue(wol.is_awake("192.168.12.42", 5555))
            self.assertEqual(attempts, [("192.168.12.42", 5555)])
        finally:
            wol.socket.create_connection = original

    def test_a_tv_whose_adb_port_does_not_answer_is_asleep(self):
        def refuse(addr, timeout=None):
            raise ConnectionRefusedError()

        original = wol.socket.create_connection
        wol.socket.create_connection = refuse
        try:
            self.assertFalse(wol.is_awake("192.168.12.42", 5555))
        finally:
            wol.socket.create_connection = original

    def test_a_learned_mac_survives_a_reload(self):
        config = _config()
        reg = registry.Registry(config, devices={}, candidates={})
        device = reg.add("192.168.1.5:5555", model="TV")
        self.assertTrue(reg.set_mac(device.id, "D0-65-B3-27-38-0B"))
        self.assertEqual(registry.Registry.load(config).get(device.id).mac, self.MAC)

    def test_a_registry_file_from_before_wake_existed_still_loads(self):
        config = _config()
        reg = registry.Registry(config, devices={}, candidates={})
        device = reg.add("192.168.1.5:5555", model="TV")
        path = pathlib.Path(config.data_dir) / registry.REGISTRY_FILE
        payload = json.loads(path.read_text())
        payload["devices"][device.id].pop("mac", None)
        path.write_text(json.dumps(payload))
        reloaded = registry.Registry.load(config).get(device.id)
        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded.mac, "")


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


class _FakeConnection:
    """Stands in for a socket from `create_connection` in a `with` block."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


if __name__ == "__main__":
    unittest.main()
