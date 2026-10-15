import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "service.harpywing", "resources", "lib"))

from harpywing import core  # noqa: E402

LIBREELEC_HOSTS = "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\n127.0.1.1\tCoreELEC\n"
# Real `netbird status --json` of an unenrolled 0.80.0 daemon on the box.
NEEDS_LOGIN = (
    '{"peers":{"total":0,"connected":0,"details":null},"cliVersion":"0.80.0",'
    '"daemonVersion":"0.80.0","daemonStatus":"NeedsLogin","management":'
    '{"url":"https://api.netbird.io:443","connected":false,"error":""},'
    '"netbirdIp":"","profileName":"default"}'
)


class HostsTest(unittest.TestCase):
    def test_adds_one_block_and_keeps_system_lines(self):
        once = core.apply_hosts(LIBREELEC_HOSTS, "Media.example.net", "100.80.166.134")
        twice = core.apply_hosts(once, "media.example.net", "100.80.166.134")
        self.assertEqual(once, twice)
        self.assertTrue(once.startswith(LIBREELEC_HOSTS.rstrip("\n")))
        self.assertIn("100.80.166.134 media.example.net\n", once)
        self.assertEqual(once.count(core.HOSTS_BEGIN), 1)

    def test_change_and_removal(self):
        first = core.apply_hosts(LIBREELEC_HOSTS, "media.example.net", "100.80.166.134")
        moved = core.apply_hosts(first, "media.example.net", "100.80.1.2")
        self.assertNotIn("100.80.166.134", moved)
        self.assertEqual(core.apply_hosts(moved), LIBREELEC_HOSTS)


class MappingTest(unittest.TestCase):
    def test_accepts_netbird_address(self):
        self.assertEqual(core.validate_mapping("media.example.net", "100.80.166.134"), "")
        self.assertEqual(core.validate_mapping("", ""), "")

    def test_refuses_lan_public_or_garbage(self):
        self.assertEqual(core.validate_mapping("media.example.net", "192.0.2.10"), "bad_address")
        self.assertEqual(core.validate_mapping("media.example.net", "8.8.8.8"), "bad_address")
        self.assertEqual(core.validate_mapping("media.example.net", "nope"), "bad_address")
        self.assertEqual(core.validate_mapping("media example", "100.80.166.134"), "bad_name")
        self.assertEqual(core.validate_mapping("", "100.80.166.134"), "bad_name")


class CommandTest(unittest.TestCase):
    def test_box_reaches_the_server_only(self):
        args = core.up_args("https://vpn.example.net", "living-room", "/run/k")
        for flag in ("--disable-dns", "--disable-client-routes", "--disable-server-routes", "--block-inbound"):
            self.assertIn(flag, args)
        self.assertEqual(args[args.index("--setup-key-file") + 1], "/run/k")
        self.assertNotIn("--setup-key-file", core.up_args("https://x"))

    def test_unit_is_inert_without_the_addon(self):
        unit = core.render_unit("/storage/.kodi/addons/service.harpywing")
        self.assertIn("ConditionPathExists=/storage/.kodi/addons/service.harpywing/bin/netbird", unit)
        self.assertIn("WantedBy=multi-user.target", unit)
        # Auto-restart skips conditions: a missing script (203) must not loop.
        self.assertIn("RestartPreventExitStatus=203", unit)


class FillTest(unittest.TestCase):
    def test_formats_and_survives_missing_or_wrong_strings(self):
        self.assertEqual(core.fill("State: %s", "Connected"), "State: Connected")
        self.assertEqual(core.fill("", "Connected"), "Connected")
        self.assertEqual(core.fill("Plain", "x"), "Plain x")
        self.assertEqual(core.fill("Plain"), "Plain")


class StatusTest(unittest.TestCase):
    def test_real_unenrolled_output(self):
        self.assertEqual(core.parse_status(NEEDS_LOGIN)["daemon"], "NeedsLogin")

    def test_link_type_of_connected_peer(self):
        details = '{"peers":{"details":[{"status":"Idle","connectionType":"-"},' \
            '{"status":"Connected","connectionType":"Relayed"}]}}'
        self.assertEqual(core.server_link(details), "Relayed")
        self.assertEqual(core.server_link(NEEDS_LOGIN), "")
        self.assertEqual(core.server_link("not json"), "")

    def test_daemon_down(self):
        status = core.parse_status("failed to connect to daemon error: context deadline exceeded")
        self.assertEqual(status["daemon"], "Unavailable")


if __name__ == "__main__":
    unittest.main()
