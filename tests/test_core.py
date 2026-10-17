import os
import sys
import struct
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
    def test_cache_server_header_is_ignored(self):
        self.assertEqual(core.hosts_mappings('# server https://example.net:443\n100.80.0.1 media.example.net\n'),
                         [('media.example.net', '100.80.0.1')])

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
    def test_mixed_names_and_forced_addresses(self):
        self.assertEqual(core.parse_names(' Media.example.net ; fixed=100.64.0.1'),
                         [('media.example.net', None), ('fixed', '100.64.0.1')])
        for value in ('name=', 'name;NAME=100.64.0.1', ';name', 'name;', 'name=ip=extra'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                core.parse_names(value)

    def test_accepts_netbird_address(self):
        self.assertEqual(core.validate_mapping("media.example.net", "100.80.166.134"), "")
        self.assertEqual(core.validate_mapping("", ""), "")

    def test_refuses_lan_public_or_garbage(self):
        self.assertEqual(core.validate_mapping("media.example.net", "192.0.2.10"), "bad_address")
        self.assertEqual(core.validate_mapping("media.example.net", "8.8.8.8"), "bad_address")
        self.assertEqual(core.validate_mapping("media.example.net", "nope"), "bad_address")
        self.assertEqual(core.validate_mapping("media example", "100.80.166.134"), "bad_name")
        self.assertEqual(core.validate_mapping("", "100.80.166.134"), "bad_name")


class DNSTest(unittest.TestCase):
    def record(self, owner, kind, data):
        return core.dns_query(owner, 123)[12:-4] + struct.pack('!HHIH', kind, 1, 0, len(data)) + data

    def packet(self, records):
        query = core.dns_query('media.example.net', 123)
        return struct.pack('!6H', 123, 0x8180, 1, len(records), 0, 0) + query[12:] + b''.join(records)

    def test_cname_conflicts_and_terminal_address(self):
        name, terminal = 'media.example.net', 'alias.example.net'
        cname = self.record(name, 5, core.dns_query(terminal, 123)[12:-4])
        address = self.record(terminal, 1, b'\x64\x50\0\2')
        alternate = self.record(name, 5, core.dns_query('other.example.net', 123)[12:-4])
        for conflict in (self.record(name, 1, b'\x64\x50\0\1'), alternate):
            for records in ([cname, conflict, address], [conflict, cname, address]):
                with self.subTest(records=records), self.assertRaises(ValueError):
                    core.dns_address(self.packet(records), name, 123)
        with self.assertRaisesRegex(ValueError, 'duplicate DNS CNAME owner'):
            core.dns_address(self.packet([cname, cname, address]), name, 123)
        with self.assertRaises(ValueError):
            core.dns_address(self.packet([cname, self.record('other.example.net', 1, b'\x64\x50\0\3')]), name, 123)

    def test_cname_chain_limit(self):
        for count in (8, 9):
            names = ['media.example.net'] + ['alias%d.example.net' % i for i in range(count)]
            records = [self.record(owner, 5, core.dns_query(target, 123)[12:-4])
                       for owner, target in zip(names, names[1:])]
            records.append(self.record(names[-1], 1, b'\x64\x50\0\2'))
            if count == 8:
                self.assertEqual(core.dns_address(self.packet(records), names[0], 123), '100.80.0.2')
            else:
                with self.assertRaisesRegex(ValueError, 'too many DNS CNAMEs'):
                    core.dns_address(self.packet(records), names[0], 123)

    def test_record_and_compression_limits(self):
        record = self.record('media.example.net', 1, b'\x64\x50\0\2')
        self.assertEqual(core.dns_address(self.packet([record] * 32), 'media.example.net', 123), '100.80.0.2')
        with self.assertRaisesRegex(ValueError, 'too many DNS records'):
            core.dns_address(self.packet([record] * 33), 'media.example.net', 123)
        with self.assertRaisesRegex(ValueError, 'too many DNS records'):
            core.dns_address(struct.pack('!6H', 123, 0x8180, 1, 1, 16, 16), 'media.example.net', 123)
        for count in (16, 17):
            pointers = b''.join(struct.pack('!H', 0xc000 | (offset + 2)) for offset in range(0, count * 2, 2))
            if count == 16:
                self.assertEqual(core._dns_name(pointers + b'\x01a\0', 0), ('a', 2))
            else:
                with self.assertRaisesRegex(ValueError, 'compression jumps'):
                    core._dns_name(pointers + b'\x01a\0', 0)

    def test_query_and_compressed_cname_answers(self):
        query = core.dns_query('media.example.net', 123)
        self.assertEqual(query[:12], struct.pack('!6H', 123, 0x100, 1, 0, 0, 0))
        self.assertEqual(query[12:], b'\x05media\x07example\x03net\0\0\1\0\1')
        # CNAME alias.example.net: its suffix points into the question.
        alias = b'\x05alias\xc0\x12'
        cname = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 30, len(alias)) + alias
        pointer = struct.pack('!H', 0xc000 | (len(query) + 12))
        records = b''
        for owner, address in ((b'\x05other\0', b'\x64\x50\0\x09'),
                               (pointer, b'\xc0\xa8\0\1'),
                               (pointer, b'\x64\x50\xa6\x86'),
                               (pointer, b'\x64\x50\0\x02')):
            records += owner + struct.pack('!HHIH', 1, 1, 30, 4) + address
        packet = struct.pack('!6H', 123, 0x8180, 1, 5, 0, 0) + query[12:] + cname + records
        self.assertEqual(core.dns_address(packet, 'media.example.net', 123), '100.80.166.134')


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
    def test_management_origin_normalization(self):
        for url in ('https://EXAMPLE.NET', 'https://example.net:443/', 'HTTPS://example.net/'):
            self.assertEqual(core.normalize_server(url), 'https://example.net:443')
        self.assertEqual(core.normalize_server('https://example.net:8443'), 'https://example.net:8443')
        for url in ('http://example.net', 'https://example.net/path', None):
            self.assertEqual(core.normalize_server(url), '')

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
