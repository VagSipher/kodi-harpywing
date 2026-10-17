"""Exercise identity / update operations with Kodi and system commands stubbed."""
import importlib
import json
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
import subprocess
import socket
import struct
import threading
import time
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
# Temporary test trees live in build/ (ignored): absent in a fresh clone.
(ROOT / 'build').mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / 'service.harpywing/resources/lib'))


def dns_reply(query, addresses=('100.80.166.134',), flags=0x8180):
    records = b''.join(b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4)
                       + socket.inet_aton(ip) for ip in addresses)
    return query[:2] + struct.pack('!5H', flags, 1, len(addresses), 0, 0) + query[12:] + records


@contextmanager
def udp_dns(reply=dns_reply):
    """A real local UDP endpoint; no socket-module mocking in DNS tests."""
    requests, errors = [], []
    stopped = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('127.0.0.1', 0))
        server.settimeout(0.1)
        def serve():
            while not stopped.is_set():
                try:
                    query, source = server.recvfrom(65535)
                except socket.timeout:
                    continue
                try:
                    requests.append(query)
                    packet = reply(query)
                    if packet is not None:
                        server.sendto(packet, source)
                except Exception as exc:
                    errors.append(exc)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield server.getsockname(), requests
        finally:
            stopped.set()
            thread.join(3)
            if thread.is_alive():
                raise AssertionError('DNS test server did not stop')
            if errors:
                raise errors[0]


class RuntimeTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(dir=ROOT / 'build')
        self.addCleanup(self.folder.cleanup)
        self.addon = Mock()
        values = {'path': str(ROOT / 'service.harpywing'), 'profile': self.folder.name, 'version': '0.4.1+nb0.80.0'}
        self.addon.getAddonInfo.side_effect = values.get
        self.addon.getSetting.return_value = ''
        self.addon.getSettingBool.return_value = False
        self.addon.getLocalizedString.return_value = '%s'
        xbmc = types.SimpleNamespace(LOGINFO=1, LOGERROR=4, log=Mock())
        gui = types.SimpleNamespace(Window=Mock(), Dialog=Mock(), DialogProgress=Mock(), NOTIFICATION_ERROR=1, NOTIFICATION_INFO=2)
        modules = {'xbmc': xbmc, 'xbmcgui': gui, 'xbmcaddon': types.SimpleNamespace(Addon=Mock(return_value=self.addon)), 'xbmcvfs': types.SimpleNamespace(translatePath=lambda path: path)}
        self.modules = patch.dict(sys.modules, modules)
        self.modules.start()
        self.addCleanup(self.modules.stop)
        sys.modules.pop('harpywing.runtime', None)
        self.rt = importlib.import_module('harpywing.runtime')
        self.addCleanup(lambda: sys.modules.pop('harpywing.runtime', None))
        self.rt.PRIVATE = self.folder.name + '/private'
        Path(self.rt.PRIVATE).mkdir()
        self.rt.DATA = self.folder.name + '/legacy'
        self.rt.USER_CONFIG = os.path.join(self.rt.PRIVATE, 'state', 'user-config')
        self.rt.LEGACY_STATE_LINK = self.folder.name + '/legacy-link'
        self.rt.SYS_NET = self.folder.name + '/sys-net'
        Path(self.rt.SYS_NET).mkdir()
        self.rt.BOOT_ID = self.folder.name + '/boot_id'
        Path(self.rt.BOOT_ID).write_text('boot-1\n')

    def hosts_file(self):
        self.rt.HOSTS = self.folder.name + '/system-hosts'
        path = Path(self.rt.HOSTS)
        path.write_text('127.0.0.1 localhost\n')
        return path

    def cache_text(self, entries):
        return '# server %s\n' % self.rt.core.normalize_server(self.rt.options()['management_url']) + entries

    def test_guard_restores_block_after_coreelec_rewrite_without_dns(self):
        rt = self.rt
        hosts = self.hosts_file()
        rt.save_file('hosts', self.cache_text('100.80.0.1 media.example.net\n100.80.0.2 fixed.example.net\n'))
        hosts.write_text('127.0.0.1 localhost\n# copied from hosts.conf\n')  # CoreELEC at Kodi start
        with patch.object(rt, '_dns_server', side_effect=AssertionError('no DNS in the guard')):
            self.assertTrue(rt.guard_hosts())
        text = hosts.read_text()
        self.assertIn('# copied from hosts.conf\n', text)
        self.assertIn('100.80.0.1 media.example.net\n100.80.0.2 fixed.example.net\n', text)
        # Intact block: no write and no lock (the lock logs a line every time).
        with patch.object(rt, 'Operation', side_effect=AssertionError('no lock when intact')):
            self.assertFalse(rt.guard_hosts())
        self.assertEqual(hosts.read_text(), text)

    def test_guard_yields_to_a_running_operation_and_ignores_invalid_cache_lines(self):
        rt = self.rt
        hosts = self.hosts_file()
        rt.save_file('hosts', self.cache_text('8.8.8.8 evil.example.net\nbroken\n100.80.0.1 media.example.net\n'))
        with rt.Operation('wizard'):
            self.assertFalse(rt.guard_hosts())
        self.assertEqual(hosts.read_text(), '127.0.0.1 localhost\n')
        self.assertTrue(rt.guard_hosts())
        self.assertNotIn('evil', hosts.read_text())
        self.assertIn('100.80.0.1 media.example.net', hosts.read_text())
        # Names turned off (empty cache): a leftover block is removed like at boot.
        rt.save_file('hosts', self.cache_text(''))
        self.assertTrue(rt.guard_hosts())
        self.assertEqual(hosts.read_text(), '127.0.0.1 localhost\n')
        # No block and no names: another program's formatting is left alone.
        hosts.write_text('127.0.0.1 localhost\n\n\n')
        self.assertFalse(rt.guard_hosts())
        self.assertEqual(hosts.read_text(), '127.0.0.1 localhost\n\n\n')

    def test_udp_names_mixed_with_forced_address_and_no_rewrite(self):
        rt = self.rt
        hosts = self.hosts_file()
        mappings = rt.core.parse_names('media.example.net;fixed=100.64.0.1')
        with udp_dns() as (endpoint, requests), patch.object(rt, '_dns_server', return_value=endpoint):
            rt.write_hosts(mappings)
            self.assertIn('100.80.166.134 media.example.net\n100.64.0.1 fixed\n', hosts.read_text())
            self.assertEqual(rt.read_file('hosts'), self.cache_text('100.80.166.134 media.example.net\n100.64.0.1 fixed\n'))
            with patch.object(rt, 'save_file') as save, patch.object(rt.os, 'replace') as replace:
                rt.write_hosts(mappings)
            save.assert_not_called()
            replace.assert_not_called()
            self.assertEqual(len(requests), 2)
            self.assertTrue(all(rt.core._dns_name(q, 12)[0] == 'media.example.net' for q in requests))
        with patch.object(rt, '_dns_server', side_effect=AssertionError('forced address queried DNS')):
            rt.write_hosts([('fixed', '100.64.0.1')])

    def test_udp_failure_keeps_valid_saved_address_and_logs_state_changes(self):
        rt = self.rt
        hosts = self.hosts_file()
        mappings = rt.core.parse_names('media.example.net;never-resolved')
        rt.save_file('hosts', self.cache_text('100.80.0.1 media.example.net\n'))
        for reply in (lambda q: dns_reply(q, ('8.8.8.8',)),
                      lambda q: dns_reply(q, (), 0x8183)):
            with self.subTest(reply=reply), udp_dns(reply) as (endpoint, requests), \
                    patch.object(rt, '_dns_server', return_value=endpoint), patch.object(rt, 'log') as log:
                rt.write_hosts(mappings)
                rt.write_hosts(mappings)
                self.assertEqual(sum('DNS failed' in call.args[0] for call in log.call_args_list), 2)
                self.assertIn('100.80.0.1 media.example.net\n', hosts.read_text())
                self.assertNotIn('never-resolved', hosts.read_text())
                self.assertEqual(rt.read_file('hosts'), self.cache_text('100.80.0.1 media.example.net\n'))
        with udp_dns() as (endpoint, requests), patch.object(rt, '_dns_server', return_value=endpoint), \
                patch.object(rt, 'log') as log:
            rt.write_hosts(mappings)
            rt.write_hosts(mappings)
            self.assertEqual(sum('resolved to' in call.args[0] for call in log.call_args_list), 2)

    def test_dns_timeout_and_disconnected_status_keep_previous_address(self):
        rt = self.rt
        hosts = self.hosts_file()
        names = ['media.example.net'] + ['name%d.example.net' % i for i in range(29)]
        original_server = rt._dns_server
        def status(timeout):
            self.assertGreater(timeout, 2.5)
            self.assertLessEqual(timeout, 3)
            time.sleep(0.6)  # Included in the same three-second deadline.
            return '{"daemonStatus":"Connected","netbirdIp":"100.80.0.2/16","management":{"url":"https://example.net:443"}}'
        self.addon.getSetting.side_effect = lambda key: 'https://example.net' if key == 'management_url' else ''
        saved = self.cache_text(''.join('100.80.0.1 %s\n' % name for name in names))
        rt.save_file('hosts', saved)
        with udp_dns(lambda q: None) as (endpoint, requests):
            def server(timeout, management_url):
                self.assertEqual(original_server(timeout, management_url), ('100.80.0.2', 53))
                return endpoint
            with patch.object(rt, 'status_json', side_effect=status), patch.object(rt, '_dns_server', side_effect=server):
                started = time.monotonic()
                rt.write_hosts([(name, None) for name in names])
                elapsed = time.monotonic() - started
            self.assertLessEqual(elapsed, 3.5)
            self.assertEqual(len(requests), 1)
            self.assertEqual(rt.read_file('hosts'), saved)
        self.assertIn('100.80.0.1 media.example.net\n', hosts.read_text())
        mappings = rt.core.parse_names('media.example.net')
        for status in ('{"daemonStatus":"NeedsLogin","netbirdIp":"100.80.0.2/16"}',
                       '{"daemonStatus":"Connected","netbirdIp":""}',
                       '{"daemonStatus":"Connected","netbirdIp":"192.168.0.1/24"}', 'unavailable', '[]'):
            with self.subTest(status=status), patch.object(rt, 'status_json', return_value=status):
                rt.write_hosts(mappings)
            self.assertIn('100.80.0.1 media.example.net\n', hosts.read_text())
        with patch.object(rt, 'status_json', return_value='{"daemonStatus":"Connected","netbirdIp":"100.80.0.2/16","management":{"url":"https://EXAMPLE.NET:443"}}'):
            self.assertEqual(rt._dns_server(), ('100.80.0.2', 53))

    def test_invalid_cache_is_empty_and_off_never_reads_it(self):
        rt = self.rt
        hosts = self.hosts_file()
        cache = Path(rt.PRIVATE, 'hosts')
        header = self.cache_text('').encode()
        for content in (b'\xff', b'bad cache\n', b'8.8.8.8 media.example.net\n',
                        b'100.80.0.1 media.example.net\n100.80.0.2 MEDIA.EXAMPLE.NET\n'):
            with self.subTest(content=content):
                cache.write_bytes(header + content)
                with patch.object(rt, '_dns_server', side_effect=ValueError('offline')), patch.object(rt, 'log') as log:
                    rt.write_hosts([('media.example.net', None)])
                self.assertTrue(any('ignoring' in call.args[0] for call in log.call_args_list))
                self.assertNotIn('media.example.net', hosts.read_text())
                self.assertEqual(cache.read_bytes(), header)
                cache.write_bytes(header + content)
                with patch.object(rt, 'read_file', side_effect=AssertionError('Off read the cache')):
                    rt.write_hosts([])
                self.assertEqual(cache.read_bytes(), header)
                cache.write_bytes(header + content)
                with patch.object(rt, '_dns_server', side_effect=AssertionError('forced address queried DNS')):
                    rt.write_hosts([('fixed.example.net', '100.80.0.2')])
                self.assertEqual(cache.read_text(), self.cache_text('100.80.0.2 fixed.example.net\n'))

    def test_dns_cache_requires_matching_management_server(self):
        rt = self.rt
        self.hosts_file()
        self.addon.getSetting.side_effect = lambda key: 'https://example.net' if key == 'management_url' else ''
        mappings = [('media.example.net', None), ('fixed.example.net', '100.80.0.2')]
        entries = '100.80.0.1 media.example.net\n'
        for header in ('', '# server https://old.example.net:443\n', '# server invalid\n'):
            rt.save_file('hosts', header + entries)
            with self.subTest(header=header), patch.object(rt, '_dns_server', side_effect=ValueError('offline')):
                self.assertEqual(rt.resolve_names(mappings), [mappings[1]])
        rt.save_file('hosts', self.cache_text(entries))
        rt.save_file('options.json', '{"management_url":"https://old.example.net"}')
        with patch.object(rt, '_dns_server', side_effect=ValueError('offline')):
            self.assertEqual(rt.resolve_names(mappings), [('media.example.net', '100.80.0.1'), mappings[1]])
            self.addon.getSetting.side_effect = lambda key: 'https://new.example.net' if key == 'management_url' else ''
            rt.write_hosts(mappings)
        self.assertEqual(rt.read_file('hosts'), self.cache_text('100.80.0.2 fixed.example.net\n'))

    def test_server_transition_never_relabels_or_reuses_old_dns_address(self):
        rt = self.rt
        hosts = self.hosts_file()
        configured = ['https://a.example.net']
        daemon = ['https://A.EXAMPLE.NET:443/']
        self.addon.getSetting.side_effect = lambda key: configured[0] if key == 'management_url' else ''
        def status(timeout):
            return json.dumps({'daemonStatus': 'Connected', 'netbirdIp': '100.80.0.2/16',
                               'management': {'url': daemon[0]}})
        original_server = rt._dns_server
        silent = [False]
        with udp_dns(lambda q: None if silent[0] else dns_reply(q)) as (endpoint, requests):
            def server(timeout, management_url):
                original_server(timeout, management_url)
                return endpoint
            with patch.object(rt, 'status_json', side_effect=status), patch.object(rt, '_dns_server', side_effect=server):
                rt.write_hosts([('media.example.net', None)])
                self.assertEqual(rt.read_file('hosts'), '# server https://a.example.net:443\n100.80.166.134 media.example.net\n')
                self.assertEqual(len(requests), 1)
                configured[0] = 'https://b.example.net'
                with self.assertRaisesRegex(ValueError, 'NetBird is connected to another server'):
                    original_server()
                rt.write_hosts([('media.example.net', None)])
                self.assertEqual(len(requests), 1)
                self.assertNotIn('media.example.net', hosts.read_text())
                rt.save_file('options.json', json.dumps(rt.options()))  # Reconnection records B.
                daemon[0] = configured[0] + ':443'
                silent[0] = True
                rt.write_hosts([('media.example.net', None)])
                self.assertEqual(len(requests), 2)
                self.assertNotIn('media.example.net', hosts.read_text())
                self.assertEqual(rt.read_file('hosts'), '# server https://b.example.net:443\n')

    def test_cache_unused_while_daemon_reports_another_server(self):
        rt = self.rt
        self.hosts_file()
        self.addon.getSetting.side_effect = lambda key: 'https://b.example.net' if key == 'management_url' else ''
        rt.save_file('hosts', '# server https://b.example.net:443\n100.80.0.1 media.example.net\n')
        status = json.dumps({'daemonStatus': 'Connected', 'netbirdIp': '100.80.0.2/16',
                             'management': {'url': 'https://a.example.net:443'}})
        with udp_dns(dns_reply) as (endpoint, requests), patch.object(rt, 'status_json', return_value=status):
            self.assertEqual(rt.resolve_names([('media.example.net', None)]), [])
            self.assertEqual(requests, [])
        with patch.object(rt, '_dns_server', side_effect=ValueError('offline')):
            self.assertEqual(rt.resolve_names([('media.example.net', None)]), [('media.example.net', '100.80.0.1')])

    def test_server_snapshot_survives_setting_change_during_dns(self):
        rt = self.rt
        self.hosts_file()
        configured = ['https://a.example.net']
        self.addon.getSetting.side_effect = lambda key: configured[0] if key == 'management_url' else ''
        def reply(query):
            configured[0] = 'https://b.example.net'
            return dns_reply(query)
        with udp_dns(reply) as (endpoint, requests), patch.object(rt, '_dns_server', return_value=endpoint):
            rt.write_hosts([('media.example.net', None)])
        self.assertTrue(rt.read_file('hosts').startswith('# server https://a.example.net:443\n'))
        self.assertEqual(rt._cached_names(rt.core.normalize_server(configured[0])), {})

    def test_hosts_conflicts_include_aliases_and_warn_once_per_setting_value(self):
        rt = self.rt
        hosts = self.hosts_file()
        original = '127.0.0.1 localhost\n100.80.0.9 other MEDIA.EXAMPLE.NET. # alias\n'
        hosts.write_text(original)
        self.addon.getSetting.return_value = 'media.example.net=100.80.0.1'
        mappings = rt.core.parse_names(self.addon.getSetting.return_value)
        with patch.object(rt, 'notify') as notify:
            rt.write_hosts(mappings)
            rt.write_hosts(mappings)
            notify.assert_called_once_with(32089, 'media.example.net')
            self.assertTrue(hosts.read_text().startswith(original))
            self.addon.getSetting.return_value += ';other=100.80.0.3'
            rt.write_hosts(mappings)
            self.assertEqual(notify.call_count, 2)
            self.assertTrue(hosts.read_text().startswith(original))
            hosts.write_text(rt.core.apply_hosts('127.0.0.1 localhost\n', mappings=mappings))
            rt.write_hosts(mappings)
            self.assertEqual(notify.call_count, 2)
            hosts.write_text(original)
            self.addon.getSetting.return_value = 'media.example.net'
            with patch.object(rt, '_dns_server', side_effect=ValueError('disconnected')):
                rt.write_hosts(rt.core.parse_names('media.example.net'))
                rt.write_hosts(rt.core.parse_names('media.example.net'))
            self.assertEqual(notify.call_count, 3)
            self.assertTrue(hosts.read_text().startswith(original))
        self.assertEqual(rt.core.apply_hosts(rt.core.apply_hosts(original, mappings=mappings)), original)

    def test_setup_key_file_mode_and_cleanup_even_on_failure(self):
        rt = self.rt
        real_mkstemp = tempfile.mkstemp
        paths = []
        def local_temp(*args, **kwargs):
            self.assertEqual(kwargs['dir'], '/run')
            kwargs['dir'] = self.folder.name
            fd, path = real_mkstemp(*args, **kwargs)
            paths.append(path)
            return fd, path
        def netbird(*args, **kwargs):
            path = args[args.index('--setup-key-file') + 1]
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(Path(path).read_text(), 'ephemeral-key')
            self.assertNotIn('ephemeral-key', args)
            return 1, 'enrollment failed'
        self.addon.getSetting.side_effect = lambda key: 'ephemeral-key' if key == 'setup_key' else ''
        with patch.object(rt.tempfile, 'mkstemp', side_effect=local_temp), patch.object(rt, 'wait_for_daemon', return_value={'daemon': 'NeedsLogin'}), patch.object(rt, 'netbird', side_effect=netbird):
            self.assertEqual(rt.connect(Mock(), 'ephemeral-key'), (False, 'enrollment failed'))
        self.assertFalse(Path(paths[0]).exists())
        self.addon.setSetting.assert_called_with('setup_key', '')

    def test_netbird_cli_keeps_account_email_inside_identity(self):
        rt = self.rt
        with patch.object(rt.subprocess, 'run', return_value=Mock(returncode=0, stdout='', stderr='')) as run:
            rt.netbird('status')
        env = run.call_args.kwargs['env']
        self.assertEqual(env['XDG_CONFIG_HOME'], os.path.join(rt.PRIVATE, 'state', 'user-config'))
        # The email file NetBird writes there is erased with the identity.
        email = Path(env['XDG_CONFIG_HOME'], 'netbird', 'default.state.json')
        email.parent.mkdir(parents=True)
        email.write_text('{"email": "previous@example.org"}')
        with patch.object(rt, 'certainly_stopped', return_value=True), patch.object(rt, 'netbird', return_value=(0, '')), patch.object(rt, 'remove_unit'), patch.object(rt, 'write_hosts'):
            rt.forget_identity()
        self.assertFalse(email.exists())
        daemon = (ROOT / 'service.harpywing/bin/harpywing-daemon').read_text()
        self.assertIn('export XDG_CONFIG_HOME="$STATE_DIR/user-config"', daemon)

    def test_write_never_reverts_a_change_made_by_another_script(self):
        # Kodi (seen on the box, 0.2.4): each Addon() loads its own copy once
        # and setSetting() saves that whole copy.
        store = {'enabled': 'true', 'setup_key': 'leftover'}
        class KodiAddon:
            def __init__(self, *args):
                self.copy = dict(store)
            def getSetting(self, key):
                return self.copy.get(key, '')
            def setSetting(self, key, value):
                self.copy[key] = value
                store.clear()
                store.update(self.copy)
        with patch.object(self.rt.xbmcaddon, 'Addon', KodiAddon):
            wizard_copy = self.rt.settings()          # loaded when the wizard starts
            KodiAddon().setSetting('enabled', 'false')  # Off from the settings screen
            self.rt.set_setting('setup_key', '')      # the wizard's final erase
            self.assertEqual(store, {'enabled': 'false', 'setup_key': ''})
            self.assertEqual(wizard_copy.getSetting('enabled'), 'true')

    def test_update_restarts_once_and_keeps_previous_version(self):
        rt = self.rt
        rt.UNIT_PATH = self.folder.name + '/service.harpywing.service'
        Path(rt.UNIT_PATH).write_text(rt.core.render_unit(rt.ADDON_DIR))
        rt.save_file('version', '0.1.0')
        with patch.object(rt, 'run', return_value=(0, '')) as run:
            rt.install_unit()
            self.assertIn(['systemctl', 'restart', rt.core.UNIT_NAME], [call.args[0] for call in run.call_args_list])
            self.assertEqual(rt.read_file('previous-version'), '0.1.0')
            self.assertEqual(rt.read_file('version'), '0.4.1+nb0.80.0')
            run.reset_mock()
            rt.install_unit()
            self.assertNotIn(['systemctl', 'restart', rt.core.UNIT_NAME], [call.args[0] for call in run.call_args_list])

    def test_reconnect_without_key_uses_new_options(self):
        rt = self.rt
        self.addon.getSetting.side_effect = lambda key: {'management_url': 'https://vpn.example.net', 'device_name': 'TV'}.get(key, '')
        self.addon.getSettingBool.return_value = True
        with patch.object(rt, 'wait_for_daemon', return_value={'daemon': 'Idle'}), patch.object(rt, 'status', return_value={'daemon': 'Connected'}), patch.object(rt, 'netbird', return_value=(0, '')) as netbird:
            self.assertTrue(rt.connect(Mock())[0])
            args = netbird.call_args.args
            self.assertNotIn('--setup-key-file', args)
            self.assertIn('--disable-client-routes=false', args)
            self.assertIn('--block-inbound=false', args)

    def test_forget_identity_down_before_stopping_and_erasing(self):
        rt = self.rt
        state = Path(rt.PRIVATE) / 'state'
        state.mkdir();(state / 'default.json').write_text('fake identity')
        events = []
        def down(*args, **kwargs):
            self.assertEqual(args, ('down',));events.append('down');return 0, ''
        def stop():
            self.assertTrue(state.exists());events.append('stop')
        with patch.object(rt, 'certainly_stopped', side_effect=[False, True]), patch.object(rt, 'netbird', side_effect=down), patch.object(rt, 'remove_unit', side_effect=stop), patch.object(rt, 'write_hosts') as hosts:
            rt.forget_identity()
        self.assertEqual(events, ['down', 'stop'])
        self.assertFalse(state.exists())
        hosts.assert_called_once_with()
        self.addon.setSetting.assert_any_call('enabled', 'false')

    def test_upgrade_from_untracked_unit_restarts(self):
        rt = self.rt
        rt.UNIT_PATH = self.folder.name + '/service.harpywing.service'
        Path(rt.UNIT_PATH).write_text(rt.core.render_unit(rt.ADDON_DIR))
        with patch.object(rt, 'run', return_value=(0, '')) as run:
            rt.install_unit()
        self.assertIn(['systemctl', 'restart', rt.core.UNIT_NAME], [call.args[0] for call in run.call_args_list])
        self.assertEqual(rt.read_file('previous-version'), 'unknown')

    def test_separate_kodi_scripts_in_same_process_cannot_overlap(self):
        # Kodi scripts can share one OS process; lockf would not isolate them.
        with self.rt.Operation() as first:
            self.assertTrue(first)
            with self.rt.Operation() as second:
                self.assertFalse(second)
        with self.rt.Operation() as after:
            self.assertTrue(after)

    def test_lock_has_no_gui_dependency_even_when_kodi_gui_raises(self):
        with patch.object(self.rt.xbmcgui, 'Window', side_effect=RuntimeError('GUI unavailable')) as window:
            with self.rt.Operation() as acquired:
                self.assertTrue(acquired)
            with self.rt.Operation() as again:
                self.assertTrue(again)
        window.assert_not_called()

    def test_body_exception_cancel_and_kodi_abort_release_lock(self):
        for error in (RuntimeError('failure'), KeyboardInterrupt(), SystemExit()):
            operation = self.rt.Operation()
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(type(error)):
                    with operation as acquired:
                        self.assertTrue(acquired)
                        raise error
                self.assertIsNone(operation.stream)
                with self.rt.Operation() as after:
                    self.assertTrue(after)

    def test_enter_logging_exception_releases_lock(self):
        # __exit__ never runs when __enter__ raises, so it must clean up itself.
        operation = self.rt.Operation()
        with patch.object(self.rt, 'log', side_effect=RuntimeError('logging unavailable')):
            with self.assertRaises(RuntimeError):
                with operation:
                    self.fail('unreachable')
        self.assertIsNone(operation.stream)
        with self.rt.Operation() as after:
            self.assertTrue(after)

    def test_explicit_unlock_releases_duplicated_descriptor(self):
        # Closing only the original FD would leave this duplicate holding flock.
        operation = self.rt.Operation()
        with operation:
            duplicate = os.dup(operation.stream.fileno())
        try:
            with self.rt.Operation() as after:
                self.assertTrue(after)
        finally:
            os.close(duplicate)

    def test_unlock_failure_still_closes_file(self):
        operation = self.rt.Operation()
        real_flock = fcntl.flock
        def flock(stream, flags):
            if flags == fcntl.LOCK_UN:
                raise OSError('simulated unlock error')
            return real_flock(stream, flags)
        with patch.object(fcntl, 'flock', side_effect=flock):
            with self.assertRaises(OSError):
                with operation:
                    stream = operation.stream
        self.assertTrue(stream.closed)
        with self.rt.Operation() as after:
            self.assertTrue(after)

    def test_acquisition_and_refusal_are_logged(self):
        with patch.object(self.rt, 'log') as log:
            with self.rt.Operation('holder'):
                with self.rt.Operation('contender') as acquired:
                    self.assertFalse(acquired)
        self.assertIn('operation lock acquired: holder', [call.args[0] for call in log.call_args_list])
        self.assertIn('operation lock refused: contender', [call.args[0] for call in log.call_args_list])

    def test_process_shutdown_releases_held_lock(self):
        source = '''
import os, sys, types
sys.path.insert(0, sys.argv[1])
addon = types.SimpleNamespace(getAddonInfo=lambda key: sys.argv[2] if key == 'profile' else '')
sys.modules.update({
    'xbmc': types.SimpleNamespace(LOGINFO=1, LOGERROR=4, log=lambda *args: None),
    'xbmcaddon': types.SimpleNamespace(Addon=lambda *args: addon),
    'xbmcgui': types.SimpleNamespace(),
    'xbmcvfs': types.SimpleNamespace(translatePath=lambda path: path),
})
from harpywing import runtime
runtime.PRIVATE = sys.argv[2]
runtime.DATA = sys.argv[2] + "/legacy"
runtime.LEGACY_STATE_LINK = sys.argv[2] + '/legacy-link'
with runtime.Operation('terminating Kodi process'):
    os._exit(0)
'''
        subprocess.run([sys.executable, '-c', source, str(ROOT / 'service.harpywing/resources/lib'), self.folder.name],
                       check=True, timeout=10, capture_output=True, encoding='utf-8', errors='replace')
        with self.rt.Operation() as after:
            self.assertTrue(after)

    def test_background_binary_failure_logs_without_ui(self):
        with patch.object(self.rt, 'ensure_executable', side_effect=OSError('missing binary')), patch.object(self.rt, 'notify') as notify, patch.object(self.rt, 'log') as log:
            self.assertFalse(self.rt.ready_binary(interactive=False))
        notify.assert_not_called()
        log.assert_called_once()
