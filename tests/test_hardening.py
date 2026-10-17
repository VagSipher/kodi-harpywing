"""Security regressions using temporary paths, fake identities and commands only."""
import importlib
import json
import os
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import Mock, mock_open, patch

import test_runtime as fixtures
from test_community import repo
from harpywing import core
from harpywing.logformat import journal_contents

ROOT = fixtures.ROOT


class DNSHardeningTest(unittest.TestCase):
    setUp = fixtures.RuntimeTest.setUp

    def oversized_reply(self, query):
        record = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + b'\x64\x50\0\2'
        return query[:2] + struct.pack('!5H', 0x8180, 1, 4090, 0, 0) + query[12:] + record * 4090

    def test_large_shared_pointer_packet_is_rejected_immediately(self):
        packet = self.oversized_reply(core.dns_query('media.example.net', 123))
        self.assertGreater(len(packet), 64000)
        started = time.perf_counter()
        with self.assertRaisesRegex(ValueError, 'DNS packet too large'):
            core.dns_address(packet, 'media.example.net', 123)
        self.assertLess(time.perf_counter() - started, 0.1)

    def test_hostile_udp_replies_never_replace_saved_mapping(self):
        rt = self.rt
        hosts = fixtures.RuntimeTest.hosts_file(self)
        saved = fixtures.RuntimeTest.cache_text(self, '100.80.0.1 media.example.net\n')
        rt.save_file('hosts', saved)
        def header(query, flags=0x8180, questions=1):
            return query[:2] + struct.pack('!5H', flags, questions, 1, 0, 0)
        def answer(query, owner):
            return header(query) + query[12:] + owner + struct.pack('!HHIH', 1, 1, 0, 4) + b'\x64\x50\0\2'
        replies = {
            'short header': lambda q: q[:5],
            'truncated answer': lambda q: fixtures.dns_reply(q)[:-1],
            'wrong id': lambda q: bytes([q[0] ^ 1]) + fixtures.dns_reply(q)[1:],
            'query flag': lambda q: fixtures.dns_reply(q, flags=0x0180),
            'wrong opcode': lambda q: fixtures.dns_reply(q, flags=0x8980),
            'truncated flag': lambda q: fixtures.dns_reply(q, flags=0x8380),
            'question count': lambda q: header(q, questions=0) + q[12:],
            'wrong question': lambda q: header(q) + b'\x05x' + q[14:],
            'wrong qtype': lambda q: header(q) + q[12:-4] + b'\0\x1c\0\1',
            'wrong qclass': lambda q: header(q) + q[12:-4] + b'\0\1\0\3',
            'literal dots in question label': lambda q: header(q) + b'\x11media.example.net\0\0\1\0\1',
            'question pointer loop': lambda q: header(q) + b'\xc0\x0c\0\1\0\1',
            'answer pointer loop': lambda q: answer(q, struct.pack('!H', 0xc000 | len(q))),
            'pointer outside packet': lambda q: answer(q, b'\xff\xff'),
            'oversized name': lambda q: answer(q, (b'\x3f' + b'a' * 63) * 4 + b'\0'),
            'truncated additional': lambda q: fixtures.dns_reply(q)[:10] + b'\0\1' + fixtures.dns_reply(q)[12:],
            'unrelated answer': lambda q: answer(q, b'\x05other\0'),
            'CNAME loop': lambda q: header(q) + q[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 0, 2) + b'\xc0\x0c',
            'oversized datagram with valid prefix': lambda q: fixtures.dns_reply(q) + b'\0' * 4096,
            '64 KiB shared pointers': self.oversized_reply,
        }
        for label, reply in replies.items():
            with self.subTest(reply=label), fixtures.udp_dns(reply) as (endpoint, requests), \
                    patch.object(rt, '_dns_server', return_value=endpoint):
                rt.write_hosts(rt.core.parse_names('media.example.net'))
                self.assertIn('100.80.0.1 media.example.net\n', hosts.read_text())
                self.assertEqual(rt.read_file('hosts'), saved)

    def test_oversized_configured_names_and_invalid_forced_addresses(self):
        rt = self.rt
        hosts = fixtures.RuntimeTest.hosts_file(self)
        for name in ('a' * 64 + '.test', '.'.join(['a' * 63] * 4)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                core.parse_names(name)
            with self.assertRaises(ValueError):
                core.dns_query(name, 123)
        with self.assertRaises(ValueError):
            rt.write_hosts([('media.example.net', '8.8.8.8')])
        self.assertEqual(hosts.read_text(), '127.0.0.1 localhost\n')


class PrivateRuntimeTest(unittest.TestCase):
    setUp = fixtures.RuntimeTest.setUp

    def test_migration_rejects_aliases_overlap_and_linked_parents(self):
        rt = self.rt
        for shape in ('symlink', 'symlink-trailing', 'same', 'inside', 'parent', 'linked-parent', 'linked-parent-dotdot', 'file'):
            with self.subTest(shape=shape), tempfile.TemporaryDirectory(dir=self.folder.name) as folder:
                base = Path(folder)
                private = base / 'private'; (private / 'state').mkdir(parents=True)
                identity = private / 'state/default.json'; identity.write_text('private identity')
                lock = private / 'operation.lock'; lock.touch()
                inode = lock.stat().st_ino
                data = base / 'old'
                if shape.startswith('symlink'):
                    data.symlink_to(private, target_is_directory=True)
                elif shape == 'same':
                    data = private
                elif shape == 'inside':
                    data = private / 'state'
                elif shape == 'parent':
                    data = base
                elif shape.startswith('linked-parent'):
                    if shape == 'linked-parent-dotdot':
                        (base / 'target/nested').mkdir(parents=True)
                        data = base / 'target/old'
                    data.mkdir()
                    (data / 'state').mkdir()
                    (data / 'state/default.json').write_text('public identity')
                    alias = base / 'alias'
                    alias.symlink_to(base / 'target/nested' if shape.endswith('dotdot') else base, target_is_directory=True)
                    data = alias / '../old' if shape.endswith('dotdot') else alias / 'old'
                else:
                    data.write_text('not a directory')
                rt.DATA, rt.PRIVATE = str(data), str(private)
                if shape == 'symlink-trailing':
                    rt.DATA += '/'
                with patch.object(rt, 'run') as run, patch.object(rt, 'log') as log:
                    rt.migrate_private()
                run.assert_not_called()
                self.assertEqual(identity.read_text(), 'private identity')
                self.assertEqual(lock.stat().st_ino, inode)
                self.assertFalse((private / 'quarantine').exists())
                log.assert_called_once()
                if shape.startswith('symlink'):
                    self.assertFalse(os.path.lexists(data))
                else:
                    self.assertTrue(data.exists())
                if shape.startswith('linked-parent'):
                    self.assertEqual((data / 'state/default.json').read_text(), 'public identity')
                    self.assertTrue(alias.is_symlink())

    def test_certainly_stopped_requires_unit_and_process_evidence(self):
        rt = self.rt
        for state in ('inactive', 'failed', 'unknown', 'Unit service.harpywing.service not loaded.'):
            for process_code, process_output in ((1, ''), (0, '123 netbird service run'), (2, 'denied'), (1, 'process check failed')):
                with self.subTest(state=state, process=process_code, output=process_output), patch.object(rt, 'run', side_effect=[(3, state), (process_code, process_output)]) as run:
                    self.assertEqual(rt.certainly_stopped(), process_code == 1 and not process_output)
                    self.assertEqual(run.call_args_list[0].args[0], ['systemctl', 'is-active', core.UNIT_NAME])
        for state in ('active', 'activating', 'deactivating', 'permission denied', 'Failed to connect to bus: socket not found', ''):
            with self.subTest(state=state), patch.object(rt, 'run', return_value=(1, state)):
                self.assertFalse(rt.certainly_stopped())

    def test_process_pattern_matches_addon_binaries_only(self):
        with patch.object(self.rt, 'run', side_effect=[(3, 'inactive'), (1, '')]) as run:
            self.rt.certainly_stopped()
        pattern = run.call_args.args[0][-1]
        # Use the same POSIX ERE syntax as pgrep, against synthetic command lines.
        commands = '\n'.join(self.rt.NETBIRD + suffix + ' service run --log-file console'
                             for suffix in ('', '-arm64', '-amd64')) + '\n'
        result = subprocess.run(['grep', '-E', pattern], input=commands, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, commands)
        result = subprocess.run(['grep', '-E', pattern], input='/usr/bin/netbird service run\n' + self.rt.NETBIRD + ' status\n', capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)

    def test_disconnect_progress_closes_before_success(self):
        # Toast + Kodi busy spinner (no frozen 0% nor useless Cancel, seen on the box).
        rt = self.rt
        events = []
        def builtin(command):
            events.append('busy' if command.startswith('ActivateWindow') else 'close')
        with patch.object(sys, 'argv', ['action.py', 'disconnect']), patch.object(rt.xbmc, 'executebuiltin', side_effect=builtin, create=True), patch.object(rt, 'forget_identity', side_effect=lambda: events.append('forget')), patch.object(rt, 'notify', side_effect=lambda i, *args: events.append(i)):
            runpy.run_path(str(ROOT / 'service.harpywing/action.py'))
        self.assertEqual(events, [32087, 'busy', 'forget', 'close', 32080])
        rt.xbmcgui.DialogProgress.assert_not_called()

    def test_running_tunnel_stop_failure_keeps_identity_and_closes_progress(self):
        rt = self.rt
        identity = Path(rt.PRIVATE) / 'state/default.json'
        identity.parent.mkdir(); identity.write_text('private identity')
        rt.save_file('options.json', 'private options')
        events = []
        rt.xbmcgui.Dialog.return_value.ok.side_effect = lambda *args: events.append('error')
        def builtin(command):
            if command.startswith('Dialog.Close'):
                events.append('close')
        def running(args, **kwargs):
            return (3, 'inactive') if args[0] == 'systemctl' else (0, '123 ' + rt.NETBIRD + '-amd64 service run')
        with patch.object(sys, 'argv', ['action.py', 'disconnect']), patch.object(rt.xbmc, 'executebuiltin', side_effect=builtin, create=True), patch.object(rt, 'run', side_effect=running), patch.object(rt, 'netbird', return_value=(1, 'RPC timeout')) as down, patch.object(rt, 'remove_unit', side_effect=RuntimeError('stop failed')), patch.object(rt, 'write_hosts') as hosts, patch.object(rt, 'notify') as notify:
            runpy.run_path(str(ROOT / 'service.harpywing/action.py'))
        down.assert_called_once_with('down', timeout=3)
        self.assertEqual(identity.read_text(), 'private identity')
        self.assertEqual(rt.read_file('options.json'), 'private options')
        hosts.assert_not_called()
        self.addon.setSetting.assert_not_called()
        notify.assert_called_once_with(32087)  # start notice only, no success
        self.assertEqual(events, ['close', 'error'])
        self.assertIn('local identity kept', rt.xbmcgui.Dialog.return_value.ok.call_args.args[1])

    def test_sso_url_with_any_path_is_masked(self):
        # NetBird prints whatever URL the IdP gives (4th review).
        output = ("Please do the SSO login in your browser. If your browser didn't open automatically, "
                  "use this URL to log in:\n\nhttps://sso.example.net/login/ABCD-EFGH\n")
        masked = core.redact(output)
        self.assertNotIn('ABCD-EFGH', masked)
        self.assertIn('[REDACTED URL]', masked)
        self.assertIn('https://docs.netbird.io/how-to', core.redact('See https://docs.netbird.io/how-to'))

    def test_sso_urls_masked_in_cli_notifications_logs_and_journal(self):
        rt = self.rt
        for url in ('https://login.example.net/activate/ABCD-EFGH',
                    'https://nest.example.net/oauth2/device?user_code=ABCD-EFGH',
                    'https://login.netbird.io/activate?user_code=ABCD-EFGH'):
            with self.subTest(url=url):
                output = ('Please do the SSO login in your browser… Use this URL to log in:\n' +
                          url + '\nEnter the code ABCD-EFGH to authenticate.')
                with patch.object(rt.subprocess, 'run', return_value=Mock(returncode=1, stdout=output, stderr='')):
                    cli_output = rt.netbird('up')[1]
                rt.notify(32052, output)
                notification = rt.xbmcgui.Dialog.return_value.notification.call_args.args[1]
                logged = rt.xbmc.log.call_args.args[0]
                raw, display = journal_contents(output, [output])
                for masked in (cli_output, notification, logged, raw, display):
                    self.assertNotIn(url, masked)
                    self.assertNotIn('ABCD-EFGH', masked)
                    self.assertIn('[REDACTED URL]', masked)

    def test_migration_old_new_both_none_and_idempotence(self):
        rt = self.rt
        for old_exists, new_exists in ((True, False), (False, True), (True, True), (False, False)):
            with self.subTest(old=old_exists, new=new_exists), tempfile.TemporaryDirectory(dir=self.folder.name) as folder:
                rt.DATA, rt.PRIVATE = folder + '/old', folder + '/private'
                old, new = Path(rt.DATA), Path(rt.PRIVATE)
                old.mkdir(); new.mkdir(mode=0o755)
                (old / 'settings.xml').write_text('Kodi settings')
                for directory, exists, content in ((old, old_exists, 'old identity'), (new, new_exists, 'new identity')):
                    if exists:
                        (directory / 'state').mkdir()
                        (directory / 'state/default.json').write_text(content)
                        for name in rt.PRIVATE_FILES[1:]:
                            (directory / name).write_text(content)
                Path(rt.LEGACY_STATE_LINK).symlink_to(old / 'state')
                def stopped(*args, **kwargs):
                    self.assertTrue((old / 'state/default.json').exists())
                    return 0, ''
                with patch.object(rt, 'run', side_effect=stopped) as run, patch.object(rt, 'log') as log:
                    rt.migrate_private()
                    rt.migrate_private()
                self.assertEqual(run.call_count, int(old_exists))
                self.assertEqual(new.stat().st_mode & 0o777, 0o700)
                self.assertFalse(os.path.lexists(rt.LEGACY_STATE_LINK))
                self.assertTrue((old / 'settings.xml').exists())
                if old_exists or new_exists:
                    expected = 'new identity' if new_exists else 'old identity'
                    self.assertEqual((new / 'state/default.json').read_text(), expected)
                    for name in rt.PRIVATE_FILES[1:]:
                        self.assertEqual((new / name).read_text(), expected)
                self.assertFalse((old / 'state').exists())
                if old_exists and new_exists:
                    quarantine = new / 'quarantine'
                    self.assertEqual(quarantine.stat().st_mode & 0o777, 0o700)
                    for name in rt.PRIVATE_FILES:
                        copies = list(quarantine.glob(name + '-*'))
                        self.assertEqual(len(copies), 1)
                        copy = copies[0] / 'default.json' if name == 'state' else copies[0]
                        self.assertEqual(copy.read_text(), 'old identity')
                        self.assertFalse((old / name).exists())
                    self.assertTrue(any('quarantining old copy' in c.args[0] for c in log.call_args_list))

    def test_empty_old_lock_is_removed_when_new_lock_exists(self):
        # Operation creates the new lock before migrating (seen on the box, 0.3.0).
        rt = self.rt
        with tempfile.TemporaryDirectory(dir=self.folder.name) as folder:
            rt.DATA, rt.PRIVATE = folder + '/old', folder + '/private'
            old, new = Path(rt.DATA), Path(rt.PRIVATE)
            old.mkdir(); new.mkdir()
            (old / 'operation.lock').write_text('')
            (new / 'operation.lock').write_text('')
            inode = (new / 'operation.lock').stat().st_ino
            with patch.object(rt, 'run', return_value=(0, '')):
                rt.migrate_private()
            self.assertFalse((old / 'operation.lock').exists())
            self.assertTrue((new / 'operation.lock').exists())
            self.assertEqual((new / 'operation.lock').stat().st_ino, inode)

    def test_old_lock_is_never_migrated(self):
        old = Path(self.rt.DATA); old.mkdir()
        lock = old / 'operation.lock'; lock.write_text('non-empty old lock')
        self.rt.migrate_private()
        self.assertEqual(lock.read_text(), 'non-empty old lock')
        self.assertFalse((Path(self.rt.PRIVATE) / 'operation.lock').exists())
        lock.write_text('')
        self.rt.migrate_private()
        self.assertFalse(lock.exists())

    def test_migration_unlinks_top_level_and_nested_symlinks_without_following(self):
        rt = self.rt
        base = Path(self.folder.name)
        victim = base / 'victim'; victim.mkdir()
        (victim / 'secret').write_text('unchanged')
        old = Path(rt.DATA); old.mkdir()
        for name in rt.PRIVATE_FILES + ('operation.lock',):
            (old / name).symlink_to(victim, target_is_directory=True)
        with patch.object(rt, 'run', return_value=(0, '')), patch.object(rt, 'log') as log:
            rt.migrate_private()
            self.assertEqual(list(old.iterdir()), [])
            state = old / 'state'; (state / 'nested').mkdir(parents=True)
            (state / 'default.json').write_text('fake identity')
            (state / 'directory-link').symlink_to(victim, target_is_directory=True)
            (state / 'nested/file-link').symlink_to(victim / 'secret')
            (state / 'nested/broken-link').symlink_to(base / 'missing')
            rt.migrate_private()
        self.assertEqual((victim / 'secret').read_text(), 'unchanged')
        self.assertFalse(state.exists())
        migrated = Path(rt.PRIVATE) / 'state'
        self.assertEqual((migrated / 'default.json').read_text(), 'fake identity')
        self.assertFalse(any(p.is_symlink() for p in migrated.rglob('*')))
        self.assertTrue(any('symlink' in c.args[0] for c in log.call_args_list))

    def test_failed_stop_preserves_old_identity(self):
        old = Path(self.rt.DATA) / 'state'
        old.mkdir(parents=True)
        (old / 'default.json').write_text('identity')
        with patch.object(self.rt, 'run', return_value=(1, 'permission denied')):
            with self.assertRaises(RuntimeError):
                self.rt.migrate_private()
        self.assertEqual((old / 'default.json').read_text(), 'identity')
        self.assertFalse((Path(self.rt.PRIVATE) / 'state').exists())

    def test_failed_state_scan_preserves_old_identity(self):
        old = Path(self.rt.DATA) / 'state'; old.mkdir(parents=True)
        (old / 'default.json').write_text('fake identity')
        def walk(path, **kwargs):
            kwargs['onerror'](PermissionError('state scan denied'))
            return iter(())
        with patch.object(self.rt, 'run', return_value=(0, '')), patch.object(self.rt.os, 'walk', side_effect=walk):
            with self.assertRaisesRegex(PermissionError, 'state scan denied'):
                self.rt.migrate_private()
        self.assertEqual((old / 'default.json').read_text(), 'fake identity')
        self.assertFalse((Path(self.rt.PRIVATE) / 'state').exists())

    def test_unrelated_var_lib_path_left_untouched(self):
        rt = self.rt
        path = Path(rt.LEGACY_STATE_LINK)
        for symlink in (False, True):
            if symlink:
                path.symlink_to('/unrelated-state')
            else:
                path.mkdir()
            rt.migrate_private()
            self.assertTrue(os.path.lexists(path))
            if symlink:
                self.assertEqual(os.readlink(path), '/unrelated-state')
                path.unlink()
            else:
                path.rmdir()

    def test_status_parses_raw_json_and_only_redacts_display_fields(self):
        output = '{"daemonStatus":"Connected","management":{"connected":false,"error": "token expired"},"netbirdIp":"100.80.1.2/16"}'
        with patch.object(self.rt.subprocess, 'run', return_value=Mock(returncode=0, stdout=output, stderr='diagnostic')):
            self.assertEqual(self.rt.status()['daemon'], 'Connected')
            self.assertEqual(self.rt.status()['ip'], '100.80.1.2/16')
            self.assertNotIn('expired', self.rt.status()['error'])
            self.assertEqual(json.loads(self.rt.status_json())['management']['error'], 'token expired')
            self.assertNotIn('expired', self.rt.netbird('status', '--json')[1])

    def test_status_dialog_uses_raw_json_and_samba_warning(self):
        output = json.dumps({'daemonStatus': 'Connected', 'management': {
            'error': 'token expired\n[COLOR red]untrusted[/COLOR][CR]injected'}})
        window = Mock()
        logwindow = type(sys)('harpywing.logwindow')
        logwindow.TextWindow = Mock(return_value=window)
        with patch.dict(sys.modules, {'harpywing.logwindow': logwindow}), patch.object(self.rt, 'ready_binary', return_value=True), patch.object(self.rt, 'status_json', return_value=output), patch.object(self.rt, 'samba_open', return_value=True), patch.object(self.rt, 'text', side_effect=lambda i, *a: str(i)):
            runpy.run_path(str(ROOT / 'service.harpywing/status.py'))
        # Full window, not a three-line OK dialog that cut the warning on the box.
        window.doModal.assert_called_once()
        body = logwindow.TextWindow.call_args.kwargs['content']
        self.assertIn('32086', body)
        self.assertNotIn('Unavailable', body)
        self.assertNotIn('expired', body)
        self.assertIn('[ COLOR red]untrusted[ /COLOR][ CR]injected', body)
        self.assertNotIn('[COLOR', body)
        self.assertNotIn('[CR]', body)

    def test_forget_after_off_skips_down_and_erases_despite_missing_unit(self):
        rt = self.rt
        private = Path(rt.PRIVATE)
        (private / 'state/user-config').mkdir(parents=True)
        (private / 'state/user-config/email').write_text('fake account')
        (private / 'quarantine/state-old').mkdir(parents=True)
        (private / 'quarantine/state-old/identity').write_text('fake old identity')
        for name in rt.PRIVATE_FILES[1:] + ('interface',):
            (private / name).write_text('private data')
        lock = private / 'operation.lock'; lock.touch()
        inode = lock.stat().st_ino
        self.addon.getSetting.return_value = 'legacy value'
        events = []
        def stop():
            events.append('stop')
            self.assertTrue((private / 'state').exists())
            raise RuntimeError('unit unavailable')
        with patch.object(rt, 'run', side_effect=[(3, 'inactive'), (1, ''), (4, 'unknown'), (1, '')]), patch.object(rt, 'netbird') as down, patch.object(rt, 'remove_unit', side_effect=stop), patch.object(rt, 'write_hosts') as hosts:
            # Every erase still runs, but a unit that could not be removed is
            # reported: no "Disconnected" notice over a failure (4th review).
            with self.assertRaisesRegex(RuntimeError, 'removing unit failed: unit unavailable'):
                rt.forget_identity()
        down.assert_not_called()
        self.assertEqual(events, ['stop'])
        self.assertEqual(list(private.iterdir()), [lock])
        self.assertEqual(lock.stat().st_ino, inode)
        hosts.assert_called_once_with()
        self.addon.setSetting.assert_any_call('setup_key', '')
        self.addon.setSetting.assert_any_call('enabled', 'false')
        self.addon.setSetting.assert_any_call('connection_validated', '')

    def test_forget_reports_local_failure_only_after_other_erases(self):
        rt = self.rt
        state = Path(rt.PRIVATE) / 'state'; state.mkdir()
        for name in rt.PRIVATE_FILES[1:]:
            rt.save_file(name, 'private data')
        self.addon.getSetting.return_value = 'legacy value'
        with patch.object(rt, 'certainly_stopped', return_value=True), patch.object(rt, 'netbird', return_value=(1, 'daemon down')), patch.object(rt, 'remove_unit'), patch.object(rt, 'write_hosts', side_effect=OSError('hosts erase failed')):
            with self.assertRaisesRegex(RuntimeError, '^hosts erase failed$'):
                rt.forget_identity()
        self.assertFalse(state.exists())
        self.assertFalse(any((Path(rt.PRIVATE) / n).exists() for n in rt.PRIVATE_FILES))
        self.addon.setSetting.assert_any_call('connection_validated', '')

    def test_write_hosts_uses_unique_local_temp_and_does_not_follow_predictable_link(self):
        rt = self.rt
        base = Path(self.folder.name)
        hosts = base / 'system-hosts'; hosts.write_text('127.0.0.1 localhost\n')
        victim = base / 'victim'; victim.write_text('unchanged')
        Path(str(hosts) + '.harpywing').symlink_to(victim)
        real_replace = os.replace
        temps = []
        def replace(source, destination):
            if destination == str(hosts):
                temp = Path(source)
                self.assertEqual(temp.parent, hosts.parent)
                self.assertEqual(temp.stat().st_mode & 0o777, 0o644)
                temps.append(temp)
            real_replace(source, destination)
        with patch.object(rt, 'HOSTS', str(hosts)), patch.object(rt.os, 'replace', side_effect=replace):
            rt.write_hosts([('box', '100.80.1.2')])
            rt.write_hosts()
        self.assertEqual(len(set(temps)), 2)
        self.assertFalse(any(p.exists() for p in temps))
        self.assertEqual(victim.read_text(), 'unchanged')
        self.assertEqual(hosts.read_text(), '127.0.0.1 localhost\n')

    def test_key_erased_when_daemon_unavailable_or_temp_cleanup_fails(self):
        self.addon.getSetting.return_value = 'fake-key'
        with patch.object(self.rt, 'wait_for_daemon', return_value={'daemon': 'Unavailable'}):
            self.assertFalse(self.rt.connect(Mock(), 'fake-key')[0])
        self.addon.setSetting.assert_called_with('setup_key', '')
        self.addon.setSetting.reset_mock()
        key_path = Path(self.folder.name) / 'temp-key'
        def mkstemp(**kwargs):
            return os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), str(key_path)
        with patch.object(self.rt, 'wait_for_daemon', return_value={'daemon': 'Idle'}), patch.object(self.rt.tempfile, 'mkstemp', side_effect=mkstemp), patch.object(self.rt, 'netbird', return_value=(1, 'failed')), patch.object(self.rt.os, 'remove', side_effect=OSError('cleanup failed')):
            with self.assertRaises(OSError):
                self.rt.connect(Mock(), 'fake-key')
        self.addon.setSetting.assert_called_with('setup_key', '')

    def fake_interface(self, name, ifindex='36', devtype='wireguard'):
        interface = Path(self.rt.SYS_NET) / name
        interface.mkdir()
        (interface / 'ifindex').write_text(ifindex + '\n')
        (interface / 'uevent').write_text('DEVTYPE=%s\nINTERFACE=%s\nIFINDEX=%s\n' % (devtype, name, ifindex))
        return interface

    def configure_interface(self, name):
        (Path(self.rt.PRIVATE) / 'state').mkdir(exist_ok=True)
        (Path(self.rt.PRIVATE) / 'state/default.json').write_text(json.dumps({'WgIface': name}))

    def test_interface_left_by_a_killed_daemon_is_removed_only_when_proven_ours(self):
        rt = self.rt
        self.configure_interface('nb-tv')
        interface = self.fake_interface('nb-tv')
        rt.remember_interface()                  # taken while our daemon is Connected
        self.assertEqual(json.loads(rt.read_file('interface')), {'name': 'nb-tv', 'ifindex': '36', 'boot': 'boot-1'})
        # Daemon gone (unit inactive, no process) but its interface remains.
        with patch.object(rt, 'run', side_effect=[(3, 'inactive'), (1, '')]):
            self.assertFalse(rt.certainly_stopped())
        def ip(args, *rest, **kwargs):
            if args[0] == 'ip':
                self.assertEqual(args, ['ip', 'link', 'delete', 'nb-tv'])
                shutil.rmtree(interface)
                return 0, ''
            return (3, 'inactive') if args[0] == 'systemctl' else (1, '')
        with patch.object(rt, 'run', side_effect=ip) as run:
            rt.remove_interface()
        self.assertFalse(interface.exists())
        self.assertEqual(run.call_count, 3)
        # A daemon still running owns its interface: never delete it then.
        interface = self.fake_interface('nb-tv')
        with patch.object(rt, 'run', side_effect=[(3, 'inactive'), (0, '123 netbird service run')]) as run:
            rt.remove_interface()
        self.assertTrue(interface.exists())
        self.assertEqual(run.call_count, 2)
        # A delete that fails while the interface remains is reported.
        with patch.object(rt, 'run', side_effect=[(3, 'inactive'), (1, ''), (2, 'Operation not permitted')]):
            with self.assertRaisesRegex(RuntimeError, 'Operation not permitted'):
                rt.remove_interface()

    def test_interface_not_proven_ours_is_reported_never_deleted(self):
        rt = self.rt
        no_command = patch.object(rt, 'run', side_effect=lambda args, *a, **k: self.fail('unexpected command %s' % args) if args[0] == 'ip' else ((3, 'inactive') if args[0] == 'systemctl' else (1, '')))
        # No config and no record: NetBird's default wt0 belongs to someone else.
        self.fake_interface('wt0')
        with no_command:
            rt.remove_interface()
            self.assertTrue(rt.certainly_stopped())
        rt.remember_interface()
        self.assertEqual(rt.read_file('interface'), '')
        # Configured name, but never recorded as ours: kept and reported.
        self.configure_interface('wt0')
        with no_command:
            rt.remove_interface()
            self.assertFalse(rt.certainly_stopped())
        # Recorded, then recreated (other index) or after a reboot: not ours.
        rt.remember_interface()
        for change in ('ifindex', 'boot'):
            with self.subTest(change=change):
                shutil.rmtree(Path(rt.SYS_NET) / 'wt0')
                self.fake_interface('wt0', ifindex='99' if change == 'ifindex' else '36')
                Path(rt.BOOT_ID).write_text('boot-2' if change == 'boot' else 'boot-1')
                with no_command:
                    rt.remove_interface()
                self.assertTrue((Path(rt.SYS_NET) / 'wt0').exists())
        # Stale record and no config left: not deleted, but still not "stopped".
        (Path(rt.PRIVATE) / 'state/default.json').unlink()
        with no_command:
            rt.remove_interface()
            self.assertFalse(rt.certainly_stopped())
        # A configured name that is not a WireGuard interface (e.g. a bridge).
        self.configure_interface('br0')
        self.fake_interface('br0', devtype='bridge')
        rt.remember_interface()
        self.assertNotIn('br0', rt.read_file('interface'))
        with no_command:
            rt.remove_interface()

    def test_wrapper_removes_only_its_recorded_interface_after_a_crash(self):
        script = (ROOT / 'service.harpywing/bin/harpywing-daemon').read_text()
        function = script[script.index('remove_leftover_interface() {'):script.index('\n}\n', script.index('remove_leftover_interface() {')) + 3]
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            base = Path(folder)
            (base / 'private').mkdir()
            (base / 'boot').write_text('boot-1\n')
            def run(record, ifindex='43', devtype='wireguard', boot='boot-1'):
                shutil.rmtree(base / 'net', ignore_errors=True)
                (base / 'net/wt0').mkdir(parents=True)
                (base / 'net/wt0/ifindex').write_text(ifindex + '\n')
                (base / 'net/wt0/uevent').write_text('DEVTYPE=%s\nINTERFACE=wt0\n' % devtype)
                (base / 'boot').write_text(boot + '\n')
                (base / 'private/interface').write_text(record)
                env = dict(os.environ, PRIVATE=str(base / 'private'), SYS_NET=str(base / 'net'), BOOT_ID=str(base / 'boot'))
                return subprocess.run(['sh', '-c', function + 'ip() { echo "ip $*"; }\nremove_leftover_interface'],
                                      env=env, capture_output=True, text=True).stdout
            record = json.dumps({'name': 'wt0', 'ifindex': '43', 'boot': 'boot-1'}, sort_keys=True)
            self.assertEqual(run(record), 'ip link delete wt0\n')
            for case in ({'ifindex': '99'}, {'devtype': 'bridge'}, {'boot': 'boot-2'}):
                with self.subTest(**case):
                    self.assertEqual(run(record, **case), '')
            for bad in ('', 'not json', json.dumps({'name': '../x', 'ifindex': '43', 'boot': 'boot-1'}),
                        json.dumps({'name': 'wt0;reboot', 'ifindex': '43', 'boot': 'boot-1'})):
                with self.subTest(record=bad):
                    self.assertEqual(run(bad), '')

    def test_repository_has_browsable_indexes_for_static_hosting(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            base = Path(folder)
            addon = base / 'plugin.example'; addon.mkdir()
            (addon / 'addon.xml').write_text('<addon id="plugin.example" version="1.0"/>')
            output = repo.generate(base, base / 'repo', 'https://example.net/repo')
            root = (output / 'index.html').read_text()
            self.assertIn('<a href="plugin.example/">', root)
            self.assertIn('<a href="addons.xml">', root)
            self.assertNotIn('.harpywing-repo', root)
            self.assertIn('<a href="plugin.example-1.0.zip">', (output / 'plugin.example/index.html').read_text())

    def test_packagers_refuse_symbolic_links(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            base = Path(folder)
            secret = base / 'secret.txt'; secret.write_text('private')
            addon = base / 'plugin.example'; addon.mkdir()
            (addon / 'addon.xml').write_text('<addon id="plugin.example" version="1.0"/>')
            (addon / 'asset.txt').symlink_to(secret)
            with self.assertRaisesRegex(ValueError, 'symbolic link'):
                repo.generate(base, base / 'repo', 'https://example.net')
            # Assets copied outside the zip, and a linked add-on directory.
            (addon / 'asset.txt').unlink()
            (addon / 'icon.png').symlink_to(secret)
            with self.assertRaisesRegex(ValueError, 'symbolic link'):
                repo.generate(base, base / 'repo', 'https://example.net')
            (addon / 'icon.png').unlink()
            elsewhere = base / 'elsewhere'; elsewhere.mkdir()
            (elsewhere / 'addon.xml').write_text('<addon id="plugin.linked" version="1.0"/>')
            (base / 'plugin.linked').symlink_to(elsewhere, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symbolic link'):
                repo.generate(base, base / 'repo', 'https://example.net')
            self.assertFalse((base / 'repo').exists())
        source = (ROOT / 'build.sh').read_text()
        self.assertIn('os.path.islink(src)', source)
        self.assertIn('os.path.islink(path)', source)
        self.assertIn('refusing symbolic link', source)

    def test_disconnect_keeps_only_netbird_cleanup_record(self):
        rt = self.rt
        state = Path(rt.PRIVATE) / 'state'
        (state / 'user-config/netbird').mkdir(parents=True)
        (state / 'default.json').write_text('{"PrivateKey": "fake-wireguard-key"}')
        (state / 'active_profile.json').write_text('{}')
        (state / 'user-config/netbird/email').write_text('fake account')
        (state / 'state.json').write_text('{"iptables_state": {"interface_state": {"name": "wt0"}}}')
        with patch.object(rt, 'certainly_stopped', return_value=True), patch.object(rt, 'remove_unit'), patch.object(rt, 'write_hosts'):
            rt.forget_identity()
        self.assertEqual(sorted(p.name for p in state.iterdir()), ['state.json'])
        (state / 'state.json').unlink()
        (state / 'default.json').write_text('{"PrivateKey": "fake-wireguard-key"}')
        with patch.object(rt, 'certainly_stopped', return_value=True), patch.object(rt, 'remove_unit'), patch.object(rt, 'write_hosts'):
            rt.forget_identity()
        self.assertFalse(state.exists())

    def test_turn_off_runs_every_step_and_requires_a_stopped_tunnel(self):
        rt = self.rt
        with patch.object(rt, 'remove_unit', side_effect=RuntimeError('disable failed')), patch.object(rt, 'write_hosts') as hosts, patch.object(rt, 'certainly_stopped', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'disable failed'):
                rt.turn_off()
        hosts.assert_called_once_with()
        with patch.object(rt, 'remove_unit'), patch.object(rt, 'write_hosts'), patch.object(rt, 'certainly_stopped', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'Cannot confirm the tunnel is stopped'):
                rt.turn_off()
        with patch.object(rt, 'remove_unit'), patch.object(rt, 'write_hosts'), patch.object(rt, 'certainly_stopped', return_value=True):
            rt.turn_off()

    def test_off_stops_even_without_unit_file(self):
        # systemd as seen on the box: without its file, `disable` fails and
        # stops nothing; `stop` still stops a loaded unit.
        self.rt.UNIT_PATH = self.folder.name + '/missing.service'
        unit = {'active': True}
        def systemctl(args, *rest, **kwargs):
            action = args[1]
            if action == 'stop':
                unit['active'] = False
                return 0, ''
            if action == 'disable':
                return 1, 'Failed to disable unit: Unit file service.harpywing.service does not exist.'
            return 0, ''
        with patch.object(self.rt, 'run', side_effect=systemctl) as run:
            self.rt.remove_unit()
        self.assertFalse(unit['active'])
        self.assertEqual(run.call_args_list[-1].args[0], ['systemctl', 'daemon-reload'])

    def test_samba_warning_requires_process_and_open_config(self):
        with patch.object(self.rt, 'run', return_value=(0, '123')), patch('builtins.open', mock_open(read_data='[data]\npath=/storage/.config\npublic=yes')):
            self.assertTrue(self.rt.samba_open())
        with patch.object(self.rt, 'run', return_value=(1, '')), patch('builtins.open') as opened:
            self.assertFalse(self.rt.samba_open())
            opened.assert_not_called()

    def test_journal_replaces_symlink_without_following_it(self):
        self.rt.xbmcgui.WindowXMLDialog = type('WindowXMLDialog', (), {})
        sys.modules.pop('harpywing.logwindow', None)
        self.addCleanup(lambda: sys.modules.pop('harpywing.logwindow', None))
        window = importlib.import_module('harpywing.logwindow')
        window.rt = self.rt
        target = Path(self.folder.name) / 'victim'
        target.write_text('unchanged')
        destination = Path(self.folder.name) / 'harpywing-journal.txt'
        destination.symlink_to(target)
        with patch.object(window, 'JOURNAL_PATH', str(destination)), patch.object(self.rt, 'notify') as notify:
            window.save_journal('token=secret')
        self.assertEqual(target.read_text(), 'unchanged')
        self.assertFalse(destination.is_symlink())
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('secret', destination.read_text())
        notify.assert_called_once_with(32083)


class PureSecurityTest(unittest.TestCase):
    def test_redaction_masks_every_authorization_form(self):
        for text, secret in (('Authorization: Basic dXNlcjpwYXNzd29yZA==', 'dXNlcjpwYXNzd29yZA'),
                             ('Proxy-Authorization: Digest username="a", response="abc123"', 'abc123'),
                             ('authorization=Bearer abc.def', 'abc.def'),
                             ('dial https://user:hunter2@relay.example.net/x', 'hunter2'),
                             ('password=hunter2', 'hunter2'), ('passwd: hunter2', 'hunter2'),
                             ('{"password": "fake\'secret"}', 'secret'), ("password='a\"b-secret'", 'secret'),
                             ('{"password": "a\\"b-secret"}', 'secret'),
                             ('{"Authorization": "Digest username=\\"a\\", response=\\"abc123\\""}', 'abc123')):
            with self.subTest(text=text):
                self.assertNotIn(secret, core.redact(text))
        self.assertIn('relay.example.net/x', core.redact('dial https://user:hunter2@relay.example.net/x'))

    def test_interface_name_is_validated_without_default(self):
        for name in ('wt0', 'nb-tv', 'wg_0.1', 'a' * 15):
            self.assertTrue(core.valid_interface(name))
        for name in (None, '', 5, '.', '..', '../x', 'a/b', 'a b', 'a' * 16, '-x'):
            self.assertFalse(core.valid_interface(name))

    def test_samba_private_descendants(self):
        for path in ('/storage/.local/share/service.harpywing/state',
                     '/storage/.local/share/service.harpywing/state/user-config'):
            self.assertTrue(core.samba_open('[share]\npath=' + path + '\npublic=yes'))
        self.assertFalse(core.samba_open('[share]\npath=/storage/.local/share/service.harpywing2/state\npublic=yes'))

    def test_repository_refuses_invalid_ids_versions_and_escaping_destinations(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            base = Path(folder)
            addon = base / 'plugin.example'; addon.mkdir()
            for addon_id in (str(base / 'escaped'), '../escaped', 'plugin.other', 'Plugin.example', 'plugin.example/child', ''):
                (addon / 'addon.xml').write_text('<addon id="' + addon_id + '" version="1"/>')
                with self.subTest(addon_id=addon_id), self.assertRaises(ValueError):
                    repo.generate(base, base / 'repo', 'https://example.net')
                self.assertFalse((base / 'escaped').exists())
                self.assertFalse((base / 'repo').exists())
            for version in ('../1', '/absolute', '1\\2', '1..2', ''):
                (addon / 'addon.xml').write_text('<addon id="plugin.example" version="' + version + '"/>')
                with self.subTest(version=version), self.assertRaises(ValueError):
                    repo.generate(base, base / 'repo', 'https://example.net')
            staging = base / 'staging'; staging.mkdir()
            (staging / 'link').symlink_to(base, target_is_directory=True)
            for parts in (('../escaped',), (str(base / 'escaped'),), ('link', 'escaped')):
                with self.subTest(parts=parts), self.assertRaises(ValueError):
                    repo.staging_path(staging, *parts)

    def test_samba_sensitive_paths_aliases_defaults_and_parents(self):
        for path in ('/', '/storage', '/storage/.kodi', '/storage/.kodi/userdata', '/storage/.kodi/addons', '/storage/.config', '/storage/.config/..', '/storage/.local', '/storage/.local/share', '/storage/.local/share/service.harpywing'):
            for public in ('public', 'guest ok'):
                self.assertTrue(core.samba_open('[share]\npath = %s\n%s = YES\n' % (path, public)))
        self.assertTrue(core.samba_open('[global]\npublic=yes\n[share]\npath="/storage/.kodi/"'))
        for value in ('true', 'True', '1', 'on'):  # Samba booleans, not only "yes"
            self.assertTrue(core.samba_open('[share]\npath=/storage\nguest ok = %s\n' % value))
        self.assertFalse(core.samba_open('[global]\npublic=yes\n[share]\npath=/storage\nguest ok=no'))
        self.assertTrue(core.samba_open('[share]\npath=/storage\nguest ok=no\npublic=yes'))
        for config in ('', '# [share]\n; public=yes\n', '[share]\npath=/storage\npublic=no', '[share]\npath=/storage2\npublic=yes', '[global]\npath=/storage\npublic=yes'):
            self.assertFalse(core.samba_open(config), config)

    def test_up_flags_always_disable_server_ssh_and_hostname_is_value(self):
        for inbound in (False, True):
            args = core.up_args('https://example.net', '--malicious', allow_inbound=inbound)
            self.assertIn('--allow-server-ssh=false', args)
            self.assertIn('--hostname=--malicious', args)
            self.assertNotIn('--hostname', args)

    def test_repository_url_rules(self):
        for url in ('https://example.net/repo', 'https://localhost:443/path'):
            repo.validate_base_url(url)
        for host in ('localhost', '127.0.0.1', '[::1]', '10.0.0.1', '172.16.0.1', '192.168.1.2', '[fd00::1]'):
            url = 'http://' + host + ':8000/repo'
            with self.assertRaises(ValueError):
                repo.validate_base_url(url)
            repo.validate_base_url(url, allow_http=True)
        for url in ('http://example.net', 'http://8.8.8.8', 'http://169.254.1.2', 'http://0.0.0.0', 'https://user:pass@example.net', 'https://@example.net', 'http://user@localhost', 'file:///repo', 'https://example.net:bad', 'https://example.net?q=1'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                repo.validate_base_url(url, allow_http=True)

    def test_repository_validates_before_replace_and_rolls_back(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            base = Path(folder)
            addon = base / 'plugin.example'; addon.mkdir()
            (addon / 'addon.xml').write_text('<addon id="plugin.example" version="1"/>')
            output = base / 'repo'; output.mkdir()
            (output / 'sentinel').write_text('old repo')
            (output / '.harpywing-repo').write_text('Generated by scripts/generate_repo.py\n')
            real_validate = repo.validate_repo
            def validate(staging):
                self.assertEqual((output / 'sentinel').read_text(), 'old repo')
                real_validate(staging)
                raise ValueError('injected validation failure')
            with patch.object(repo, 'validate_repo', side_effect=validate):
                with self.assertRaises(ValueError):
                    repo.generate(base, output, 'https://example.net')
            self.assertEqual({p.name for p in output.iterdir()}, {'sentinel', '.harpywing-repo'})
            real_replace = os.replace
            def replace(source, destination):
                if Path(source).name == 'new':
                    raise OSError('injected publication failure')
                real_replace(source, destination)
            with patch.object(repo.os, 'replace', side_effect=replace):
                with self.assertRaises(OSError):
                    repo.generate(base, output, 'https://example.net')
            self.assertEqual((output / 'sentinel').read_text(), 'old repo')
            repo.generate(base, output, 'https://example.net')
            self.assertFalse((output / 'sentinel').exists())
            self.assertTrue((output / '.harpywing-repo').is_file())
            real_validate(output)

    def test_settings_have_no_setup_key_and_version_names_embedded_netbird(self):
        settings = ET.parse(ROOT / 'service.harpywing/resources/settings.xml').getroot()
        self.assertNotIn('setup_key', {s.get('id') for s in settings.iter('setting')})
        addon = ET.parse(ROOT / 'service.harpywing/addon.xml').getroot()
        netbird = dict(line.split('=', 1) for line in (ROOT / 'NETBIRD_VERSION').read_text().splitlines()
                       if line and not line.startswith('#'))
        self.assertRegex(addon.get('version'), r'^\d+\.\d+\.\d+\+nb' + netbird['VERSION'].replace('.', r'\.') + '$')

    def test_repository_refuses_protected_and_non_generated_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            base = Path(folder)
            for name in ('.git', 'scripts', 'tests', 'service.harpywing', 'repository.harpywing', 'unrelated'):
                directory = base / name; directory.mkdir()
                sentinel = directory / 'keep'; sentinel.write_text('unchanged')
                if name != 'unrelated':
                    (directory / '.harpywing-repo').write_text('marker')
                for output in (directory, directory / 'nested') if name != 'unrelated' else (directory,):
                    with self.subTest(output=output), self.assertRaises(ValueError):
                        repo.generate(base, output, 'https://example.net')
                self.assertEqual(sentinel.read_text(), 'unchanged')
                self.assertFalse((directory / 'nested').exists())

    def test_boot_hosts_revalidates_every_line_and_uses_safe_temp(self):
        valid = ['100.64.0.0 a', '100.127.255.255 box.example', '100.80.1.2 ' + 'a'*63]
        invalid = ['127.0.0.1 localhost', '100.63.255.255 box', '100.128.0.0 box', '100.80.1.256 box', '100.080.1.1 box', '::1 box', '100.80.1.2 UPPER', '100.80.1.2 -box', '100.80.1.2 box-', '100.80.1.2 a..b', '100.80.1.2 '+ 'a'*64, '100.80.1.2 '+ '.'.join(['a'*63]*4), '100.80.1.2 box extra', '# END service.harpywing', '100.80.1.2 box;command']
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            path = Path(folder) / 'hosts'; path.write_text('127.0.0.1 localhost\n')
            mappings = Path(folder) / 'mappings'; mappings.write_text('\n'.join(valid + invalid) + '\n')
            victim = Path(folder) / 'victim'; victim.write_text('safe')
            (Path(str(path) + '.harpywing-boot')).symlink_to(victim)
            subprocess.run(['sh', str(ROOT / 'service.harpywing/bin/harpywing-hosts'), str(path), str(mappings)], check=True)
            expected = core.apply_hosts('127.0.0.1 localhost\n', mappings=[(line.split()[1], line.split()[0]) for line in valid])
            self.assertEqual(path.read_text(), expected)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(victim.read_text(), 'safe')


class DaemonTest(unittest.TestCase):
    def make_daemon(self, folder, netbird_source):
        base = Path(folder)
        addon = base / 'addon'; (addon / 'bin').mkdir(parents=True)
        for script in ('harpywing-daemon', 'harpywing-hosts'):
            shutil.copyfile(ROOT / 'service.harpywing/bin' / script, addon / 'bin' / script)
        binary = addon / 'bin/netbird'; binary.write_text(netbird_source); binary.chmod(0o755)
        commands = base / 'commands'; commands.mkdir()
        # Instant fake-daemon exits can race watcher startup. Bound its sleeps
        # so an inherited output pipe never holds communicate() for 60 seconds.
        sleep = commands / 'sleep'
        sleep.write_text('#!/bin/sh\nexec /bin/sleep 0.02\n')
        sleep.chmod(0o755)
        systemctl = commands / 'systemctl'
        systemctl.write_text('#!/bin/sh\n[ -f "$TEST_ROOT/stopped" ] || exit 9\nprintf "%s\\n" "$*" >> "$TEST_ROOT/systemctl.log"\n')
        systemctl.chmod(0o755)
        hosts = base / 'hosts'; hosts.write_text('127.0.0.1 localhost\n')
        env = dict(os.environ, TEST_ROOT=folder, PATH=str(commands) + os.pathsep + os.environ['PATH'],
                   HARPYWING_PRIVATE=str(base / 'private'), HARPYWING_DATA_DIR=str(base / 'old'),
                   HARPYWING_HOSTS_PATH=str(hosts), HARPYWING_LEGACY_LINK=str(base / 'legacy-link'))
        return base, addon, commands, env

    def test_shell_migration_rejects_aliases_overlap_and_linked_parents(self):
        for shape in ('symlink', 'symlink-trailing', 'same', 'inside', 'parent', 'linked-parent', 'linked-parent-dotdot', 'file'):
            with self.subTest(shape=shape), tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
                base, addon, commands, env = self.make_daemon(folder, '#!/bin/sh\nexit 23\n')
                private = base / 'private'; (private / 'state').mkdir(parents=True)
                identity = private / 'state/default.json'; identity.write_text('private identity')
                lock = private / 'operation.lock'; lock.touch()
                inode = lock.stat().st_ino
                data = base / 'old'
                if shape.startswith('symlink'):
                    data.symlink_to(private, target_is_directory=True)
                elif shape == 'same':
                    data = private
                elif shape == 'inside':
                    data = private / 'state'
                elif shape == 'parent':
                    data = base
                elif shape.startswith('linked-parent'):
                    if shape == 'linked-parent-dotdot':
                        (base / 'target/nested').mkdir(parents=True)
                        data = base / 'target/old'
                    data.mkdir()
                    (data / 'state').mkdir()
                    (data / 'state/default.json').write_text('public identity')
                    alias = base / 'alias'
                    alias.symlink_to(base / 'target/nested' if shape.endswith('dotdot') else base, target_is_directory=True)
                    data = alias / '../old' if shape.endswith('dotdot') else alias / 'old'
                else:
                    data.write_text('not a directory')
                env['HARPYWING_DATA_DIR'] = str(data)
                if shape == 'symlink-trailing':
                    env['HARPYWING_DATA_DIR'] += '/'
                result = subprocess.run(['sh', str(addon / 'bin/harpywing-daemon')], env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertIn('skipped unsafe', result.stderr)
                self.assertEqual(identity.read_text(), 'private identity')
                self.assertEqual(lock.stat().st_ino, inode)
                self.assertFalse((private / 'quarantine').exists())
                if shape.startswith('symlink'):
                    self.assertFalse(os.path.lexists(data))
                else:
                    self.assertTrue(data.exists())
                if shape.startswith('linked-parent'):
                    self.assertTrue(alias.is_symlink())
                    self.assertEqual((data / 'state/default.json').read_text(), 'public identity')

    def test_shell_migration_conflicts_and_nested_links_leave_lock_untouched(self):
        for conflict in (False, True):
            with self.subTest(conflict=conflict), tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
                base, addon, commands, env = self.make_daemon(folder, '#!/bin/sh\nexit 23\n')
                old = base / 'old'; (old / 'state/nested').mkdir(parents=True)
                private = base / 'private'; private.mkdir()
                victim = base / 'victim'; victim.mkdir()
                (victim / 'secret').write_text('unchanged')
                (old / 'state/default.json').write_text('old identity')
                (old / 'state/directory-link').symlink_to(victim, target_is_directory=True)
                (old / 'state/nested/file-link').symlink_to(victim / 'secret')
                (old / 'state/nested/broken-link').symlink_to(base / 'missing')
                names = ('hosts', 'options.json', 'version', 'previous-version')
                for name in names:
                    (old / name).write_text('old data')
                if conflict:
                    (private / 'state').mkdir()
                    (private / 'state/default.json').write_text('private identity')
                    for name in names:
                        (private / name).write_text('private data')
                # Even a public lock symlink must be completely untouched by shell.
                old_lock = old / 'operation.lock'; old_lock.symlink_to(victim / 'secret')
                private_lock = private / 'operation.lock'; private_lock.write_text('private lock')
                inode = private_lock.stat().st_ino
                result = subprocess.run(['sh', str(addon / 'bin/harpywing-daemon')], env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(list(old.iterdir()), [old_lock])
                self.assertTrue(old_lock.is_symlink())
                self.assertEqual(private_lock.read_text(), 'private lock')
                self.assertEqual(private_lock.stat().st_ino, inode)
                self.assertEqual((victim / 'secret').read_text(), 'unchanged')
                expected = 'private identity' if conflict else 'old identity'
                self.assertEqual((private / 'state/default.json').read_text(), expected)
                for name in names:
                    self.assertEqual((private / name).read_text(), 'private data' if conflict else 'old data')
                if conflict:
                    quarantine = private / 'quarantine'
                    self.assertEqual(quarantine.stat().st_mode & 0o777, 0o700)
                    for name in ('state',) + names:
                        copies = list(quarantine.glob(name + '-*'))
                        self.assertEqual(len(copies), 1)
                        copy = copies[0] / 'default.json' if name == 'state' else copies[0]
                        self.assertEqual(copy.read_text(), 'old identity' if name == 'state' else 'old data')
                    self.assertIn('quarantining old copy', result.stderr)
                self.assertFalse(any(p.is_symlink() for p in private.rglob('*')))
                self.assertIn('symlink', result.stderr)

    def test_shell_unlinks_top_level_links_without_following_targets(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            base, addon, commands, env = self.make_daemon(folder, '#!/bin/sh\nexit 23\n')
            old = base / 'old'; old.mkdir()
            victim = base / 'victim'; victim.mkdir()
            (victim / 'secret').write_text('unchanged')
            for name in ('state', 'hosts', 'options.json', 'version', 'previous-version'):
                (old / name).symlink_to(victim, target_is_directory=True)
            result = subprocess.run(['sh', str(addon / 'bin/harpywing-daemon')], env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertEqual(list(old.iterdir()), [])
            self.assertEqual((victim / 'secret').read_text(), 'unchanged')
            self.assertEqual(list((base / 'private/state').iterdir()), [])
            self.assertFalse(any(p.is_symlink() for p in (base / 'private').rglob('*')))
            self.assertIn('symlink', result.stderr)

    def test_watcher_requires_two_consecutive_missing_checks_and_migrates(self):
        source = '''#!/bin/sh
trap 'echo stopped > "$TEST_ROOT/stopped"; exit 0' TERM
printf '%s\\n' "$NB_STATE_DIR" "$XDG_CONFIG_HOME" > "$TEST_ROOT/env"
echo started > "$TEST_ROOT/started"
while :; do /bin/sleep 0.02; done
'''
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            base, addon, commands, env = self.make_daemon(folder, source)
            old = base / 'old'; (old / 'state').mkdir(parents=True)
            (old / 'state/default.json').write_text('fake identity')
            (old / 'hosts').write_text('100.80.1.2 media.example\n')
            (base / 'legacy-link').symlink_to(old / 'state')
            # Each fake 60-second sleep advances one check. Restore the binary
            # at check 2 to simulate an update, then remove it at checks 3/4.
            sleep = commands / 'sleep'
            sleep.write_text('''#!/bin/sh
[ "$1" = 60 ] || exit 8
/bin/sleep 0.05
count=0
[ ! -f "$TEST_ROOT/checks" ] || count=$(cat "$TEST_ROOT/checks")
count=$((count + 1))
echo "$count" > "$TEST_ROOT/checks"
case "$count" in
  1|3) mv "$TEST_ROOT/addon" "$TEST_ROOT/addon.saved" ;;
  2) mv "$TEST_ROOT/addon.saved" "$TEST_ROOT/addon" ;;
esac
''')
            sleep.chmod(0o755)
            result = subprocess.run(['sh', str(addon / 'bin/harpywing-daemon')], env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((base / 'checks').read_text().strip(), '4')
            self.assertEqual((base / 'systemctl.log').read_text().strip(), 'disable service.harpywing.service')
            self.assertTrue((base / 'stopped').exists())
            self.assertNotIn(core.HOSTS_BEGIN, (base / 'hosts').read_text())
            self.assertIn('127.0.0.1 localhost', (base / 'hosts').read_text())
            self.assertEqual((base / 'private/state/default.json').read_text(), 'fake identity')
            self.assertFalse((old / 'state').exists())
            self.assertFalse(os.path.lexists(base / 'legacy-link'))
            self.assertEqual((base / 'env').read_text().splitlines(), [str(base / 'private/state'), str(base / 'private/state/user-config')])

    def test_normal_exit_code_and_sigterm_forwarding(self):
        for stop in (False, True):
            with self.subTest(stop=stop), tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
                source = ('#!/bin/sh\ntrap \'echo stopped > "$TEST_ROOT/stopped"; exit 0\' TERM\necho started > "$TEST_ROOT/started"\nwhile :; do /bin/sleep 0.02; done\n' if stop else '#!/bin/sh\nexit 23\n')
                base, addon, commands, env = self.make_daemon(folder, source)
                process = subprocess.Popen(['sh', str(addon / 'bin/harpywing-daemon')], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    if stop:
                        import time
                        deadline = time.monotonic() + 3
                        while not (base / 'started').exists():
                            if time.monotonic() > deadline:
                                self.fail('fake daemon did not start')
                            time.sleep(.01)
                        process.terminate()
                    out, err = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 0 if stop else 23, err)
                    if stop:
                        self.assertTrue((base / 'stopped').exists())
                    self.assertFalse((base / 'systemctl.log').exists())
                finally:
                    if process.poll() is None:
                        process.kill(); process.communicate()
