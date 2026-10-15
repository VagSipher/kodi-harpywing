"""Exercise identity / update operations with Kodi and system commands stubbed."""
import importlib
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
import subprocess
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
# Temporary test trees live in build/ (ignored): absent in a fresh clone.
(ROOT / 'build').mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / 'service.harpywing/resources/lib'))


class RuntimeTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(dir=ROOT / 'build')
        self.addCleanup(self.folder.cleanup)
        self.addon = Mock()
        values = {'path': str(ROOT / 'service.harpywing'), 'profile': self.folder.name, 'version': '0.2.0'}
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
            self.assertEqual(rt.read_file('version'), '0.2.0')
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
