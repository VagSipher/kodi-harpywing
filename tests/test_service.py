"""Service/action regressions without running Kodi or any system command."""
from contextlib import ExitStack
from pathlib import Path
import importlib.util
import runpy
import sys
import types
import unittest
from unittest.mock import Mock, patch

import test_runtime as fixtures

ROOT = fixtures.ROOT


class ServiceTest(unittest.TestCase):
    setUp = fixtures.RuntimeTest.setUp

    def load_service(self, legacy_key=''):
        stack = ExitStack()
        self.addCleanup(stack.close)
        class Monitor:
            def abortRequested(self):
                return False
        stack.enter_context(patch.object(self.rt.xbmc, 'Monitor', Monitor, create=True))
        self.launch = stack.enter_context(patch.object(self.rt.xbmc, 'executebuiltin', create=True))
        self.addon.getSetting.side_effect = lambda key: {'management_url': 'https://api.netbird.io', 'login_method': '0', 'setup_key': legacy_key}.get(key, '')
        self.addon.getSettingBool.side_effect = lambda key: key == 'enabled'
        self.gui = self.rt.xbmcgui
        # Non-modal toasts are allowed (deduplicated by Service.say); modal dialogs are not.
        self.notify = stack.enter_context(patch.object(self.rt, 'notify'))
        self.ready = stack.enter_context(patch.object(self.rt, 'ready_binary', return_value=True))
        stack.enter_context(patch.object(self.rt, 'write_hosts'))
        stack.enter_context(patch.object(self.rt, 'install_unit'))
        stack.enter_context(patch.object(self.rt, 'certainly_stopped', return_value=True))
        self.wait = stack.enter_context(patch.object(self.rt, 'wait_for_daemon', return_value={'daemon': 'NeedsLogin'}))
        self.wizard = Mock(side_effect=AssertionError('wizard must run in action script'))
        stack.enter_context(patch.dict(sys.modules, {'harpywing.wizard': types.SimpleNamespace(wizard=self.wizard)}))
        spec = importlib.util.spec_from_file_location('harpywing_service_test', ROOT / 'service.harpywing/service.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.Service()

    def test_legacy_key_erased_before_startup_operation_can_fail(self):
        service = self.load_service(legacy_key='legacy-key')
        self.addon.setSetting.assert_called_once_with('setup_key', '')
        with patch.object(self.rt, 'Operation', side_effect=RuntimeError('operation failed')):
            service.apply(startup=True)
        self.addon.setSetting.assert_called_once_with('setup_key', '')

    def test_service_never_enrolls_with_legacy_key_and_only_dispatches_at_startup(self):
        service = self.load_service(legacy_key='legacy-key')
        for state in ('NeedsLogin', 'LoginFailed', 'SessionExpired'):
            with self.subTest(state=state), patch.object(self.rt, 'connect') as connect:
                self.wait.return_value = {'daemon': state}
                self.launch.reset_mock()
                service.apply(startup=True)
                self.launch.assert_called_once()
                service.apply()
                self.launch.assert_called_once()
                connect.assert_not_called()

    def assert_no_service_ui(self):
        self.wizard.assert_not_called()
        self.gui.Window.assert_not_called()
        self.gui.Dialog.assert_not_called()
        self.ready.assert_called_with(interactive=False)

    def test_first_launch_dispatches_wizard_only_after_releasing_lock(self):
        service = self.load_service()
        def run_action(command):
            self.assertEqual(command, 'RunScript(special://home/addons/service.harpywing/action.py,wizard)')
            self.assertFalse(service.busy)
            # Executing synchronously here proves the service no longer owns it.
            with self.rt.Operation('test action') as acquired:
                self.assertTrue(acquired)
        self.launch.side_effect = run_action
        with patch.object(self.rt, 'log') as log:
            service.apply(startup=True)
        self.launch.assert_called_once()
        self.assertTrue(any('launching connection wizard' in call.args[0] for call in log.call_args_list))
        self.assert_no_service_ui()
        self.launch.reset_mock()
        service.apply()
        self.launch.assert_not_called()

    def test_abort_does_not_dispatch_wizard_and_releases_lock(self):
        service = self.load_service()
        service.abortRequested = lambda: True
        service.apply(startup=True)
        self.launch.assert_not_called()
        with self.rt.Operation() as acquired:
            self.assertTrue(acquired)
        self.assert_no_service_ui()

    def test_failed_apply_logs_without_ui_and_releases_lock(self):
        service = self.load_service()
        with patch.object(service, '_apply', side_effect=RuntimeError('failed apply')), patch.object(self.rt, 'log') as log:
            service.apply(startup=True)
        # The first occurrence goes through rt.notify (which logs); repeats are logged only.
        shown = [str(a) for call in self.notify.call_args_list for a in call.args]
        logged = [str(call.args[0]) for call in log.call_args_list]
        self.assertTrue(any('failed apply' in m for m in shown + logged))
        self.assertFalse(service.busy)
        self.launch.assert_not_called()
        with self.rt.Operation() as acquired:
            self.assertTrue(acquired)
        self.gui.Window.assert_not_called()
        self.gui.Dialog.assert_not_called()

    def test_own_setting_writes_do_not_loop(self):
        service = self.load_service()
        calls = []
        service.apply = lambda startup=False: calls.append(startup)
        service.applied = service.signature()
        service.onSettingsChanged()          # e.g. our connection_validated write
        self.assertEqual(calls, [])
        settings = {'management_url': 'https://nb.example.org', 'login_method': '0'}
        self.addon.getSetting.side_effect = lambda key: settings.get(key, '')
        service.onSettingsChanged()          # a real user change
        self.assertEqual(calls, [False])

    def test_set_setting_writes_only_changes(self):
        self.load_service()
        self.addon.getSetting.side_effect = lambda key: 'true'
        self.addon.setSetting.reset_mock()
        self.rt.set_setting('connection_validated', 'true')
        self.addon.setSetting.assert_not_called()
        self.rt.set_setting('connection_validated', '')
        self.addon.setSetting.assert_called_once_with('connection_validated', '')

    def test_same_message_is_shown_once(self):
        service = self.load_service()
        service.say(32056, "boom", error=True)
        service.say(32056, "boom", error=True)
        service.say(32050)
        self.assertEqual(self.notify.call_count, 2)

    def test_daemon_error_has_no_service_ui(self):
        service = self.load_service()
        self.wait.return_value = {'daemon': 'Unavailable'}
        service.apply(startup=True)
        self.launch.assert_not_called()
        self.assert_no_service_ui()

    def test_reconnect_applies_options_without_key_or_service_ui(self):
        service = self.load_service()
        self.wait.return_value = {'daemon': 'Connected'}
        self.rt.save_file('options.json', '{}')
        with patch.object(self.rt, 'netbird', return_value=(0, '')) as netbird, patch.object(self.rt, 'connect', return_value=(True, '')) as connect:
            service.apply()
        netbird.assert_called_once_with('down')
        connect.assert_called_once_with(service, '', self.rt.options())
        self.assert_no_service_ui()
        self.launch.assert_not_called()

    def test_invalid_names_still_apply_network_options(self):
        # A typo in the names list must not keep inbound connections open.
        service = self.load_service()
        settings = {'management_url': 'https://api.netbird.io', 'login_method': '0', 'hosts': 'not a mapping'}
        self.addon.getSetting.side_effect = lambda key: settings.get(key, '')
        self.wait.return_value = {'daemon': 'Connected'}
        self.rt.save_file('options.json', '{"allow_inbound": true}')
        with patch.object(self.rt, 'netbird', return_value=(0, '')) as netbird, \
             patch.object(self.rt, 'connect', return_value=(True, '')) as connect, \
             patch.object(self.rt, 'write_hosts') as hosts:
            service.apply()
        netbird.assert_called_once_with('down')
        connect.assert_called_once_with(service, '', self.rt.options())
        hosts.assert_not_called()
        self.assertTrue(any(call.args[0] == 32055 for call in self.notify.call_args_list))

    def test_connected_without_saved_options_reconciles_and_records_only_success(self):
        service = self.load_service()
        self.wait.return_value = {'daemon': 'Connected'}
        for saved in (None, ''):
            for success in (False, True):
                with self.subTest(saved=saved, success=success):
                    path = Path(self.rt.PRIVATE) / 'options.json'
                    if path.exists():
                        path.unlink()
                    if saved is not None:
                        path.write_text(saved)
                    with patch.object(self.rt, 'netbird', return_value=(0, '')) as netbird, patch.object(self.rt, 'connect', return_value=(success, '')) as connect:
                        service.apply()
                    netbird.assert_called_once_with('down')
                    connect.assert_called_once_with(service, '', self.rt.options())
                    self.assertEqual(bool(self.rt.read_file('options.json')), success)

    def test_service_refusal_keeps_other_holder_and_does_not_launch(self):
        service = self.load_service()
        with self.rt.Operation('other holder'):
            service.apply(startup=True)
            with self.rt.Operation('probe') as acquired:
                self.assertFalse(acquired)
        self.launch.assert_not_called()
        self.gui.Window.assert_not_called()
        self.gui.Dialog.assert_not_called()

    def test_change_refused_by_lock_is_retried_until_applied(self):
        service = self.load_service()
        settings = {'management_url': 'https://api.netbird.io', 'login_method': '0'}
        self.addon.getSetting.side_effect = lambda key: settings.get(key, '')
        enabled = [True]
        self.addon.getSettingBool.side_effect = lambda key: key == 'enabled' and enabled[0]
        service.apply()
        self.assertFalse(service.retry)
        enabled[0] = False                   # Off while the wizard holds the lock
        with patch.object(self.rt, 'remove_unit') as remove:
            with self.rt.Operation('wizard'):
                service.onSettingsChanged()
                remove.assert_not_called()
                self.assertTrue(service.retry)
                self.assertNotEqual(service.applied, service.signature())
            service.apply()                  # the main loop's quick retry
            remove.assert_called_once()
        self.assertFalse(service.retry)
        self.assertEqual(service.applied, service.signature())

    def test_invalid_server_stops_the_tunnel_instead_of_keeping_old_options(self):
        service = self.load_service()
        self.addon.getSetting.side_effect = lambda key: {'management_url': 'http://insecure.example', 'login_method': '0'}.get(key, '')
        with patch.object(self.rt, 'turn_off') as off, patch.object(self.rt, 'connect') as connect:
            service.apply()
        off.assert_called_once_with()
        connect.assert_not_called()
        self.assertIn(32088, [call.args[0] for call in self.notify.call_args_list])

    def test_off_clears_names_even_when_the_unit_cannot_be_removed(self):
        service = self.load_service()
        self.addon.getSettingBool.side_effect = lambda key: False
        with patch.object(self.rt, 'remove_unit', side_effect=RuntimeError('disable failed')), patch.object(self.rt, 'write_hosts') as hosts:
            service.apply()
        hosts.assert_called_once_with()
        self.assertEqual(self.notify.call_args.args[0], 32052)
        self.assertIn('disable failed', self.notify.call_args.args[1])

    def test_change_during_up_is_neither_saved_nor_dropped(self):
        service = self.load_service()
        settings = {'management_url': 'https://api.netbird.io', 'login_method': '0'}
        inbound = [True]
        self.addon.getSetting.side_effect = lambda key: settings.get(key, '')
        self.addon.getSettingBool.side_effect = lambda key: key == 'enabled' or (key == 'allow_inbound' and inbound[0])
        self.wait.return_value = {'daemon': 'Idle'}
        def up(monitor, key, chosen):
            self.assertTrue(chosen['allow_inbound'])
            inbound[0] = False               # inbound turned off while `up` runs
            service.onSettingsChanged()      # arrives while this pass is busy
            return True, ''
        with patch.object(self.rt, 'connect', side_effect=up), patch.object(self.rt, 'remember_options') as remember:
            service.apply()
        # What `up` really applied is saved, not the newer settings ...
        self.assertTrue(remember.call_args.args[0]['allow_inbound'])
        # ... and the newer change is retried within seconds, not dropped.
        self.assertTrue(service.retry)

    def test_failure_while_options_change_stops_the_tunnel(self):
        service = self.load_service()
        saved = '{"allow_inbound": true}'      # differs from the wanted options
        for failure in ('down', 'binary', 'daemon'):
            with self.subTest(failure=failure), patch.object(self.rt, 'read_file', return_value=saved), \
                    patch.object(self.rt, 'turn_off') as off, patch.object(self.rt, 'connect') as connect, \
                    patch.object(self.rt, 'netbird', return_value=(1, 'daemon not responding')):
                self.ready.return_value = failure != 'binary'
                self.wait.return_value = {'daemon': 'Unavailable' if failure == 'daemon' else 'Connected'}
                service.apply()
                off.assert_called_once_with()
                connect.assert_not_called()
        # Writing names or installing the unit can fail too (read-only storage).
        for step in ('write_hosts', 'install_unit'):
            with self.subTest(step=step), patch.object(self.rt, 'read_file', return_value=saved), \
                    patch.object(self.rt, 'turn_off') as off, patch.object(self.rt, step, side_effect=OSError('read-only')):
                self.ready.return_value = True
                service.apply()
                off.assert_called_once_with()
        # Without a pending change, a transient failure does not cut the tunnel.
        with patch.object(self.rt, 'read_file', return_value=''), patch.object(self.rt, 'turn_off') as off:
            self.ready.return_value = False
            service.apply()
            off.assert_not_called()

    def test_refused_periodic_check_without_change_waits_normally(self):
        service = self.load_service()
        self.wait.return_value = {'daemon': 'Connected'}
        service.apply()
        with self.rt.Operation('wizard'):
            service.apply()
        self.assertFalse(service.retry)

    def test_loop_retries_a_refusal_within_seconds_and_checks_each_minute(self):
        service = self.load_service()
        clock = [0]
        applied = []
        def apply(startup=False):
            applied.append(clock[0])
            service.retry = clock[0] == 5        # still refused once at 5 s
        def wait(seconds):
            self.assertEqual(seconds, 5)
            clock[0] += seconds
            if clock[0] == 5:
                service.retry = True             # onSettingsChanged refused mid-wait
            return clock[0] >= 75
        service.apply, service.waitForAbort = apply, wait
        service.run()
        self.assertEqual(applied, [0, 5, 10, 70])


class ActionTest(unittest.TestCase):
    setUp = fixtures.RuntimeTest.setUp

    def run_action(self, argument):
        with patch.object(sys, 'argv', ['action.py', argument]):
            runpy.run_path(str(ROOT / 'service.harpywing/action.py'), run_name='__main__')

    def test_refusal_is_a_persistent_ok_dialog(self):
        with self.rt.Operation('other holder'), patch.object(self.rt, 'notify') as notify:
            self.run_action('disconnect')
            self.rt.xbmcgui.Dialog.return_value.ok.assert_called_once_with('Harpy Wing', self.rt.text(32078))
            self.rt.xbmcgui.Dialog.return_value.yesno.assert_not_called()
            notify.assert_not_called()
            with self.rt.Operation('probe') as acquired:
                self.assertFalse(acquired)

    def test_cancelled_disconnect_releases_lock(self):
        self.rt.xbmcgui.Dialog.return_value.yesno.return_value = False
        with patch.object(self.rt, 'forget_identity') as forget:
            self.run_action('disconnect')
            forget.assert_not_called()
        with self.rt.Operation('next action') as acquired:
            self.assertTrue(acquired)

    def test_wizard_cancel_exception_and_abort_release_lock(self):
        for error in (None, RuntimeError('wizard failed'), KeyboardInterrupt(), SystemExit()):
            wizard = Mock(return_value=False, side_effect=error)
            with self.subTest(error=type(error).__name__), patch.dict(sys.modules, {'harpywing.wizard': types.SimpleNamespace(wizard=wizard)}):
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    with self.assertRaises(type(error)):
                        self.run_action('wizard')
                else:
                    self.run_action('wizard')
                with self.rt.Operation('next action') as acquired:
                    self.assertTrue(acquired)
