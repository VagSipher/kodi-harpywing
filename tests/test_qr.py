"""QR cancellation: the script thread is modal, NetBird is polled by a worker."""
import importlib
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

import test_runtime as fixtures


class QRTest(unittest.TestCase):
    def setUp(self):
        fixtures.RuntimeTest.setUp(self)
        gui = self.rt.xbmcgui
        class Window:
            """Kodi semantics: close() only ends a doModal() already running."""
            def __init__(self):
                self.addControls = Mock()
                self.setFocus = Mock()
                self.show = Mock(side_effect=AssertionError('show() never gets remote input'))
                self.close = Mock(side_effect=self._close)
                self.modal = False
                self.ended = threading.Event()
                self.on_modal = None
            def _close(self):
                if self.modal:
                    self.ended.set()
            def doModal(self):
                self.modal = True
                if self.on_modal:
                    threading.Thread(target=self.on_modal, daemon=True).start()
                if not self.ended.wait(10):
                    raise AssertionError('doModal never closed')
                self.modal = False
        gui.INPUT_ALPHANUM = 0
        gui.ALPHANUM_HIDE_INPUT = 1
        gui.WindowDialog = Window
        gui.ControlImage = Mock()
        gui.ControlTextBox = Mock()
        gui.ControlLabel = Mock()
        gui.ControlButton = Mock()
        gui.ControlButton.return_value.getId.return_value = 3006
        gui.DialogProgress = Mock()
        for name in ('harpywing.dialogs', 'harpywing.wizard'):
            sys.modules.pop(name, None)
            self.addCleanup(lambda name=name: sys.modules.pop(name, None))
        self.dialogs = importlib.import_module('harpywing.dialogs')
        self.wizard = importlib.import_module('harpywing.wizard')

    def test_button_contrast_and_textures_do_not_depend_on_skin(self):
        window = self.dialogs.DeviceDialog()
        args, kwargs = self.rt.xbmcgui.ControlButton.call_args
        self.assertEqual(args[-1], self.rt.text(32070))
        for name, filename in (('focusTexture', 'white.png'), ('noFocusTexture', 'black.png')):
            path = Path(kwargs[name])
            self.assertEqual(path.name, filename)
            self.assertTrue(path.is_file())
            self.assertTrue(path.is_relative_to(fixtures.ROOT / 'service.harpywing/resources/skins/Default/media'))
        self.assertEqual(kwargs['textColor'], '0xFFFFFFFF')
        self.assertEqual(kwargs['focusedColor'], '0xFF000000')
        self.assertEqual(kwargs['shadowColor'], '0x00000000')
        self.assertFalse(window.cancelled)

    def cancel_during_login(self, action):
        from harpywing import auth
        dialog = self.rt.xbmcgui.Dialog.return_value
        dialog.input.side_effect = ['https://api.netbird.io', 'TV']
        self.addon.getSetting.side_effect = lambda key: 'leftover' if key == 'setup_key' else ''
        dialog.select.return_value = 1
        monitor = Mock()
        monitor.abortRequested.return_value = False
        window = self.dialogs.DeviceDialog()
        shown = threading.Event()
        cancelled_at = []
        def remote():
            # Kodi delivers the remote's input to the modal window callbacks.
            self.assertTrue(shown.wait(5))
            cancelled_at.append(time.monotonic())
            if action == 'button':
                # Kodi hands over another wrapper of the same control.
                window.onControl(Mock(getId=Mock(return_value=3006)))
            else:
                window.onAction(Mock(getId=Mock(return_value=action)))
        window.on_modal = remote
        def display_pin(login):
            self.assertEqual(login['code'], 'ABCD')
            self.assertIsNot(threading.current_thread(), threading.main_thread())
            shown.set()
        window.display_pin = Mock(side_effect=display_pin)
        def netbird(*args, **kwargs):
            if args == ('down',):
                return 0, ''
            self.assertEqual(args, ('status', '--json'))
            self.assertEqual(kwargs['timeout'], .5)
            time.sleep(.45)  # Cancellation must also tolerate a slow status call.
            return 0, '{"daemonStatus":"NeedsLogin"}'
        original_login = auth.device_login
        real_popen = subprocess.Popen
        processes = []
        def capture(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process
        source = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('Use this URL to log in:\\n\\nhttps://example.net/login and enter the code ABCD to authenticate.', flush=True); time.sleep(20)"
        def login(args, status, cancelled, display, **kwargs):
            return original_login([sys.executable, '-u', '-c', source], status, cancelled, display,
                                  timeout=3, **kwargs)
        def text(identifier, *args):
            if identifier == 32073:
                return 'Connexion annulée'
            if identifier == 32052:
                return 'Échec de la connexion : ' + args[0]
            return str(identifier)
        with patch.object(self.wizard.xbmc, 'Monitor', return_value=monitor, create=True), \
             patch.object(self.wizard, 'DeviceDialog', return_value=window), \
             patch.object(self.rt, 'text', side_effect=text), \
             patch.object(self.rt, 'ready_binary', return_value=True), \
             patch.object(self.rt, 'write_hosts'), patch.object(self.rt, 'install_unit'), \
             patch.object(self.rt, 'wait_for_daemon', return_value={'daemon': 'NeedsLogin'}), \
             patch.object(self.rt, 'netbird', side_effect=netbird), \
             patch.object(self.rt, 'status_json', side_effect=lambda timeout: netbird('status', '--json', timeout=timeout)[1]), \
             patch.object(auth, 'device_login', side_effect=login), \
             patch.object(auth.subprocess, 'Popen', side_effect=capture), \
             patch.object(self.rt, 'notify') as notify:
            self.assertFalse(self.wizard.wizard())
        self.assertTrue(window.cancelled)
        self.assertEqual(len(cancelled_at), 1)
        self.assertEqual(window.display_pin.call_count, 1)
        self.assertLess(time.monotonic() - cancelled_at[0], 2)
        self.assertIsNotNone(processes[0].poll(), 'netbird up must be killed and reaped')
        self.assertTrue(processes[0].stdout.closed)
        window.close.assert_called()
        # A cancel is the user's choice: a toast, never a "connection failed" dialog.
        notify.assert_called_once_with(32073)
        dialog.ok.assert_not_called()
        self.addon.setSetting.assert_any_call('setup_key', '')

    def test_cancel_button_while_waiting_kills_even_sigterm_resistant_child(self):
        self.cancel_during_login('button')

    def test_back_while_waiting_kills_child_and_reports_cancelled(self):
        for action in (9, 10, 92):
            with self.subTest(action=action):
                self.rt.xbmcgui.Dialog.return_value.reset_mock()
                self.cancel_during_login(action)

    def test_worker_close_before_modal_starts_is_repeated(self):
        window = self.dialogs.DeviceDialog()
        done = threading.Event()
        def task():
            done.set()
            return False, 'boom'
        real_modal = window.doModal
        def late_modal():
            # The worker finishes and closes before the modal loop starts.
            self.assertTrue(done.wait(5))
            time.sleep(.1)
            real_modal()
        window.doModal = late_modal
        started = time.monotonic()
        self.assertEqual(window.run(task), (False, 'boom'))
        self.assertLess(time.monotonic() - started, 3)
        self.assertGreaterEqual(window.close.call_count, 2)

    def test_qr_success_keeps_expiration_advice_in_dialog_body(self):
        dialog = self.rt.xbmcgui.Dialog.return_value
        dialog.input.side_effect = ['https://api.netbird.io', 'TV']
        dialog.select.return_value = 1
        texts = {32050: 'Connected', 32075: 'For a TV box to stay connected, disable its login expiration.'}
        self.addon.getSetting.side_effect = lambda key: 'true' if key == 'connection_validated' else ''
        window = self.dialogs.DeviceDialog()
        window.run = Mock(return_value=(True, ''))
        with patch.object(self.wizard.xbmc, 'Monitor', create=True), \
             patch.object(self.wizard, 'DeviceDialog', return_value=window), \
             patch.object(self.rt, 'text', side_effect=lambda i, *a: texts.get(i, str(i))), \
             patch.object(self.rt, 'ready_binary', return_value=True), \
             patch.object(self.rt, 'write_hosts'), patch.object(self.rt, 'install_unit'), \
             patch.object(self.rt, 'remember_options'), \
             patch.object(self.rt, 'samba_open', return_value=False), \
             patch.object(self.rt, 'wait_for_daemon', return_value={'daemon': 'NeedsLogin'}), \
             patch.object(self.rt, 'netbird', return_value=(0, '')):
            self.assertTrue(self.wizard.wizard())
        # The skin shows about three body lines: the advice alone, status in the heading.
        dialog.ok.assert_called_once_with('Harpy Branch - Connected', texts[32075])

    def test_success_warns_about_samba_for_both_methods_and_login_parses_raw_status(self):
        for method in (0, 1):
            with self.subTest(method=method):
                dialog = self.rt.xbmcgui.Dialog.return_value
                dialog.reset_mock()
                dialog.select.return_value = method
                dialog.input.side_effect = ['https://api.netbird.io'] + (['fake-key'] if method == 0 else []) + ['TV']
                self.addon.getSetting.side_effect = lambda key: 'true' if key == 'connection_validated' else ''
                window = Mock()
                window.run.side_effect = lambda login: login()
                output = '{"daemonStatus":"Connected","management":{"error": "token expired"}}'
                def login(args, status, *other, **kwargs):
                    result = status()
                    self.assertEqual(result['daemon'], 'Connected')
                    self.assertNotIn('expired', result['error'])
                    return True, ''
                with patch.object(self.wizard.xbmc, 'Monitor', create=True), \
                     patch.object(self.wizard, 'DeviceDialog', return_value=window), \
                     patch.object(self.wizard.auth, 'device_login', side_effect=login), \
                     patch.object(self.rt, 'ready_binary', return_value=True), \
                     patch.object(self.rt, 'write_hosts'), patch.object(self.rt, 'install_unit'), \
                     patch.object(self.rt, 'remember_options'), \
                     patch.object(self.rt, 'wait_for_daemon', return_value={'daemon': 'Idle'}), \
                     patch.object(self.rt, 'connect', return_value=(True, '')), \
                     patch.object(self.rt, 'status_json', return_value=output) as raw, \
                     patch.object(self.rt, 'samba_open', return_value=True), \
                     patch.object(self.rt, 'netbird', return_value=(0, '')):
                    self.assertTrue(self.wizard.wizard())
                self.assertEqual(dialog.ok.call_count, 2)
                self.assertEqual(dialog.ok.call_args.args, ('Harpy Branch', self.rt.text(32086)))
                if method == 1:
                    raw.assert_called_once_with(.5)
