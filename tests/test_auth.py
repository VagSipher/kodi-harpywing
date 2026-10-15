import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'service.harpywing/resources/lib'))
from harpywing import auth


class StreamingTest(unittest.TestCase):
    def launch(self, source, status, cancelled, display, timeout=3, **kwargs):
        processes = []
        real_popen = subprocess.Popen
        def capture(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process
        with patch.object(auth.subprocess, 'Popen', side_effect=capture):
            result = auth.device_login([sys.executable, '-u', '-c', source], status, cancelled, display, timeout=timeout, **kwargs)
        self.assertIsNotNone(processes[0].poll(), 'child must be reaped after every outcome')
        return result

    def test_fragmented_url_and_code_read_before_child_exits_without_desktop(self):
        source = """import os, sys, time
assert 'DISPLAY' not in os.environ and 'WAYLAND_DISPLAY' not in os.environ
sys.stdout.write('Use this URL to log in:\\n\\nhttps://example.net/'); sys.stdout.flush()
time.sleep(.1)
sys.stdout.write('login and enter the code ABCD-EFGH to authenticate.\\n'); sys.stdout.flush()
time.sleep(20)
"""
        shown = []
        def status():
            return {'daemon': 'Connected' if shown else 'NeedsLogin'}
        with patch.dict(os.environ, {'DISPLAY': ':0', 'WAYLAND_DISPLAY': 'wayland-0'}):
            success, error = self.launch(source, status, lambda: False, shown.append)
        self.assertTrue(success, error)
        self.assertEqual(shown, [{'url': 'https://example.net/login', 'code': 'ABCD-EFGH'}])

    def test_cancel_and_timeout_kill_process(self):
        for cancelled, timeout, expected in [(lambda: True, 3, 'cancelled'), (lambda: False, .1, 'timeout')]:
            with self.subTest(expected=expected):
                result = self.launch('import time; time.sleep(20)', lambda: {'daemon': 'NeedsLogin'}, cancelled, lambda value: None, timeout)
                self.assertEqual(result, (False, expected))

    def test_exit_zero_without_connected_status_is_failure_and_redacted(self):
        result = self.launch("print('setup-key=do-not-display');", lambda: {'daemon': 'NeedsLogin'}, lambda: False, lambda value: None)
        self.assertFalse(result[0])
        self.assertNotIn('do-not-display', result[1])

    def test_given_environment_reaches_netbird(self):
        source = "import os; print('Use this URL to log in:\\n\\nhttps://example.net/' + os.environ['XDG_CONFIG_HOME'].strip('/') + ' and enter the code ABCD to authenticate.', flush=True); import time; time.sleep(20)"
        shown = []
        env = dict(os.environ, XDG_CONFIG_HOME='/data/state/user-config', DISPLAY=':0')
        self.launch(source, lambda: {'daemon': 'Connected' if shown else 'NeedsLogin'}, lambda: False, shown.append, env=env)
        self.assertEqual(shown[0]['url'], 'https://example.net/data/state/user-config')
