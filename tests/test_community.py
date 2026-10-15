import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
# Temporary test trees live in build/ (ignored): absent in a fresh clone.
(ROOT / 'build').mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / 'service.harpywing/resources/lib'))
from harpywing import core
from harpywing.logreader import LogReader
from harpywing.logformat import get_errors, set_styles

spec = importlib.util.spec_from_file_location('generate_repo', ROOT / 'scripts/generate_repo.py')
repo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repo)


class DeviceOutputTest(unittest.TestCase):
    def test_openurl_real_browser_message(self):
        value = "Please do the SSO login in your browser. \nIf your browser didn't open automatically, use this URL to log in:\n\nhttps://login.example.net/activate and enter the code ABCD-EFGH to authenticate.\n\n"
        self.assertEqual(core.parse_device_login(value), {'url': 'https://login.example.net/activate', 'code': 'ABCD-EFGH'})

    def test_no_browser_variant(self):
        self.assertEqual(core.parse_device_login('Use this URL to log in:\n\nhttps://example.net/login and enter the code 1234 to authenticate.\n')['code'], '1234')

    def test_code_absent_and_embedded(self):
        for url in ('https://example.net/login', 'https://example.net/login?user_code=ABCD'):
            self.assertEqual(core.parse_device_login('Use this URL to log in:\n\n' + url + ' \n'), {'url': url, 'code': ''})

    def test_not_an_unrelated_url(self):
        self.assertIsNone(core.parse_device_login('See https://docs.netbird.io/setup-keys'))


class GenericSettingsTest(unittest.TestCase):
    def test_names_valid_and_normalized(self):
        self.assertEqual(core.parse_names(' Media.example.net = 100.64.0.1 ; box = 100.127.255.254'), [('media.example.net', '100.64.0.1'), ('box', '100.127.255.254')])
        self.assertEqual(core.parse_names(''), [])
        original = '127.0.0.1 localhost\n'
        mappings = core.parse_names('media.example.net=100.80.0.1;box=100.80.0.2')
        hosts = core.apply_hosts(original, mappings=mappings)
        self.assertEqual(core.apply_hosts(hosts, mappings=mappings), hosts)
        self.assertEqual(core.apply_hosts(hosts), original)

    def test_refuses_invalid_list_atomically(self):
        for value in ('a=100.63.255.255', 'a=100.128.0.0', 'a=::1', '=100.80.0.1', 'a b=100.80.0.1', 'a=100.80.0.1;a=100.80.0.2', 'a=100.80.0.1;', 'a=100.80.0.1\nlocalhost', 'a=b=c'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                core.parse_names(value)

    def test_architecture(self):
        for arch in ('aarch64', 'arm64'):
            self.assertEqual(core.binary_name(arch), 'netbird-arm64')
        self.assertEqual(core.binary_name('x86_64'), 'netbird-amd64')
        for arch in ('armv7l', 'i686', 'unknown'):
            with self.assertRaises(ValueError):
                core.binary_name(arch)

    def test_options_all_combinations_and_persisted_flag_reset(self):
        for routes in (False, True):
            for inbound in (False, True):
                args = core.up_args('https://api.netbird.io', receive_routes=routes, allow_inbound=inbound)
                self.assertIn('--disable-dns', args)
                self.assertIn('--disable-server-routes', args)
                self.assertIn('--disable-client-routes=false' if routes else '--disable-client-routes', args)
                self.assertIn('--block-inbound=false' if inbound else '--block-inbound', args)
                self.assertNotIn('--setup-key-file', args)

    def test_server_validation(self):
        for value in ('https://api.netbird.io', 'https://vpn.example.net:33073/'):
            self.assertTrue(core.valid_server(value))
        for value in ('', 'file:///etc/passwd', 'https://u:p@example.net', 'https://example.net?q=x', 'https://example.net/a', 'https://example.net:bad'):
            self.assertFalse(core.valid_server(value))


class JournalTest(unittest.TestCase):
    def test_secrets_never_remain(self):
        secret = '12345678-1234-1234-1234-123456789abc'
        jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature'
        source = '\n'.join((secret, 'setup-key=not-a-uuid-secret', '--setup-key other-secret', 'Bearer bearer-secret', json.dumps({'access_token': 'access-secret', 'refresh_token': 'refresh-secret'}), 'token: token-secret', 'https://example.net/?code=login-secret', jwt, 'and enter the code device-secret to authenticate.'))
        redacted = core.redact(source)
        for value in (secret, 'not-a-uuid-secret', 'other-secret', 'bearer-secret', 'access-secret', 'refresh-secret', 'token-secret', 'login-secret', jwt, 'device-secret'):
            self.assertNotIn(value, redacted)
        self.assertIn('[REDACTED]', redacted)
        self.assertEqual(core.redact('Connected 100.80.1.2 media.example.net'), 'Connected 100.80.1.2 media.example.net')

    def test_reader_tail_and_utf8_and_styles(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            path = Path(folder) / 'kodi.log'
            path.write_bytes('one\néchec\nthree'.encode('utf-8'))
            reader = LogReader(str(path), buf_size=4)
            self.assertEqual(reader.read(invert=True, lines_number=2), 'three\néchec')
            reader.set_offset(path.stat().st_size)
            with path.open('ab') as stream:
                stream.write(b'\nnew\xff')
            self.assertEqual(reader.tail(), '\nnew�')
        self.assertIn('[COLOR red]', set_styles('2026-10-14 10:00:00 ERROR: failed'))
        self.assertIn('ERROR', get_errors('2026-10-14 10:00:00 ERROR: failed\n traceback\n2026-10-14 10:00:01 INFO: ok'))


class RepositoryTest(unittest.TestCase):
    def test_index_and_archives_and_configured_url(self):
        import zipfile
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            base = Path(folder)
            for name in ('plugin.example', 'repository.harpywing'):
                directory = base / name
                directory.mkdir()
                (directory / 'addon.xml').write_text('<addon id="%s" version="1.0"><extension point="xbmc.addon.repository"><dir><info>@BASE_URL@/addons.xml</info><datadir zip="true">@BASE_URL@/</datadir></dir></extension></addon>' % name)
            output = repo.generate(base, base / 'repo', 'http://localhost:8000/test', allow_http=True)
            for addon in ET.parse(output / 'addons.xml').getroot():
                archive = output / addon.get('id') / (addon.get('id') + '-1.0.zip')
                self.assertTrue(archive.is_file())
                with zipfile.ZipFile(archive) as z:
                    self.assertIn(b'http://localhost:8000/test/addons.xml', z.read(addon.get('id') + '/addon.xml'))
            self.assertEqual((output / 'addons.xml.md5').read_text(), hashlib.md5((output / 'addons.xml').read_bytes()).hexdigest())
            archive.unlink()
            with self.assertRaises(FileNotFoundError):
                repo.validate_repo(output)

    def test_unbuilt_service_does_not_publish_an_index(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            base = Path(folder);directory = base / 'service.harpywing';directory.mkdir()
            (directory / 'addon.xml').write_text('<addon id="service.harpywing" version="1"/>')
            with self.assertRaises(ValueError):
                repo.generate(base, base / 'repo', 'https://example.net/repo')
            self.assertFalse((base / 'repo/addons.xml').exists())


class BootHostsTest(unittest.TestCase):
    def test_boot_and_kodi_produce_identical_markers(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            path = Path(folder) / 'hosts'
            config = Path(folder) / 'mappings'
            mappings = [('media.example.net', '100.80.1.2'), ('box', '100.80.1.3')]
            original = '127.0.0.1 localhost\n\n' + '  ' + core.HOSTS_BEGIN + '  \n100.80.0.1 old\n  ' + core.HOSTS_END + '  ' + '\n\n'
            path.write_text(original)
            config.write_text(''.join('%s %s\n' % (ip, name) for name, ip in mappings))
            command = ['sh', str(ROOT / 'service.harpywing/bin/harpywing-hosts'), str(path), str(config)]
            for _ in range(2):
                subprocess.run(command, check=True)
                self.assertEqual(path.read_text(), core.apply_hosts(original, mappings=mappings))
            config.write_text('')
            subprocess.run(command, check=True)
            self.assertEqual(path.read_text(), core.apply_hosts(original))


# Maintainer-only values that must never ship, one per line, kept out of the
# repository (build/ is ignored): the published tests name no installation.
PRIVATE_LIST = ROOT / 'build' / 'private-values.txt'
PRIVATE_VALUES = [line.strip() for line in (PRIVATE_LIST.read_text().splitlines() if PRIVATE_LIST.exists() else [])
                  if line.strip() and not line.startswith('#')]


class PackagingSourceTest(unittest.TestCase):
    def test_settings_strings_complete_and_no_private_values(self):
        import re
        settings = ET.parse(ROOT / 'service.harpywing/resources/settings.xml').getroot()
        ids = {element.get('label') for element in settings.iter() if element.get('label')}
        ids.update(element.get('help') for element in settings.iter() if element.get('help'))
        # English only (owner's decision, 2026-10-14): one language to maintain.
        languages = sorted(p.name for p in (ROOT / 'service.harpywing/resources/language').iterdir())
        self.assertEqual(languages, ['resource.language.en_gb'])
        po = (ROOT / 'service.harpywing/resources/language/resource.language.en_gb/strings.po').read_text()
        translated = set(re.findall(r'msgctxt "#(\d+)"\nmsgid "[^\n]+"\nmsgstr "[^\n]+"', po))
        self.assertTrue(ids <= translated, ids - translated)
        for directory in ('service.harpywing', 'scripts', 'repository.harpywing'):
            for path in (ROOT / directory).rglob('*'):
                if path.suffix in ('.py', '.xml', '.po') or path.name in ('netbird', 'harpywing-daemon', 'harpywing-hosts'):
                    source = path.read_text()
                    for private in PRIVATE_VALUES:
                        self.assertNotIn(private, source, str(path))

    def test_vendored_qr_png_without_dependencies(self):
        sys.path.insert(0, str(ROOT / 'service.harpywing/resources/lib/vendor'))
        import segno
        import io
        output = io.BytesIO()
        segno.make('https://example.net/login?user_code=ABCD', micro=False).save(output, kind='png', scale=4)
        self.assertTrue(output.getvalue().startswith(b'\x89PNG\r\n\x1a\n'))


if __name__ == '__main__':
    unittest.main()
