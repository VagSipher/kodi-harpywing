"""Validate Kodi setting defaults without importing the Kodi runtime."""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


class SettingsTest(unittest.TestCase):
    def test_empty_string_defaults_are_explicitly_allowed(self):
        definitions = sorted(ROOT.glob('*/resources/settings.xml'))
        self.assertTrue(definitions, 'No Kodi settings definitions found')
        for path in definitions:
            settings = list(ET.parse(path).getroot().iter('setting'))
            self.assertTrue(settings, str(path))
            for setting in settings:
                if setting.get('type') != 'string' or setting.findtext('default'):
                    continue
                with self.subTest(file=str(path.relative_to(ROOT)), setting=setting.get('id')):
                    self.assertEqual(setting.findtext('constraints/allowempty'), 'true',
                                     'An empty string default requires allowempty=true')


if __name__ == '__main__':
    unittest.main()
