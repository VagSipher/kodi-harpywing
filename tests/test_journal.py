"""Text shown on TV stays readable and safe for Kodi's markup parser."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'service.harpywing/resources/lib'))
from harpywing.logformat import escape_markup, journal_contents


class JournalDisplayTest(unittest.TestCase):
    def test_recent_systemd_and_kodi_lines_first_saved_order_unchanged(self):
        raw, display = journal_contents('10:00 old system\n11:00 new system\n',
                                        ['11:02 new Kodi', '10:02 old Kodi'])
        self.assertTrue(display.startswith('11:00 new system\n10:00 old system'))
        self.assertLess(display.index('new Kodi'), display.index('old Kodi'))
        self.assertLess(raw.index('old system'), raw.index('new system'))
        self.assertLess(raw.index('old Kodi'), raw.index('new Kodi'))

    def test_empty_sections(self):
        for system, kodi in (('', []), ('new system', []), ('', ['new Kodi'])):
            raw, display = journal_contents(system, kodi)
            self.assertIn('--- Kodi / Harpy Wing ---', raw)
            self.assertIn('--- Kodi / Harpy Wing ---', display)

    def test_ordinary_ascii_brackets_are_preserved(self):
        message = '[service.harpywing] peers=[1, 2] [REDACTED]'
        self.assertEqual(escape_markup(message), message)
        raw, display = journal_contents(message, [])
        self.assertIn(message, raw)
        self.assertIn(message, display)
        self.assertTrue(display.isascii())

    def test_external_markup_literal_our_severity_colors_still_active(self):
        message = '[COLOR blue]WARN[/COLOR] [B]bold[/B] [CR] [TABS]20[/TABS]'
        escaped = escape_markup(message)
        for tag in ('[COLOR blue]', '[/COLOR]', '[B]', '[/B]', '[CR]', '[TABS]', '[/TABS]'):
            self.assertNotIn(tag, escaped)
        self.assertTrue(escaped.isascii())
        raw, display = journal_contents(message + '\nERROR: failed', [])
        self.assertIn(message, raw)
        self.assertIn('[COLOR gold]WARN[/COLOR]', display)
        self.assertIn('[COLOR red]ERROR[/COLOR]', display)
        self.assertIn('[ COLOR blue]', display)
        self.assertIn('[ /COLOR]', display)
        # Every active tag must come from our severity formatter.
        self.assertEqual(set(re.findall(r'\[[^\] ]+(?: [^\]]+)?\]', display)),
                         {'[COLOR red]', '[COLOR gold]', '[/COLOR]'})

    def test_both_display_and_saved_content_are_redacted(self):
        raw, display = journal_contents('setup-key=secret-system', ['token=secret-kodi'])
        for output in (raw, display):
            self.assertNotIn('secret-system', output)
            self.assertNotIn('secret-kodi', output)
            self.assertIn('[REDACTED]', output)
