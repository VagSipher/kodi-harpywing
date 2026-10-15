# -*- coding: utf-8 -*-
# TextWindow: Log Viewer by i96751414 / fightnight; GPL-2.0-or-later.
# onInit / modal-dialog pattern also adapted from VPN Manager libs/logbox.py.
#!/usr/bin/python
# -*- coding: utf-8 -*-
#
#    Copyright (C) 2016 Zomboided
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#    This module will display a log box on the screen


import os
import tempfile

import xbmcgui
from . import core, runtime as rt

ACTION_PARENT_DIR, KEY_NAV_BACK, ACTION_PREVIOUS_MENU = 9, 92, 10

class TextWindow(xbmcgui.WindowXMLDialog):
    def __init__(self, xml_filename, script_path, title, content):
        super(TextWindow, self).__init__(xml_filename, script_path)
        self.title = title
        self.content = content
        # Controls IDs
        self.close_button_id = 32500
        self.title_label_id = 32501
        self.text_box_id = 32503
        self.save_button_id = 32504
        # Only the journal sets this; the status window has nothing to save.
        self.raw_content = None

    def onInit(self):
        # noinspection PyUnresolvedReferences
        self.getControl(self.title_label_id).setLabel(self.title)
        # noinspection PyUnresolvedReferences
        self.getControl(self.text_box_id).setText(self.content)
        if self.raw_content is None:
            self.getControl(self.save_button_id).setVisible(False)

    def onClick(self, control_id):
        if control_id == self.close_button_id:
            # Close Button
            self.close()
        elif control_id == self.save_button_id and self.raw_content is not None:
            save_journal(self.raw_content)

    def onAction(self, action):
        if action.getId() in [ACTION_PARENT_DIR, KEY_NAV_BACK, ACTION_PREVIOUS_MENU]:
            self.close()


JOURNAL_PATH = "/storage/harpywing-journal.txt"


def save_journal(content):
    temp = ""
    try:
        # mkstemp uses O_EXCL and mode 0600 in the destination directory.
        fd, temp = tempfile.mkstemp(prefix=".harpywing-journal-", dir=os.path.dirname(JOURNAL_PATH))
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(core.redact(content))
        os.replace(temp, JOURNAL_PATH)
        rt.notify(32083)
    except OSError as exc:
        rt.notify(32052, str(exc), error=True)
    finally:
        if temp and os.path.exists(temp):
            os.remove(temp)
