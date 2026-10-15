# -*- coding: utf-8 -*-
"""

    Copyright (C) 2011-2018 PleXBMC (plugin.video.plexbmc) by hippojay (Dave Hawes-Johnson)
    Copyright (C) 2018-2019 Composite (plugin.video.composite_for_plex)

    This file is part of Composite (plugin.video.composite_for_plex)

    SPDX-License-Identifier: GPL-2.0-or-later
    See LICENSES/GPL-2.0-or-later.txt for more information.
"""

# Device-code display/navigation adapted to native Kodi controls; no PyXBMCt.
import os
import sys
import tempfile
import threading

import xbmcgui

from . import runtime as rt

sys.path.insert(0, os.path.join(rt.ADDON_DIR, "resources", "lib", "vendor"))
import segno


class DeviceDialog(xbmcgui.WindowDialog):
    def __init__(self):
        super().__init__()
        self.cancelled = False
        self.qr_path = ""
        background = os.path.join(rt.ADDON_DIR, "resources", "skins", "Default", "media", "AddonWindow", "black.png")
        self.background = xbmcgui.ControlImage(80, 40, 1120, 640, background)
        self.description = xbmcgui.ControlTextBox(130, 70, 1020, 100, font="font16")
        self.qr = xbmcgui.ControlImage(140, 190, 360, 360, "", aspectRatio=2)
        self.address = xbmcgui.ControlTextBox(550, 190, 580, 260, font="font14")
        self.code = xbmcgui.ControlLabel(550, 470, 580, 60, "", font="font30")
        media = os.path.dirname(background)
        self.cancel_button = xbmcgui.ControlButton(
            550, 570, 320, 60, rt.text(32070),
            focusTexture=os.path.join(media, "white.png"), noFocusTexture=background,
            textColor="0xFFFFFFFF", focusedColor="0xFF000000", shadowColor="0x00000000")
        self.addControls([self.background, self.description, self.qr, self.address, self.code, self.cancel_button])
        self.cancel_button.setNavigation(self.cancel_button, self.cancel_button, self.cancel_button, self.cancel_button)
        self.description.setText(rt.text(32076))
        self.code.setLabel(rt.text(32072))

    def run(self, task):
        """Run task() on a worker thread while this window is modal; return its result.

        Composite's sign-in keeps the script thread in doModal() and polls in a
        thread: a window opened with show() never receives the remote's
        Back / Cancel (0.2.3 real test), a modal one does.
        """
        result = []
        returned = threading.Event()

        def worker():
            try:
                result.append(task())
            except Exception as exc:
                result.append((False, str(exc)))
            finally:
                # A close() sent before doModal() has started is lost: repeat it.
                while True:
                    self.close()
                    if returned.wait(0.5):
                        break

        thread = threading.Thread(target=worker, name="harpywing-device-login", daemon=True)
        thread.start()
        try:
            self.setFocus(self.cancel_button)
            self.doModal()
        finally:
            # Window gone for any reason: stop the worker; its own result is kept.
            self.cancelled = True
            returned.set()
            thread.join()
        return result[0]

    def display_pin(self, login):
        # Composite displays the verification address, the returned code and
        # focuses the action control; polling is supplied by our NetBird bridge.
        self.cleanup()
        fd, self.qr_path = tempfile.mkstemp(prefix="harpywing-qr-", suffix=".png", dir="/run")
        os.close(fd)
        segno.make(login["url"], micro=False).save(self.qr_path, scale=8, border=4)
        os.chmod(self.qr_path, 0o600)
        self.qr.setImage(self.qr_path)
        self.address.setText(login["url"])
        self.code.setLabel(login["code"])
        self.setFocus(self.cancel_button)

    def onControl(self, control):
        # Kodi passes a new wrapper of the clicked control: compare ids (== is
        # identity, False for the same button, seen on the box in 0.2.4).
        if control.getId() == self.cancel_button.getId():
            self.cancelled = True
            self.close()

    def onAction(self, action):
        if action.getId() in (9, 10, 92):
            self.cancelled = True
            self.close()

    def cleanup(self):
        if self.qr_path and os.path.exists(self.qr_path):
            os.remove(self.qr_path)
        self.qr_path = ""
