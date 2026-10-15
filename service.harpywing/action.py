"""Settings actions; one local identity operation at a time."""
import os
import sys

import xbmc
import xbmcaddon
import xbmcgui
import xbmcvfs

addon = xbmcaddon.Addon("service.harpywing")
sys.path.insert(0, os.path.join(xbmcvfs.translatePath(addon.getAddonInfo("path")), "resources", "lib"))
from harpywing import core, runtime as rt

try:
    with rt.Operation("action:" + (sys.argv[1] if len(sys.argv) > 1 else "wizard")) as acquired:
        if not acquired:
            xbmcgui.Dialog().ok("Harpy Wing", rt.text(32078))
        elif len(sys.argv) > 1 and sys.argv[1] == "disconnect":
            if xbmcgui.Dialog().yesno("Harpy Wing", rt.text(32079)):
                # Toast for the text, Kodi's busy spinner for the wait: DialogProgress
                # showed a frozen "0%" and a Cancel button that could not cancel.
                rt.notify(32087)
                xbmc.executebuiltin("ActivateWindow(busydialognocancel)")
                try:
                    rt.forget_identity()
                finally:
                    xbmc.executebuiltin("Dialog.Close(busydialognocancel)")
                rt.notify(32080)
        else:
            from harpywing.wizard import wizard
            wizard()
except Exception as exc:
    xbmcgui.Dialog().ok("Harpy Wing", rt.text(32052, core.redact(str(exc))))
