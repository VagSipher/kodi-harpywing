"""View a bounded, redacted local journal on the TV; never upload it."""
import os
import sys

import xbmcaddon
import xbmcvfs

addon = xbmcaddon.Addon("service.harpywing")
sys.path.insert(0, os.path.join(xbmcvfs.translatePath(addon.getAddonInfo("path")), "resources", "lib"))
from harpywing import core, runtime as rt
from harpywing.logreader import LogReader
from harpywing.logformat import journal_contents
from harpywing.logwindow import TextWindow

code, system = rt.run(["journalctl", "-u", core.UNIT_NAME, "-n", "500", "--no-pager"], timeout=15)
kodi = []
try:
    filename = os.path.join(xbmcvfs.translatePath("special://logpath"), "kodi.log")
    for line in LogReader(filename).read_lines(invert=True, lines_number=10000):
        if "[service.harpywing]" in line:
            kodi.append(line)
            if len(kodi) >= 500:
                break
except OSError as exc:
    kodi.append(str(exc))
raw, content = journal_contents(system, kodi)
window = TextWindow("script.logviewer-textwindow-fullscreen.xml", rt.ADDON_DIR,
                    title=rt.text(32081), content=content)
window.raw_content = raw
window.doModal()
del window
