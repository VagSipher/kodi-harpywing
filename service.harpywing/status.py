"""Settings button: a short, redacted connection summary at the TV."""
import os
import sys

import xbmcaddon
import xbmcvfs

addon = xbmcaddon.Addon("service.harpywing")
sys.path.insert(0, os.path.join(xbmcvfs.translatePath(addon.getAddonInfo("path")), "resources", "lib"))
from harpywing import core, logformat, runtime as rt
from harpywing.logwindow import TextWindow

if rt.ready_binary():
    output = rt.status_json(timeout=15)
    state = core.parse_status(output)
    link = {"P2P": rt.text(32023), "Relayed": rt.text(32024)}.get(core.server_link(output), rt.text(32025))
    lines = [rt.text(32021, rt.text(32050) if state["daemon"] == "Connected" else rt.text(32084)),
             rt.text(32022, state["ip"].split("/")[0] or "-"), link,
             rt.text(32085, state["daemon"])]
    if state["error"]:
        lines.append(core.redact(state["error"]))
    if rt.samba_open():
        lines.append(rt.text(32086))
    # Not Dialog.ok(): skins show about three lines and cut the daemon state and
    # the Samba warning; Dialog.textviewer() is titled "Plot" by some skins.
    window = TextWindow("script.logviewer-textwindow-fullscreen.xml", rt.ADDON_DIR,
                        title=rt.text(32020), content=logformat.escape_markup("\n".join(lines)))
    window.doModal()
    del window
