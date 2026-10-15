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
#    Shared code fragments used by the add-on.

# Adapted from wizard() / connectionValidated(); see THIRD_PARTY.md.
import xbmc
import xbmcgui

from . import auth, core, runtime as rt
from .dialogs import DeviceDialog


def connectionValidated(addon):
    if not addon.getSetting("connection_validated") == "":
        return True
    return False


def wizard():
    """VPN Manager's staged prompts and validation, adapted to NetBird."""
    addon = rt.settings()
    dialog = xbmcgui.Dialog()
    server = dialog.input(rt.text(32002), addon.getSetting("management_url") or "https://api.netbird.io",
                          type=xbmcgui.INPUT_ALPHANUM)
    if not server:
        return False
    if not core.valid_server(server):
        dialog.ok("Harpy Wing", rt.text(32060))
        return False
    method = dialog.select(rt.text(32005), [rt.text(32006), rt.text(32007)],
                           preselect=1 if addon.getSetting("login_method") == "1" else 0)
    if method < 0:
        return False
    key = ""
    if method == 0:
        # Reuse the VPN Manager token prompt / retry-or-cancel pattern.
        while True:
            key = dialog.input(rt.text(32003), "",
                               type=xbmcgui.INPUT_ALPHANUM, option=xbmcgui.ALPHANUM_HIDE_INPUT).strip()
            if key:
                break
            if dialog.yesno("Harpy Wing", rt.text(32051), nolabel=rt.text(32071), yeslabel=rt.text(32070)):
                return False
    name = dialog.input(rt.text(32004), addon.getSetting("device_name") or rt.options()["hostname"],
                        type=xbmcgui.INPUT_ALPHANUM)
    if not name:
        return False
    # Commit the settings entered and try the connection (VPN Manager wizard).
    rt.set_setting("management_url", server.strip())
    rt.set_setting("login_method", str(method))
    rt.set_setting("device_name", name.strip())
    rt.set_setting("enabled", "true")
    if not rt.ready_binary():
        return False
    rt.write_hosts(core.parse_names(rt.settings().getSetting("hosts")))
    rt.install_unit()
    monitor = xbmc.Monitor()
    current = rt.wait_for_daemon(monitor)
    if current["daemon"] == "Unavailable":
        dialog.ok("Harpy Wing", rt.text(32056, ""))
        return False
    code, output = rt.netbird("down")
    if code:
        dialog.ok("Harpy Wing", rt.text(32052, output))
        return False
    chosen = rt.options()  # applied by `up` and saved on success: one snapshot
    if method == 0:
        progress = xbmcgui.DialogProgress()
        progress.create("Harpy Wing", rt.text(32072))
        try:
            success, error = rt.connect(monitor, key, chosen)
        finally:
            progress.close()
    else:
        window = DeviceDialog()

        def cancelled():
            return monitor.abortRequested() or window.cancelled

        def login_status():
            # A slow/unresponsive daemon must not postpone remote cancellation
            # by runtime.status()'s normal five-second command timeout.
            return rt.status(timeout=0.5)

        def login():
            return auth.device_login([rt.NETBIRD, *core.up_args(**chosen)],
                                     login_status, cancelled, window.display_pin, env=rt.cli_env())

        try:
            success, error = window.run(login)
        finally:
            window.cleanup()
            rt.set_setting("setup_key", "")
        if error == "cancelled":
            # The user's own choice, not a failure: a toast, no error dialog.
            rt.notify(32073)
            return False
        if error == "timeout":
            error = rt.text(32074)
    if success:
        rt.set_setting("connection_validated", "true")
        if not connectionValidated(rt.settings()):
            return False
        rt.remember_options(chosen)
        if method == 1:
            # "Connected" goes in the heading: the skin's OK dialog shows about
            # three lines and cut the expiration advice after a blank line.
            dialog.ok("Harpy Wing - " + rt.text(32050), rt.text(32075))
        else:
            dialog.ok("Harpy Wing", rt.text(32050))
        if rt.samba_open():
            dialog.ok("Harpy Wing", rt.text(32086))
    else:
        dialog.ok("Harpy Wing", rt.text(32052, core.redact(error) or rt.text(32073)))
    return success
