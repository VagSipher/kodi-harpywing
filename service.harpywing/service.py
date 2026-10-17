"""Kodi service: generic NetBird enrollment, boot service and local names."""
import json
import os
import sys

import xbmc
import xbmcaddon
import xbmcvfs

ADDON = xbmcaddon.Addon()
ADDON_DIR = xbmcvfs.translatePath(ADDON.getAddonInfo("path"))
sys.path.insert(0, os.path.join(ADDON_DIR, "resources", "lib"))
from harpywing import core, runtime as rt


class Service(xbmc.Monitor):
    def __init__(self):
        # Erase legacy plaintext keys before initialization or operations can fail.
        rt.set_setting("setup_key", "")
        super().__init__()
        self.busy = False
        self.last_notice = None
        self.applied = None
        self.retry = False

    def say(self, string_id, *values, error=False):
        """Log every time; show a non-modal toast only when the message changes.

        The service re-checks every minute: a persistent error must not flash
        on the TV each minute, but the user must see a new state once.
        """
        message = rt.text(string_id, *values)
        if message == self.last_notice:
            rt.log(message, xbmc.LOGERROR if error else xbmc.LOGINFO)
            return
        self.last_notice = message
        try:
            rt.notify(string_id, *values, error=error)  # logs the message too
        except Exception as exc:  # a toast must never break the service
            rt.log("%s (notification failed: %s)" % (message, exc), xbmc.LOGERROR)

    def onSettingsChanged(self):
        # Our own writes (validation flag, erased key) also fire this event:
        # react only when something the user sets has changed.
        if self.signature() != self.applied:
            self.apply()

    @staticmethod
    def signature():
        chosen = rt.settings()
        return json.dumps([chosen.getSettingBool("enabled"), rt.options(), chosen.getSetting("hosts"),
                           chosen.getSetting("login_method")],
                          sort_keys=True)

    def apply(self, startup=False):
        if self.busy:
            # A change made while applying (e.g. during waitForAbort) must not
            # be dropped: the current pass may already have used old options.
            self.retry = True
            return
        self.busy = True
        launch_wizard = False
        try:
            with rt.Operation("service") as acquired:
                # A refused change (e.g. Off during the wizard) stays pending:
                # its signature is recorded only once applied, retried soon.
                self.retry = not acquired and self.signature() != self.applied
                if acquired:
                    self.applied = self.signature()
                    launch_wizard = bool(self._apply(startup))
        except Exception as exc:
            self.say(32052, core.redact(str(exc)), error=True)
        finally:
            self.busy = False
        if launch_wizard and not self.abortRequested():
            rt.log("launching connection wizard via RunScript (outside operation lock)")
            xbmc.executebuiltin("RunScript(special://home/addons/service.harpywing/action.py,wizard)")

    def run(self):
        self.apply(startup=True)
        # Short waits: a refusal reported by onSettingsChanged during a wait
        # must not stay pending until a full minute ends (32 s on the box, 0.2.5).
        waited = 0
        while not self.waitForAbort(5):
            waited += 5
            if self.retry or waited >= 60:
                waited = 0
                self.apply()
            elif not self.busy:
                try:
                    # Off must never bring names back, even from a cache left behind.
                    if rt.settings().getSettingBool("enabled"):
                        rt.guard_hosts()
                except Exception as exc:  # the guard must never stop the service
                    rt.log("hosts guard failed: %s" % core.redact(str(exc)), xbmc.LOGERROR)

    def _apply(self, startup):
        chosen = rt.settings()
        if not chosen.getSettingBool("enabled"):
            rt.turn_off()
            return
        if not core.valid_server(rt.options()["management_url"]):
            # The running tunnel keeps its old options: a change closing
            # inbound connections would never apply (4th review). Stop it.
            self.say(32088, error=True)
            rt.turn_off()
            return
        try:
            mappings = core.parse_names(chosen.getSetting("hosts"))
        except ValueError:
            # Keep the current names, but still apply network options: a typo
            # in the list must not keep inbound connections open.
            self.say(32055, error=True)
            mappings = None
        # One snapshot for the whole pass: what is compared, applied and saved
        # must be the same options, whatever changes meanwhile (5th review).
        chosen = rt.options()
        saved = rt.read_file("options.json").strip()
        wanted = json.dumps(chosen, sort_keys=True)
        # A failure while options change must not leave the old ones applied
        # (e.g. inbound still open): stop the tunnel instead (5th review).
        pending = bool(saved) and saved != wanted
        if not rt.ready_binary(interactive=False):
            if pending:
                rt.turn_off()
            return
        try:
            if mappings is not None:
                rt.write_hosts(mappings)
            rt.install_unit()
        except Exception:
            if pending:
                rt.turn_off()
            raise
        current = rt.wait_for_daemon(self)
        if current["daemon"] == "Unavailable":
            self.say(32056, "", error=True)
            if pending:
                rt.turn_off()
            return
        changed = saved != wanted if current["daemon"] == "Connected" else pending
        if current["daemon"] == "Connected" and not changed:
            rt.remember_options(chosen)
            rt.set_setting("connection_validated", "true")
            return
        if current["daemon"] in ("NeedsLogin", "LoginFailed", "SessionExpired"):
            # The script owning the wizard acquires its own operation lock.
            # Never run modal UI on the long-lived service's Python thread.
            return startup
        if changed:
            code, output = rt.netbird("down")
            if code:
                self.say(32052, output, error=True)
                rt.turn_off()
                return
            self.say(32077)
        success, output = rt.connect(self, "", chosen)
        if success:
            rt.remember_options(chosen)
            rt.set_setting("connection_validated", "true")
            self.say(32050)
        else:
            self.say(32052, output, error=True)


if __name__ == "__main__":
    Service().run()
