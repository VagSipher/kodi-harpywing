"""Streaming bridge for NetBird's device flow; deliberately independent of Kodi."""
import codecs
import os
import selectors
import signal
import subprocess
import time

from . import core


def stop_process(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=0.5)


def device_login(args, status, cancelled, display, timeout=300, env=None):
    """Stream NetBird's device flow until connected, cancelled or timed out.

    Kodi runs this on a worker thread while the script thread sits in the
    QR window's doModal(): only a modal Python window receives the remote's
    Back / Cancel, which then set the flag polled by cancelled().
    """
    env = dict(os.environ if env is None else env)
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               env=env, start_new_session=True)
    output = ""
    shown = None
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    deadline = time.monotonic() + timeout
    next_status = 0
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if cancelled():
                return False, "cancelled"
            for key, _ in selector.select(timeout=0.1):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if chunk:
                    output = (output + decoder.decode(chunk))[-32768:]
                    # openURL ends its URL/code line with a newline. Wait for it,
                    # so a pipe split cannot truncate a URL or lose the user code.
                    complete = output[:output.rfind("\n") + 1]
                    login = core.parse_device_login(complete)
                    if login and login != shown:
                        display(login)
                        shown = login
                else:
                    selector.unregister(key.fileobj)
            now = time.monotonic()
            if now >= next_status:
                if status()["daemon"] == "Connected":
                    return True, ""
                next_status = now + 2
            if process.poll() is not None and not selector.get_map():
                if status()["daemon"] == "Connected":
                    return True, ""
                # The complete verification URL can carry a code in its path,
                # which a generic token redactor cannot recognize.
                if shown:
                    output = output.replace(shown["url"], "[REDACTED URL]")
                return False, core.redact(output.strip() or "NetBird exited: %s" % process.returncode)
        return False, "timeout"
    finally:
        selector.close()
        try:
            stop_process(process)
        finally:
            process.stdout.close()
