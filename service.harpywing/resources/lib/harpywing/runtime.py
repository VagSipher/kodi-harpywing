"""Shared Kodi / systemd operations. No network API or credential management."""
import errno
from datetime import datetime, timezone
import fcntl
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time

import xbmc
import xbmcaddon
import xbmcgui
import xbmcvfs

from . import core

ADDON = xbmcaddon.Addon("service.harpywing")
ADDON_DIR = xbmcvfs.translatePath(ADDON.getAddonInfo("path")).rstrip("/")
DATA = xbmcvfs.translatePath(ADDON.getAddonInfo("profile")).rstrip("/")
NETBIRD = os.path.join(ADDON_DIR, "bin", "netbird")
UNIT_PATH = "/storage/.config/system.d/" + core.UNIT_NAME
HOSTS = "/etc/hosts"
PRIVATE = "/storage/.local/share/service.harpywing"
LEGACY_STATE_LINK = "/var/lib/netbird"
PRIVATE_FILES = ("state", "hosts", "options.json", "version", "previous-version")
SYS_NET = "/sys/class/net"
BOOT_ID = "/proc/sys/kernel/random/boot_id"
_name_states = {}
_hosts_notices = set()


def settings():
    """A fresh view of the settings, for every read and write.

    Each xbmcaddon.Addon keeps its own copy, loaded once; its setSetting()
    rewrites them all, undoing what another script changed meanwhile (real
    test 0.2.4: Off chosen during the QR wizard was reverted at its end).
    """
    return xbmcaddon.Addon("service.harpywing")


def text(string_id, *values):
    return core.fill(ADDON.getLocalizedString(string_id), *values)


def log(message, level=xbmc.LOGINFO):
    xbmc.log("[service.harpywing] " + core.redact(message), level)


def notify(string_id, *values, error=False):
    message = text(string_id, *values) or "#%s" % string_id
    xbmcgui.Dialog().notification("Harpy Wing", core.redact(message),
        xbmcgui.NOTIFICATION_ERROR if error else xbmcgui.NOTIFICATION_INFO, 6000)
    log(message, xbmc.LOGERROR if error else xbmc.LOGINFO)


# The NetBird CLI keeps the last account email (SSO login_hint) in the user
# config directory: /storage/.config/netbird on CoreELEC, outside addon_data.
# Disconnect left it there and the next QR proposed the previous account.
USER_CONFIG = os.path.join(PRIVATE, "state", "user-config")


def cli_env():
    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = USER_CONFIG
    return env


def run(args, timeout=60, env=None, raw=False):
    try:
        done = subprocess.run(args, capture_output=True, encoding="utf-8", errors="replace",
                              timeout=timeout, env=env)
        output = (done.stdout if raw else done.stdout + done.stderr).strip()
        return done.returncode, output if raw else core.redact(output)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, core.redact(str(exc))


def netbird(*args, timeout=60):
    return run([NETBIRD, *args], timeout, env=cli_env())


def status_json(timeout=5):
    # Redaction is for display: it can invalidate otherwise valid JSON.
    return run([NETBIRD, "status", "--json"], timeout, env=cli_env(), raw=True)[1]


def status(timeout=5):
    result = core.parse_status(status_json(timeout))
    result["error"] = core.redact(result["error"])
    return result


def samba_open():
    if run(["pidof", "smbd"], timeout=5)[0]:
        return False
    try:
        with open("/run/samba/smb.conf", encoding="utf-8", errors="replace") as stream:
            return core.samba_open(stream.read())
    except OSError:
        return False


def ensure_private():
    os.makedirs(PRIVATE, mode=0o700, exist_ok=True)
    os.chmod(PRIVATE, 0o700)


def migrate_private():
    """Called under Operation, before writing any private files."""
    ensure_private()
    # Inspect components before normalizing '..': link/../ can resolve outside
    # the lexical directory and must not bypass the linked-parent check.
    data = DATA.rstrip("/") or "/"
    if not os.path.isabs(data):
        data = os.path.join(os.getcwd(), data)
    parent = os.path.dirname(data)
    linked_parent = False
    while parent != os.path.dirname(parent):
        linked_parent |= os.path.islink(parent)
        parent = os.path.dirname(parent)
    private = os.path.realpath(PRIVATE)
    source = os.path.realpath(data)
    overlap = os.path.commonpath((source, private)) in (source, private)
    if linked_parent or os.path.islink(data) or not os.path.isdir(data) or overlap:
        # Reject aliases before touching state or the private lock inode.
        # Only unlink DATA itself when its parents and lexical location are safe.
        lexical_data = os.path.abspath(data)
        lexical_private = os.path.abspath(PRIVATE)
        if (os.path.islink(data) and not linked_parent and
                os.path.commonpath((lexical_data, lexical_private)) not in (lexical_data, lexical_private)):
            os.unlink(data)
        log("migration: skipped unsafe or missing DATA directory: " + DATA)
        return
    if os.path.lexists(os.path.join(DATA, "state")) or any(os.path.lexists(os.path.join(DATA, name)) and
           not os.path.lexists(os.path.join(PRIVATE, name)) for name in PRIVATE_FILES):
        code, output = run(["systemctl", "stop", core.UNIT_NAME])
        if code and not unit_missing(output):
            raise RuntimeError(output)
    # Never rename the lock inode used by Operation, nor import a public lock.
    old_lock = os.path.join(DATA, "operation.lock")
    if os.path.islink(old_lock):
        os.unlink(old_lock)
        log("migration: removed old operation.lock symlink")
    elif os.path.isfile(old_lock) and not os.path.getsize(old_lock):
        os.unlink(old_lock)
    for name in PRIVATE_FILES:
        old, new = os.path.join(DATA, name), os.path.join(PRIVATE, name)
        if not os.path.lexists(old):
            continue
        if os.path.islink(old):
            os.unlink(old)
            log("migration: removed old %s symlink" % name)
            continue
        if name == "state" and os.path.isdir(old):
            # os.walk does not follow directory links; remove them before rename.
            def scan_failed(exc):
                raise exc  # An incomplete scan could import an unseen symlink.
            for root, dirs, files in os.walk(old, followlinks=False, onerror=scan_failed):
                for entry in dirs + files:
                    path = os.path.join(root, entry)
                    if os.path.islink(path):
                        os.unlink(path)
                        if entry in dirs:
                            dirs.remove(entry)  # Do not visit a link we just removed.
                        log("migration: removed old state symlink: " + path)
        if os.path.lexists(new):
            quarantine = os.path.join(PRIVATE, "quarantine")
            os.makedirs(quarantine, mode=0o700, exist_ok=True)
            os.chmod(quarantine, 0o700)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            new = os.path.join(quarantine, name + "-" + stamp)
            log("migration: keeping private %s; quarantining old copy in %s" % (name, new))
        # Same storage filesystem: rename keeps the identity intact on failure.
        os.rename(old, new)
    if os.path.islink(LEGACY_STATE_LINK) and os.readlink(LEGACY_STATE_LINK) == os.path.join(DATA, "state"):
        os.unlink(LEGACY_STATE_LINK)


def ensure_executable():
    for name in ("netbird", "netbird-arm64", "netbird-amd64", "harpywing-daemon"):
        path = os.path.join(ADDON_DIR, "bin", name)
        mode = os.stat(path).st_mode
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def ready_binary(interactive=True):
    def report(string_id, *values):
        if interactive:
            notify(string_id, *values, error=True)
        else:
            log(text(string_id, *values), xbmc.LOGERROR)

    try:
        core.binary_name(os.uname().machine)
        ensure_executable()
    except (ValueError, OSError):
        report(32054, os.uname().machine)
        return False
    code, output = netbird("version", timeout=10)
    if code:
        report(32056, output)
        return False
    return True


def save_file(name, content):
    ensure_private()
    path = os.path.join(PRIVATE, name)
    fd, temp = tempfile.mkstemp(prefix=".harpywing-", dir=PRIVATE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.remove(temp)


def read_file(name):
    try:
        with open(os.path.join(PRIVATE, name), encoding="utf-8") as stream:
            return stream.read()
    except OSError as exc:
        if name == "hosts" and not isinstance(exc, FileNotFoundError):
            log("ignoring unreadable hosts cache", xbmc.LOGERROR)
        return ""
    except UnicodeError:
        log("ignoring non-UTF-8 private file: " + name, xbmc.LOGERROR)
        return ""


class OtherServer(ValueError):
    """NetBird answers for another management server: its names are not ours."""


def _dns_server(timeout=2, management_url=None):
    raw = status_json(timeout=timeout)
    current = core.parse_status(raw)
    address = current["ip"].split("/", 1)[0]
    if current["daemon"] != "Connected" or not address or core.validate_mapping("peer", address):
        raise ValueError("NetBird is not connected or has no overlay IPv4")
    wanted = core.normalize_server(management_url if management_url is not None else options()["management_url"])
    reported = (json.loads(raw).get("management") or {}).get("url")
    if not wanted or core.normalize_server(reported) != wanted:
        raise OtherServer("NetBird is connected to another server")
    return address, 53


def _cached_names(management_url):
    lines = read_file("hosts").splitlines()
    if not lines or not management_url or lines[0] != "# server " + management_url:
        return {}
    previous = {}
    for line in lines[1:]:
        fields = line.split()
        if (len(fields) != 2 or core.validate_mapping(fields[1], fields[0])
                or fields[1].lower() in previous):
            log("ignoring invalid hosts cache", xbmc.LOGERROR)
            return {}
        previous[fields[1].lower()] = fields[0]
    return previous


def _dns_remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("DNS resolution budget exhausted")
    return remaining


def resolve_names(mappings, management_url=None):
    deadline = time.monotonic() + 3
    origin = core.normalize_server(management_url if management_url is not None else options()["management_url"])
    has_dns = any(ip is None for host, ip in mappings)
    previous = _cached_names(origin) if has_dns else {}
    server, failure = None, ""
    if has_dns:
        try:
            server = _dns_server(timeout=_dns_remaining(deadline), management_url=origin)
        except (ValueError, TypeError, AttributeError, OSError) as exc:
            failure = str(exc)
            if isinstance(exc, OtherServer):
                # The tunnel leads to another server: cached addresses may now
                # belong to other peers. Keep only forced addresses (3rd review).
                previous = {}
    result = []
    for host, ip in mappings:
        if ip is None:
            try:
                remaining = _dns_remaining(deadline)
                if server is None:
                    raise ValueError(failure)
                identifier = int.from_bytes(os.urandom(2), "big")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(remaining)
                    sock.connect(server)
                    sock.send(core.dns_query(host, identifier))
                    sock.settimeout(_dns_remaining(deadline))
                    packet, ancillary, flags, source = sock.recvmsg(core.DNS_MAX_PACKET)
                    if flags & socket.MSG_TRUNC:
                        raise ValueError("DNS packet too large")
                    ip = core.dns_address(packet, host, identifier)
                state = "resolved to " + ip
            except (OSError, ValueError) as exc:
                ip = previous.get(host)
                state = "DNS failed (%s); %s" % (exc, "keeping " + ip if ip else "no saved address")
            if _name_states.get(host) != state:
                log("%s: %s" % (host, state))
                _name_states[host] = state
        if ip is not None:
            if core.validate_mapping(host, ip):
                raise ValueError("invalid hosts mapping")
            result.append((host, ip))
    return result


def write_hosts(mappings=()):
    mappings = list(mappings)
    origin = core.normalize_server(options()["management_url"])
    resolved = resolve_names(mappings, origin)
    path = os.path.realpath(HOSTS)
    with open(path, encoding="utf-8", errors="replace") as stream:
        current = stream.read()
    outside = {host for host, ip in core.hosts_mappings(core.apply_hosts(current))}
    setting = settings().getSetting("hosts")
    for host, ip in mappings:
        notice = (setting, host)
        if host in outside and notice not in _hosts_notices:
            _hosts_notices.add(notice)
            try:
                notify(32089, host)
            except Exception as exc:
                log(text(32089, host) + " (notification failed: %s)" % exc, xbmc.LOGERROR)
    # Persist before touching /etc/hosts: the daemon restores it before Kodi.
    saved = "# server %s\n" % origin + "".join("%s %s\n" % (ip, host) for host, ip in resolved)
    if not resolved or read_file("hosts") != saved:
        save_file("hosts", saved)
    wanted = core.apply_hosts(current, mappings=resolved)
    if current != wanted:
        _replace_hosts(path, wanted)
        log("hosts updated")


def _replace_hosts(path, wanted):
    fd, temp = tempfile.mkstemp(prefix=".harpywing-hosts-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(wanted)
            os.fchmod(stream.fileno(), 0o644)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _saved_block(path):
    """/etc/hosts as it should be with the saved names (boot restore rules: the
    server line and invalid lines are ignored, no DNS)."""
    mappings, seen = [], set()
    for line in read_file("hosts").splitlines():
        fields = line.split()
        if len(fields) == 2 and not core.validate_mapping(fields[1], fields[0]) and fields[1].lower() not in seen:
            seen.add(fields[1].lower())
            mappings.append((fields[1].lower(), fields[0]))
    with open(path, encoding="utf-8", errors="replace") as stream:
        current = stream.read()
    if not mappings and core.HOSTS_BEGIN not in current:
        return current, current  # nothing of ours: never reformat another file
    return current, core.apply_hosts(current, mappings=mappings)


def guard_hosts():
    """Put the saved names back when another writer replaced /etc/hosts.

    CoreELEC copies /storage/.config/hosts.conf over it about 15 s after Kodi
    starts, which dropped the names until the next minute pass. Checked every
    few seconds; the lock (and its log line) is taken only to repair.
    """
    path = os.path.realpath(HOSTS)
    current, wanted = _saved_block(path)
    if current == wanted:
        return False
    with Operation("hosts-guard") as acquired:
        if not acquired:
            return False
        current, wanted = _saved_block(path)
        if current == wanted:
            return False
        _replace_hosts(path, wanted)
    log("hosts block restored: /etc/hosts was rewritten by another program")
    return True


def install_unit():
    wanted = core.render_unit(ADDON_DIR)
    try:
        with open(UNIT_PATH, encoding="utf-8") as stream:
            current = stream.read()
    except OSError:
        current = ""
    if current != wanted:
        os.makedirs(os.path.dirname(UNIT_PATH), exist_ok=True)
        with open(UNIT_PATH, "w", encoding="utf-8") as stream:
            stream.write(wanted)
        code, output = run(["systemctl", "daemon-reload"])
        if code:
            raise RuntimeError(output)
    # Called on every check: only touch systemd when something is missing.
    for check, action in (("is-enabled", "enable"), ("is-active", "start")):
        if run(["systemctl", check, "--quiet", core.UNIT_NAME])[0] == 0:
            continue
        code, output = run(["systemctl", action, core.UNIT_NAME])
        if code:
            raise RuntimeError(output)
    version = ADDON.getAddonInfo("version")
    previous = read_file("version").strip()
    # 0.1.0 did not persist a version marker: an existing untracked unit
    # must also restart once when this community release replaces its files.
    if (previous and previous != version) or (current and not previous):
        save_file("previous-version", previous or "unknown")
        code, output = run(["systemctl", "restart", core.UNIT_NAME])
        if code:
            raise RuntimeError(output)
        log("daemon restarted after add-on update: %s -> %s" % (previous, version))
    save_file("version", version)


def unit_missing(output):
    return any(message in output.lower() for message in ("not loaded", "not found", "does not exist"))


def remove_unit():
    # Stop first: without its file, `disable --now` fails before stopping and
    # left the tunnel up (real test, 0.3.0); a loaded unit still stops.
    for action in ("stop", "disable"):
        code, output = run(["systemctl", action, core.UNIT_NAME])
        if code and not unit_missing(output):
            raise RuntimeError(output)
        if action == "stop":
            remove_interface()
    if os.path.exists(UNIT_PATH):
        os.remove(UNIT_PATH)
    code, output = run(["systemctl", "daemon-reload"])
    if code:
        raise RuntimeError(output)


def read_system(*parts):
    try:
        with open(os.path.join(*parts), encoding="utf-8", errors="replace") as stream:
            return stream.read().strip()
    except OSError:
        return ""


def configured_interface():
    """WireGuard interface from NetBird's own config (NB_STATE_DIR/default.json)."""
    try:
        with open(os.path.join(PRIVATE, "state", "default.json"), encoding="utf-8") as stream:
            name = json.load(stream).get("WgIface")
    except (OSError, ValueError, AttributeError):
        return ""
    return name if core.valid_interface(name) else ""


def interface_identity(name):
    """Name, ifindex and boot of a present WireGuard interface, else None.

    Only kernel WireGuard survives its daemon (a userspace TUN closes with
    it), so any other interface type is never considered ours.
    """
    if not core.valid_interface(name):
        return None
    ifindex = read_system(SYS_NET, name, "ifindex")
    boot = read_system(BOOT_ID)
    if not ifindex or not boot or "DEVTYPE=wireguard" not in read_system(SYS_NET, name, "uevent").split():
        return None
    return {"name": name, "ifindex": ifindex, "boot": boot}


def remember_interface():
    """Proof of ownership, taken while our own daemon reports Connected."""
    identity = interface_identity(configured_interface())
    if identity:
        content = json.dumps(identity, sort_keys=True)
        if read_file("interface").strip() != content:
            save_file("interface", content)


def recorded_interface():
    try:
        recorded = json.loads(read_file("interface"))
        return recorded if isinstance(recorded, dict) and core.valid_interface(recorded.get("name")) else {}
    except ValueError:
        return {}


def owned_interface():
    """The recorded interface, if the very same one is still present."""
    recorded = recorded_interface()
    return recorded["name"] if recorded and interface_identity(recorded["name"]) == recorded else ""


def interface_present():
    """Any WireGuard interface under our configured or recorded name, even
    when the record no longer proves it ours (Oracle review of 0.3.6)."""
    names = {configured_interface(), recorded_interface().get("name", "")} - {""}
    return any(interface_identity(name) for name in names)


def remove_interface():
    """A killed daemon leaves its kernel WireGuard interface up (real run,
    README): once the daemon is certainly gone, delete what it left behind,
    but only the interface recorded as ours (same name, index and boot)."""
    if not owned_interface() or not daemon_absent():
        return
    # Check again right before deleting by name: the probes above take time,
    # and a replacement under the same name must not be deleted (5th review).
    name = owned_interface()
    if not name:
        return
    code, output = run(["ip", "link", "delete", name])
    if code and interface_identity(name):
        raise RuntimeError(output)
    log("removed interface left by the daemon: " + name)


def certainly_stopped():
    """No unit, no daemon process and no tunnel interface left. An interface
    not proven ours is never deleted: it is reported instead."""
    return daemon_absent() and not interface_present()


def daemon_absent():
    """A missing unit alone does not exclude a surviving add-on daemon."""
    _, output = run(["systemctl", "is-active", core.UNIT_NAME], timeout=5)
    missing = core.UNIT_NAME in output and unit_missing(output)
    if output.strip() not in ("inactive", "failed", "unknown") and not missing:
        return False
    # The launcher execs netbird-arm64 or netbird-amd64; include both binaries.
    pattern = (re.escape(NETBIRD) + r"(-arm64|-amd64)?[[:space:]]+"
               r"([^[:space:]]+[[:space:]]+)*service[[:space:]]+run([[:space:]]|$)")
    code, output = run(["pgrep", "-f", pattern], timeout=5)
    return code == 1 and not output  # A failed process check is not proof.


def turn_off():
    """No tunnel and no names. Every step runs even if another fails, and a
    tunnel still up is an error: Off must really close access (4th review)."""
    errors = []
    for step in (remove_unit, write_hosts):
        try:
            step()
        except Exception as exc:
            errors.append(str(exc))
    if not certainly_stopped():
        errors.append("Cannot confirm the tunnel is stopped.")
    if errors:
        raise RuntimeError("; ".join(errors))


def options():
    current = settings()
    return {"management_url": current.getSetting("management_url").strip() or "https://api.netbird.io",
            "hostname": current.getSetting("device_name").strip() or os.uname().nodename,
            "receive_routes": current.getSettingBool("receive_routes"),
            "allow_inbound": current.getSettingBool("allow_inbound")}


def wait_for_daemon(monitor, seconds=30):
    for _ in range(seconds):
        current = status()
        if current["daemon"] != "Unavailable":
            return current
        if monitor.waitForAbort(1):
            break
    return status()


def connect(monitor, key="", chosen=None):
    """`chosen`: the options snapshot the caller will save on success."""
    key_file = ""
    try:
        current = wait_for_daemon(monitor)
        if current["daemon"] == "Unavailable":
            return False, text(32056, "")
        if key:
            fd, key_file = tempfile.mkstemp(prefix="harpywing-", dir="/run")
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(key)
        code, output = netbird(*core.up_args(setup_key_file=key_file, **(chosen or options())), timeout=90)
    finally:
        try:
            if key_file:
                os.remove(key_file)
        finally:
            # Cleanup failure must not retain the key in Kodi settings.
            set_setting("setup_key", "")
    if code:
        return False, output
    return status()["daemon"] == "Connected", output


def set_setting(key, value):
    """Write a setting only when it changes: every write fires onSettingsChanged."""
    current = settings()
    if current.getSetting(key) != value:
        current.setSetting(key, value)


def remember_options(chosen):
    """Save the very options `up` used, not a later read of the settings."""
    save_file("options.json", json.dumps(chosen, sort_keys=True))
    remember_interface()


def forget_identity():
    # Called only by the TV action after its explicit confirmation.
    if not certainly_stopped():
        try:
            code, output = netbird("down", timeout=3)
            if code:
                log("disconnect: netbird down failed: " + output, xbmc.LOGERROR)
        except Exception as exc:
            log("disconnect: netbird down failed: " + str(exc), xbmc.LOGERROR)
    unit_error = ""
    try:
        remove_unit()
    except Exception as exc:
        # Stopped is checked below; a unit left enabled is still reported.
        unit_error = "removing unit failed: " + str(exc)
        log("disconnect: " + unit_error, xbmc.LOGERROR)
    if not certainly_stopped():
        raise RuntimeError("Cannot confirm the tunnel is stopped; local identity kept.")
    # Off may already have stopped the daemon. Try every local erase even if
    # another fails, and report only local cleanup failures at the end.
    errors = [unit_error] if unit_error else []
    def erase(action):
        try:
            action()
        except Exception as exc:
            errors.append(str(exc))

    state = os.path.join(PRIVATE, "state")
    for name in ("state", "quarantine"):
        path = os.path.join(PRIVATE, name)
        if os.path.islink(path):
            erase(lambda: os.unlink(path))
        elif name == "state" and os.path.isdir(path):
            # Keep NetBird's cleanup record (interface and firewall state, no
            # key): after a crash it removes its stale iptables chains at the
            # next start; without it, a new enrollment failed with "Chain
            # already exists" until reboot (real test, 0.3.8).
            for entry in os.listdir(path):
                if entry != "state.json":
                    child = os.path.join(path, entry)
                    if os.path.isdir(child) and not os.path.islink(child):
                        erase(lambda: shutil.rmtree(child))
                    else:
                        erase(lambda: os.unlink(child))
            if not os.listdir(path):
                erase(lambda: os.rmdir(path))
        elif os.path.isdir(path):
            erase(lambda: shutil.rmtree(path))
        elif os.path.lexists(path):
            erase(lambda: os.unlink(path))
    erase(write_hosts)
    # Keep the lock inode: unlinking it would let another operation overlap.
    for name in ("hosts", "options.json", "version", "previous-version", "interface"):
        path = os.path.join(PRIVATE, name)
        if os.path.lexists(path):
            erase(lambda: os.unlink(path))
    for key, value in (("enabled", "false"), ("setup_key", ""), ("connection_validated", "")):
        erase(lambda: set_setting(key, value))
    if errors:
        raise RuntimeError("; ".join(errors))


class Operation:
    """Serialize Kodi scripts touching one identity (not a machine resource lease)."""
    def __init__(self, owner="action"):
        self.owner = owner
        self.stream = None

    def __enter__(self):
        ensure_private()
        self.stream = open(os.path.join(PRIVATE, "operation.lock"), "a", encoding="utf-8")
        try:
            try:
                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                self._release()
                log("operation lock refused: " + self.owner)
                return False
            log("operation lock acquired: " + self.owner)
            migrate_private()
        except BaseException:
            # __exit__ is not called if acquisition or logging raises here.
            self._release()
            raise
        return True

    def __exit__(self, *args):
        self._release()

    def _release(self):
        stream, self.stream = self.stream, None
        if stream is not None:
            try:
                # Explicit unlock also releases the lock if an FD was duplicated.
                # No GUI work may precede cleanup: Kodi can interrupt GUI calls.
                fcntl.flock(stream, fcntl.LOCK_UN)
            finally:
                stream.close()
