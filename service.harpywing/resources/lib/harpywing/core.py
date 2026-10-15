"""Pure logic of the Harpy Wing Kodi service: no Kodi import, unit tested."""

import ipaddress
import json
import posixpath
import re
from urllib.parse import urlsplit

UNIT_NAME = "service.harpywing.service"
HOSTS_BEGIN = "# BEGIN service.harpywing"
HOSTS_END = "# END service.harpywing"
_INTERFACE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}")  # Linux IFNAMSIZ

# NetBird hands out overlay addresses from the CGNAT range.
NETBIRD_RANGE = ipaddress.ip_network("100.64.0.0/10")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


def render_unit(addon_dir):
    """systemd unit started at boot, independent of Kodi.

    The condition keeps an orphan unit inert once the add-on is uninstalled
    (Kodi gives a service add-on no uninstall hook).
    """
    return (
        "[Unit]\n"
        "Description=Harpy Wing (NetBird) for Kodi\n"
        "Wants=network-online.target\n"
        "After=network-online.target\n"
        f"ConditionPathExists={addon_dir}/bin/netbird\n"
        "\n"
        "[Service]\n"
        f"ExecStart={addon_dir}/bin/harpywing-daemon\n"
        "Restart=always\n"
        "RestartSec=10\n"
        # systemd does not recheck conditions on auto-restart: once the add-on
        # is uninstalled, 203/EXEC looped every 10 s until reboot (real test).
        "RestartPreventExitStatus=203\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def up_args(management_url, hostname="", setup_key_file="", receive_routes=False, allow_inbound=False):
    """TV defaults: permitted peers, no DNS/routes/inbound unless requested.

    DNS and server routes always remain disabled. Explicit false flags clear
    persisted NetBird restrictions when the user enables routes or inbound.
    """
    args = [
        "up",
        "--management-url", management_url,
        "--disable-dns",
        "--disable-client-routes=false" if receive_routes else "--disable-client-routes",
        "--disable-server-routes",
        "--allow-server-ssh=false",
        "--block-inbound=false" if allow_inbound else "--block-inbound",
    ]
    if hostname:
        args += ["--hostname=" + hostname]
    if setup_key_file:
        args += ["--setup-key-file", setup_key_file]
    return args


def valid_interface(name):
    """No default name: NetBird's wt0 may belong to another service."""
    return isinstance(name, str) and bool(_INTERFACE.fullmatch(name))


def parse_status(output):
    """Return the daemon status ("Connected", "NeedsLogin", ...) and details."""
    try:
        data = json.loads(output)
    except ValueError:
        return {"daemon": "Unavailable", "ip": "", "management": False, "error": output.strip()[:200]}
    management = data.get("management") or {}
    return {
        "daemon": data.get("daemonStatus") or "Unknown",
        "ip": data.get("netbirdIp") or "",
        "management": bool(management.get("connected")),
        "error": management.get("error") or "",
    }


def samba_open(config):
    """Whether an anonymous disk share exposes a sensitive storage directory."""
    sensitive = ("/storage", "/storage/.kodi", "/storage/.kodi/userdata",
                 "/storage/.kodi/addons", "/storage/.config",
                 "/storage/.local/share/service.harpywing")
    sections = {}
    section = "global"
    for line in config.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
        elif "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            key = key.lower()
            if key == "public":
                key = "guest ok"
            sections.setdefault(section, {})[key] = value
    defaults = sections.get("global", {})
    for name, share in sections.items():
        if name == "global":
            continue
        values = dict(defaults, **share)
        path = values.get("path", "").strip("\"'")
        if not path.startswith("/") or values.get("guest ok", "no").lower() not in ("yes", "true", "1", "on"):
            continue
        path = posixpath.normpath(path)
        if any(target == path or target.startswith(path.rstrip("/") + "/") for target in sensitive):
            return True
        if path.startswith("/storage/.local/share/service.harpywing/"):
            return True
    return False


def fill(template, *values):
    """Format a Kodi string; Kodi serves "" for strings it has not reloaded yet."""
    if not template:
        return " ".join(str(value) for value in values)
    try:
        return template % values if values else template
    except (TypeError, ValueError):
        return " ".join([template, *map(str, values)])


def server_link(output):
    """Link type to the first connected peer: "P2P", "Relayed" or ""."""
    try:
        details = (json.loads(output).get("peers") or {}).get("details") or []
    except ValueError:
        return ""
    for peer in details:
        if peer.get("status") == "Connected":
            return peer.get("connectionType") or ""
    return ""


def validate_mapping(name, address):
    """Check the server name and its NetBird address; return an error key or ''."""
    name = (name or "").strip().lower()
    address = (address or "").strip()
    if not name and not address:
        return ""
    if not _HOSTNAME.match(name):
        return "bad_name"
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "bad_address"
    if ip.version != 4 or ip not in NETBIRD_RANGE:
        return "bad_address"
    return ""


def apply_hosts(text, name="", address="", mappings=None):
    """Replace this add-on's block in a hosts file; no mapping removes it."""
    kept = []
    inside = False
    for line in text.splitlines():
        if line.strip() == HOSTS_BEGIN:
            inside = True
            continue
        if line.strip() == HOSTS_END:
            inside = False
            continue
        if not inside:
            kept.append(line)
    while kept and not kept[-1].strip():
        kept.pop()
    if mappings is None:
        mappings = [(name.strip().lower(), address)] if name and address else []
    if mappings:
        kept += ["", HOSTS_BEGIN] + [f"{ip} {host}" for host, ip in mappings] + [HOSTS_END]
    return "\n".join(kept) + "\n"


def parse_names(value):
    """Validate the whole list before changing hosts. Duplicate names are errors."""
    result = []
    seen = set()
    if not value.strip():
        return result
    for entry in value.split(";"):
        parts = entry.split("=")
        if len(parts) != 2:
            raise ValueError("bad_mapping")
        name, address = (part.strip().lower() for part in parts)
        error = validate_mapping(name, address)
        if error or not name or name in seen:
            raise ValueError(error or "duplicate_name")
        seen.add(name)
        result.append((name, address))
    return result


def binary_name(machine):
    if machine in ("aarch64", "arm64"):
        return "netbird-arm64"
    if machine == "x86_64":
        return "netbird-amd64"
    raise ValueError(machine)


def valid_server(value):
    try:
        url = urlsplit(value)
        return (url.scheme == "https" and bool(url.hostname) and not url.username
                and not url.password and not url.query and not url.fragment
                and url.path in ("", "/") and (url.port is None or 1 <= url.port <= 65535))
    except ValueError:
        return False


def parse_device_login(output):
    """Parse only NetBird 0.80 openURL, never unrelated URLs in diagnostics."""
    match = re.search(r"(?:use|Use) this URL to log in:\s*\n\s*(https?://[^\s]+)([^\n]*)", output)
    if not match:
        return None
    url = match.group(1)
    code = re.search(r"and enter the code\s+(\S+)\s+to authenticate", match.group(2))
    return {"url": url, "code": code.group(1) if code else ""}


_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_SECRET = re.compile(
    r'''(?i)((?:["']?(?:setup[-_ ]?key(?:[-_]file)?|access[-_]?token|refresh[-_]?token|id[-_]?token|token|client[-_]?secret|private[-_]?key|device[-_]?code|user[-_]?code|authorization|pass(?:word|wd))["']?)\s*(?:[:=]|\s)\s*)(?:"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|[^\s,;}]+)''')


def redact(text):
    def mask_url(match):
        try:
            url = urlsplit(match.group(0))
        except ValueError:
            return "[REDACTED URL]"
        if re.search(r"activate|device|verif(?:y|ication)|user[_-]?code|code=",
                     url.path + "?" + url.query, re.I):
            return "[REDACTED URL]"
        if "@" in url.netloc:  # user:password@host
            return match.group(0).replace(url.netloc.rsplit("@", 1)[0], "[REDACTED]", 1)
        return match.group(0)

    # Whatever its path, the link NetBird prints for the SSO login carries the
    # device code (an IdP may use e.g. /login/ABCD-EFGH): mask it first.
    text = re.sub(r"(?i)(URL to log in:\s*)https?://\S+", r"\1[REDACTED URL]", str(text))
    # Mask the whole verification link before generic secret substitution can
    # consume its query or leave a device code embedded in the URL path.
    text = re.sub(r"https?://[^\s<>\"']+", mask_url, text, flags=re.I)
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
                  "[REDACTED PRIVATE KEY]", str(text), flags=re.S)
    text = _UUID.sub("[REDACTED]", text)
    # The whole header value: "Basic <base64>" or "Digest ..." left it visible.
    text = re.sub(r"(?i)\b((?:proxy-)?authorization[\"']?\s*[:=]\s*)[^\r\n]*", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED]", text)
    text = _SECRET.sub(lambda m: m.group(1) + "[REDACTED]", text)
    text = re.sub(r"(?i)([?&](?:code|token|access_token|refresh_token|id_token|user_code|device_code)=)[^\s&#]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(enter the code\s+)\S+", r"\1[REDACTED]", text)
    return text
