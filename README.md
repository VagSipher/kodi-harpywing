# Harpy Wing for Kodi

Unofficial NetBird client for **CoreELEC / LibreELEC**, compatible with
NetBird Cloud and self-hosted servers. One zip contains the official NetBird
**0.80.0 arm64 and amd64** clients, unmodified, with pinned SHA-256 sums.
Kernels `aarch64`/`arm64` (including 32-bit userspace) and `x86_64`;
**armv7 is not supported**. The interface is in English only.

## User guide

Repository URL: `https://vagsipher.github.io/kodi-harpywing/`

1. Kodi > Settings > File manager > Add source: enter that repository URL.
2. Settings > System > Add-ons: enable unknown sources. Add-ons > Install
   from zip file > the source > `repository.harpywing/` >
   `repository.harpywing-0.2.0.zip`.
3. Install from repository > Harpy Wing Repository > Services > Harpy Wing.
4. On first launch without an identity, follow the wizard; you can also open
   Settings > Tools > Connection wizard. Enter the management server URL
   (`https://api.netbird.io` for Cloud, your self-hosted HTTPS management URL),
   choose setup key or account, enter a device name and connect. Obtain a
   setup key from your administrator. Kore/Yatse can send text to Kodi input
   fields. The key is hidden, stored temporarily in a `/run` file with mode
   0600, then the file is removed, even after failure. Enter keys only in the
   wizard; they are never saved in Kodi settings. Legacy saved keys are erased
   at service startup.
5. Account: scan the TV QR code with your phone, sign in, approve the device
   and enter the displayed code if requested. Cancel/Back stops the attempt;
   timeout is five minutes. Your server must support SSO device-code login.
   After success, **disable this device’s login expiration in the NetBird
   console** so the TV box stays connected.
6. Tools > Connection status shows Connected, address and direct/relayed
   link. Tools > Journal shows the last 500 systemd lines plus up to 500
   recent Harpy Wing lines from Kodi, redacts secrets and highlights errors.
   Save journal writes `/storage/harpywing-journal.txt`.

Routes and inbound connections default to off. Permitted peers remain
reachable; routes additionally allow advertised networks and Internet exits.
Inbound removes NetBird’s inbound block: every service listening on this box
(Kodi web interface, SSH, file sharing…) becomes reachable by peers the server
allows. Keep it off unless needed. NetBird’s built-in server SSH stays disabled. Changing
these options announces and applies a reconnection (`down`, then `up`
without a key). NetBird DNS and server routes remain disabled. Optional
names use `name=NetBirdIPv4;name=NetBirdIPv4`, unique hostnames and addresses
in `100.64.0.0/10`; names are restored before Kodi at boot and every minute.

Turning Connect this box off **stops** the daemon and removes startup/names,
but keeps the identity. A WireGuard interface left by a crashed daemon is
deleted too, but only the one recorded as this add-on's while its daemon was
connected (same name, interface index and boot; no default name is assumed,
so another NetBird's `wt0` is never touched). Off reports an error if a
tunnel under the configured or recorded name cannot be confirmed gone. An invalid server
address also stops the tunnel until it is fixed: the running tunnel would
otherwise keep its old options (for example inbound still open). Disabling only the Kodi add-on leaves the tunnel
running. Disconnect asks for confirmation, shows progress, stops the daemon and forgets the
local identity (including the account email NetBird keeps for the next
sign-in) and disables connection. When Off already stopped the daemon, Disconnect
works immediately without waiting for `down`. If the tunnel cannot be confirmed
stopped, it keeps the identity and reports an error instead of success.
Enrollment is required next time after a successful Disconnect.
**Revoke** separately by removing the device in the NetBird console. Updates
keep the previous version number in the private directory and restart the systemd unit
once the new files are installed.

## Build and local repository

```bash
bash build.sh
python3 scripts/generate_repo.py --base-url http://localhost:8000/repo --allow-http
python3 -m unittest discover -s tests
```

On a shared machine, run package generation / the complete test suite through
the required resource broker, reserving `cpu-build` once for the batch.
No client compilation is needed. `build.sh` verifies both official release
tarballs and writes `dist/service.harpywing-<version>+nb0.80.0.zip`.
The repository generator requires that built zip and creates `repo/addons.xml`,
`addons.xml.md5`, and both versioned zips under their addon IDs. It substitutes
the chosen base URL into the repository zip and validates the entire temporary
repository before replacing the visible output. HTTPS is required; `--allow-http`
permits only localhost, loopback or private LAN IP addresses for local tests.
Output must be empty or contain the generator's `.harpywing-repo` marker;
Git metadata, scripts, tests and add-on source directories are protected.
URLs containing a username or password are always refused.
`localhost` is an example: use a LAN address reachable by the TV for a real
local installation. No public URL, DNS configuration or CI is provided yet.

The systemd unit lives in `/storage/.config/system.d`, uses
`ConditionPathExists` and `Restart=always`, and starts independently of Kodi.
Identity and trusted files live in `/storage/.local/share/service.harpywing`
(mode 0700), outside the default Samba shares. Only Kodi settings remain in
addon_data. The old layout is migrated with the daemon stopped; if both copies
exist, the private copy wins and the old one is moved into private `quarantine/`
with a UTC timestamp and a log entry. Old symlinks are unlinked without following
their targets; the public operation lock is never migrated.
NetBird uses `NB_STATE_DIR`; an old link from `/var/lib/netbird` to our addon_data
state is unlinked, and anything else there is left alone. Installation repairs
executable modes lost by Kodi.

After uninstall, two missing-add-on checks 60 seconds apart stop the tunnel,
remove our live hosts entries and disable the unit. A brief directory replacement
during an update does not trigger this. Identity stays in the private directory
after uninstall; use **Disconnect before uninstall** to erase it.

If Samba exports sensitive storage without a password, the wizard and status
show a warning: anyone on that network can read and change the box’s files.
Set a Samba password in CoreELEC/LibreELEC settings > Services.

## Proof

Real run on a CoreELEC 21.3 box (S905X4, kernel 4.9, 32-bit userspace) on
2026-10-14, against a self-hosted NetBird server:

| Check | Result |
|---|---|
| enrollment with a guest key, key erased | OK, kernel WireGuard |
| media server (Jellyfin) on a peer, through the tunnel | 200 via `wt0` |
| that peer's other services, outside the access policy | refused / blocked |
| Kodi playback of a 4K movie through the tunnel | 43 s played, no watch state written |
| throughput, direct (LAN) | 391 Mbit/s |
| throughput, forced relay (self-hosted, TCP 443) | 34 Mbit/s |
| daemon killed | tunnel kept (kernel WireGuard), restarted by systemd |
| 40 s network cut | Jellyfin back immediately |
| reboot | same peer, service up, hosts entry restored |
| hosts entry deleted by hand | restored within 51 s |
| "Connect this box" off | unit, `wt0` and hosts entry removed |

Also proven on the same box with 0.2.8: install and update from Kodi's
"Install from zip file" screen (the wizard opens by itself), account login
by QR code through to "Connected", Cancel/Back on the QR window (closed in
under a second, login process stopped), and Off chosen during the wizard
(kept, applied seconds after it ends).

NetBird Cloud, same box, 0.2.9 (2026-10-14): setup key and account QR code
both reach Connected; a page served by a second Cloud peer (container on
another machine) is fetched through the tunnel, direct P2P link. Cloud enables a
24 h login expiration for account-connected devices, not for setup keys.

Security hardening, same box, 0.3.1 (2026-10-14): update from 0.2.10 moved
the identity out of the Samba-shared addon_data (same peer address, no new
login, old `/var/lib/netbird` link removed; an anonymous Samba listing then
shows only Kodi settings); boot hosts filter kept a valid mapping and dropped
a public IPv4 and an invalid name; Off stops the tunnel even after the unit
file was deleted; removing the add-on directory stopped the tunnel, removed
the hosts entry and disabled the unit within 2 minutes, with a single restart
attempt; the status window shows every line, including the Samba warning.

Second security pass, same box, 0.3.2 (2026-10-14): from a connected 0.2.10
with a plaintext key left in Kodi settings, an identity copy already in the
private directory and a planted symlink in the old state, 0.3.2 erased the key,
left only settings.xml in addon_data, quarantined the old identity inside the
private directory, removed the symlink without touching its target, and kept
the same peer address. Off then Disconnect erased the identity with the daemon
already stopped.

Third security pass, same box, 0.3.3 (2026-10-14): Disconnect while running
takes about 5 s with a "Disconnecting…" notice and Kodi's busy spinner; after
Off it takes 1 s (no wait for the stopped daemon); identity and account email
erased in both cases.

Last review pass, same box, 0.3.5 (2026-10-15): daemon killed with
`kill -9`, then Off during systemd's restart delay: the `wt0` interface it
left was deleted, unit gone, identity kept. Connected with inbound allowed,
then server address made invalid and inbound turned off together: tunnel
stopped, names removed, identity kept; address fixed: reconnected with
inbound blocked. 0.3.6: a foreign WireGuard `wt0` created by hand, with no
add-on configuration, survived Off twice; the add-on's own recorded `wt0`
was removed after `kill -9`.
0.3.8 (2026-10-15): `kill -9` of the daemon without Off: the launcher
deleted the recorded `wt0` at once and systemd's restart came back clean.
Crash, Off, then Disconnect, then a new enrollment: NetBird removed its
stale firewall chains at start (Disconnect keeps its `state.json` cleanup
record, no key) and connected; without that record the new enrollment had
failed with "Chain already exists" until reboot.
End to end with the 0.3.9 zip (2026-10-15), driven by the remote: install
from Kodi's "Install from zip file", wizard opened by itself, account QR
code approved on another device, Connected with inbound blocked; inbound
allowed then blocked again, both applied; Off removed the unit, `wt0`, the
firewall rules and names; Disconnect confirmed with Yes erased the identity
in about a second.

Not proven yet: a box **outside** the home (only LAN direct and forced relay
were tried) and an `x86_64` box.

## Licences

Add-on: GPL-3.0-or-later. Official NetBird clients: BSD-3-Clause, with their
license files in each zip. Reused upstream revisions, files, adaptations and
license distinctions are recorded in [THIRD_PARTY.md](THIRD_PARTY.md).
