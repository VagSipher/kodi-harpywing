# Third-party code / pinned revisions

Harpy Wing is GPL-3.0-or-later. Upstream headers are retained; adaptations
are marked in the files. No GPL-2.0-only code is included.

| Project | Pinned commit | License | Reused files and adaptations |
|---|---|---|---|
| [Log Viewer, matrix](https://github.com/i96751414/script.logviewer/tree/8090c1fe983d60147f302c963a2be00c17c77eed) (i96751414, continuation of fightnight) | `8090c1fe983d60147f302c963a2be00c17c77eed` | GPL-2.0-or-later (addon.xml declaration) | `resources/lib/logreader.py` → `harpywing/logreader.py` (UTF-8 decoder); `logviewer.py` formatting / `parse_errors` → `logformat.py`, `TextWindow` → `logwindow.py` (local save button); both textwindow XMLs and their PNG textures → `resources/skins/Default/` |
| [VPN Manager](https://github.com/Zomboided/service.vpn.manager/tree/81a049c379bcd91003b1e77a0a50e709d8cc4355) (Zomboided) | `81a049c379bcd91003b1e77a0a50e709d8cc4355` | GPL-3.0-or-later **in the reused file headers**; repository LICENSE.txt differs and is not the license relied on | `libs/common.py`: `wizard()` token retry/cancel, commit/connect/validate progression and `connectionValidated()` → `harpywing/wizard.py`; `libs/logbox.py`: modal log dialog/onInit pattern → `logwindow.py`. OpenVPN/provider-specific logic removed |
| [Segno](https://github.com/heuer/segno/tree/b11dc2913c22b22b3bc0a6efaa989904c44977bf) (Lars Heuer) | `b11dc2913c22b22b3bc0a6efaa989904c44977bf` | BSD-3-Clause | Whole `segno/` package, unchanged, in `resources/lib/vendor/segno/`, with LICENSE. QR/PNG without PyQRCode/PyPNG dependencies |
| [Composite for Plex](https://github.com/anxdpanic/plugin.video.composite_for_plex/tree/49487b5d3c6bf39ebd9c718d5f0ebf4a4b2d95fe) (PleXBMC/hippojay, Composite authors) | `49487b5d3c6bf39ebd9c718d5f0ebf4a4b2d95fe` | GPL-2.0-or-later | `resources/lib/composite_addon/plex/plexsignin.py`: device-code display, cancellation, focus/navigation ideas → `harpywing/dialogs.py`, rewritten with native Kodi controls; copyright/SPDX retained. No PyXBMCt or Plex API code |
| [Seranov](https://github.com/seranov/seranov-kodi/tree/9e1f05f0c4dbe5695a8cb4764ed7a50985c6abd7) | `9e1f05f0c4dbe5695a8cb4764ed7a50985c6abd7` | MIT | `scripts/generate_repo.py` adapted to configurable URL, ready-built service zip and index/zip validation; `repository.seranov/addon.xml` → `repository.harpywing/addon.xml`; LICENSE included |

License texts: `service.harpywing/resources/licenses/`, Segno's own LICENSE,
and `repository.harpywing/LICENSE`. The GPL-3.0-or-later license also covers
adapted VPN Manager files. THIRD_PARTY.md is copied into the service zip.

Official **NetBird 0.80.0** client: BSD-3-Clause, unchanged Linux arm64/amd64
release binaries. SHA-256 of both release tarballs are pinned in
`NETBIRD_VERSION`, taken from the official `netbird_0.80.0_checksums.txt`.
Its LICENSE and bundled dependency LICENSES are copied into the universal
zip under `LICENSES/`. No compilation or Harpy patch is involved.
