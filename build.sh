#!/usr/bin/env bash
# Builds dist/service.harpywing-<version>.zip, installable from Kodi
# ("Install from zip file"). Downloads the official arm64 and amd64 clients
# and refuses it unless its SHA-256 matches NETBIRD_VERSION.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
. "$ROOT/NETBIRD_VERSION"
ADDON="$ROOT/service.harpywing"
WORK="$ROOT/build"
mkdir -p "$WORK" "$ROOT/dist" "$ADDON/LICENSES"
for ARCH in arm64 amd64; do
  TARBALL="netbird_${VERSION}_linux_${ARCH}.tar.gz"
  case "$ARCH" in
    arm64) CHECKSUM=$SHA256_ARM64 ;;
    amd64) CHECKSUM=$SHA256_AMD64 ;;
  esac
  if [ ! -f "$WORK/$TARBALL" ]; then
    curl -fsSL -o "$WORK/$TARBALL.part" \
      "https://github.com/netbirdio/netbird/releases/download/v${VERSION}/${TARBALL}"
    mv "$WORK/$TARBALL.part" "$WORK/$TARBALL"
  fi
  echo "$CHECKSUM  $WORK/$TARBALL" | sha256sum -c --quiet -
  mkdir -p "$WORK/netbird-$ARCH"
  tar -xzf "$WORK/$TARBALL" -C "$WORK/netbird-$ARCH" netbird LICENSE LICENSES
  install -m 0755 "$WORK/netbird-$ARCH/netbird" "$ADDON/bin/netbird-$ARCH"
  cp "$WORK/netbird-$ARCH/LICENSE" "$ADDON/LICENSES/NETBIRD-LICENSE"
  cp -r "$WORK/netbird-$ARCH/LICENSES/." "$ADDON/LICENSES/"
done
cp "$ROOT/LICENSE" "$ADDON/LICENSES/ADDON-LICENSE"
cp "$ROOT/THIRD_PARTY.md" "$ADDON/THIRD_PARTY.md"

ADDON_VERSION=$(sed -n 's/.*<addon [^>]*version="\([^"]*\)".*/\1/p' "$ADDON/addon.xml")
OUT="$ROOT/dist/service.harpywing-${ADDON_VERSION}.zip"
python3 - "$ADDON" "$OUT" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
base = os.path.dirname(src)
if os.path.islink(src):
    sys.exit("refusing symbolic link: " + src)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
    for folder, dirs, files in os.walk(src):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in dirs + sorted(files):
            path = os.path.join(folder, name)
            # A link could pull a private file of the build machine into the zip.
            if os.path.islink(path):
                sys.exit("refusing symbolic link: " + path)
        for name in sorted(files):
            path = os.path.join(folder, name)
            info = zipfile.ZipInfo(os.path.relpath(path, base))
            info.compress_type = zipfile.ZIP_DEFLATED
            # Only the launchers are executable, whatever the checkout modes.
            mode = 0o755 if os.path.basename(folder) == "bin" else 0o644
            info.external_attr = (0o100000 | mode) << 16
            with open(path, "rb") as handle:
                archive.writestr(info, handle.read())
PY
echo "$OUT"
