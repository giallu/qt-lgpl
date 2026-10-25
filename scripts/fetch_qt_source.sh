#!/usr/bin/env bash
# Download, verify and unpack qt-everywhere-src-<version> in the current directory.
#
#   scripts/fetch_qt_source.sh <qt version>
#
# The .sha256 is served by download.qt.io itself; the tarball may come from a
# mirror, so it is checked against that published hash. When run in GitHub
# Actions, QT_SRC_URL and QT_SRC_SHA256 are exported to later steps.
set -euo pipefail

version=$1
line=${version%.*}
PY=${PY:-$(command -v python3 || command -v python)}

# Since 6.8.4 the delayed open-source LTS releases are named
# qt-everywhere-opensource-src-*; the directory inside is unchanged.
url=
for location in official_releases archive; do
  for file in qt-everywhere-src-$version.tar.xz qt-everywhere-opensource-src-$version.tar.xz; do
    candidate=https://download.qt.io/$location/qt/$line/$version/single/$file
    if curl -fsSL -o "$file.sha256" "$candidate.sha256" 2>/dev/null; then url=$candidate; break 2; fi
  done
done
[ -n "$url" ] || { echo "::error::Qt $version not found on download.qt.io"; exit 1; }

expected=$(grep -oE '[0-9a-f]{64}' "$file.sha256" | head -1)
[ -n "$expected" ] || { echo "::error::no SHA-256 published for $url"; exit 1; }
echo "Downloading $url (expected sha256 $expected)"
curl -fsSL --retry 3 -o "$file" "$url"
"$PY" - "$file" "$expected" <<'PYEOF'
import hashlib, sys
path, expected = sys.argv[1], sys.argv[2]
h = hashlib.sha256()
with open(path, "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
if h.hexdigest() != expected:
    sys.exit(f"SHA-256 mismatch for {path}: got {h.hexdigest()}, expected {expected}")
print(f"SHA-256 OK: {expected}")
PYEOF
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "QT_SRC_SHA256=$expected" >> "$GITHUB_ENV"
  echo "QT_SRC_URL=$url" >> "$GITHUB_ENV"
fi
tar xf "$file"
rm -f "$file" "$file.sha256"
