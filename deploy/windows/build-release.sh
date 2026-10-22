#!/usr/bin/env bash
# Builds release/SpringSync-<ver>-windows.zip from a git tag (SPEC 11.5; no PyInstaller / packed exe):
#   app/     = `git archive <tag>` of this repo (tracked files only: no .env, no DB, no secrets)
#   vendor/  = official, unmodified files, each checked against deploy/windows/pins.psd1 or
#              requirements-windows.lock: python-<v>-embed-amd64.zip, rclone-<v>-windows-amd64.zip,
#              pip-<v>.whl, wheels/*.whl
#   install.ps1, update.ps1, uninstall.ps1 (copies), VERSION, INSTALL-WINDOWS.md/.pdf, SHA256SUMS.txt
# Deterministic: fixed file order and timestamps (the tag's commit time), so the zip hash is reproducible.
#
#   bash deploy/windows/build-release.sh v0.10.0 /path/to/vendor /path/to/release-dir
set -euo pipefail
TAG="${1:?tag}"; VENDOR="${2:?vendor dir}"; OUTDIR="${3:?output dir}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "tag must be vX.Y.Z" >&2; exit 2; }
VER="${TAG#v}"; NAME="SpringSync-$VER-windows"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
S="$T/$NAME"; mkdir -p "$S/app" "$S/vendor/wheels"

git -C "$ROOT" archive "$TAG" | tar -x -C "$S/app"
rm -rf "$S/app/.github"
grep -q "__version__ = \"$VER\"" "$S/app/odnas/__init__.py" || { echo "odnas.__version__ != $VER" >&2; exit 1; }
echo "$VER" > "$S/VERSION"

pinval() { sed -n "/^    $1 = @{/,/^    }/s/^ *$2 *= *'\([^']*\)'.*/\1/p" "$S/app/deploy/windows/pins.psd1" | head -1; }
for comp in Python Pip Rclone; do
  f="$(pinval $comp File)"; h="$(pinval $comp Sha256)"
  echo "$h  $VENDOR/$f" | sha256sum -c --quiet - || { echo "$f does not match pins.psd1" >&2; exit 1; }
  cp "$VENDOR/$f" "$S/vendor/$f"
done
n=0
while read -r h; do
  f=""
  for w in "$VENDOR"/wheels/*.whl; do
    if [[ "$(sha256sum "$w" | cut -d' ' -f1)" == "$h" ]]; then f="$w"; break; fi
  done
  [[ -n "$f" ]] || { echo "no wheel with sha256 $h" >&2; exit 1; }
  cp "$f" "$S/vendor/wheels/"; n=$((n+1))
done < <(sed -n 's/.*--hash=sha256:\([0-9a-f]\{64\}\).*/\1/p' "$S/app/requirements-windows.lock")
echo "wheels: $n"

for f in install.ps1 update.ps1 uninstall.ps1; do cp "$S/app/deploy/windows/$f" "$S/$f"; done
cp "$S/app/docs/INSTALL-WINDOWS.md" "$S/INSTALL-WINDOWS.md"
if [[ -f "$S/app/docs/INSTALL-WINDOWS.pdf" ]]; then cp "$S/app/docs/INSTALL-WINDOWS.pdf" "$S/INSTALL-WINDOWS.pdf"; fi

# guards: nothing secret-looking or local-only in the package
if find "$S" \( -name '.env' -o -name '*.db' -o -name '*.sqlite' -o -name '*.key' -o -name '*.pem' -o -name '*.dpapi' \
     -o -name 'gcp-acme-sa.json' -o -name 'id_ed25519*' \) | grep -q .; then echo "secret-like file in package" >&2; exit 1; fi
if grep -rIl -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$S/app" --exclude=test_hygiene_and_deploy.py | grep -q .; then
  echo "private key text in package" >&2; exit 1; fi

(cd "$S" && find . -type f ! -name SHA256SUMS.txt | sed 's|^\./||' | LC_ALL=C sort | xargs -d '\n' sha256sum > SHA256SUMS.txt)
STAMP="$(git -C "$ROOT" log -1 --format=%cI "$TAG")"
find "$S" -exec touch -h -d "$STAMP" {} +
mkdir -p "$OUTDIR"
python3 - "$T" "$NAME" "$OUTDIR/$NAME.zip" <<'PY'
import os, sys, zipfile
base, name, out = sys.argv[1], sys.argv[2], sys.argv[3]
files = []
for d, _, fs in os.walk(os.path.join(base, name)):
    for f in fs:
        files.append(os.path.relpath(os.path.join(d, f), base))
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for rel in sorted(files):
        p = os.path.join(base, rel)
        import time
        zi = zipfile.ZipInfo(rel.replace(os.sep, "/"), date_time=tuple(time.gmtime(os.stat(p).st_mtime))[:6])
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = 0o644 << 16
        with open(p, "rb") as fh:
            z.writestr(zi, fh.read())
PY
cp "$S/SHA256SUMS.txt" "$OUTDIR/SHA256SUMS.txt"
(cd "$OUTDIR" && sha256sum "$NAME.zip" > "$NAME.zip.sha256" && cat "$NAME.zip.sha256")
