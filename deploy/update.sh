#!/usr/bin/env bash
# One-command update to a tagged release with automatic rollback (SPEC §11.4). Run as root.
#
#   sudo /opt/springsync/current/deploy/update.sh v0.1.1 [--slug springsync]
#
# Pull model: the server fetches from GitHub with a READ-ONLY deploy key
# (/etc/<slug>/deploy/id_ed25519, 0400 root). Nothing ever pushes to the server.
set -euo pipefail
TAG="${1:-}"; shift || true
SLUG="springsync"
while [[ $# -gt 0 ]]; do case "$1" in --slug) SLUG="$2"; shift ;; *) echo "unknown arg $1" >&2; exit 2 ;; esac; shift; done
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: update.sh vX.Y.Z  (branch names are refused)" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

OPT="/opt/$SLUG"; ETC="/etc/$SLUG"; LIB="/var/lib/$SLUG"
CUR="$(readlink -f "$OPT/current")"; REL="$OPT/releases/$TAG"
export GIT_SSH_COMMAND="ssh -i $ETC/deploy/id_ed25519 -o IdentitiesOnly=yes"
export ODNAS_CONFIG="$ETC/$SLUG.toml"
say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
audit() { sudo -u "$SLUG" env ODNAS_CONFIG="$ODNAS_CONFIG" CREDENTIALS_DIRECTORY="$ETC/keys" \
            "$OPT/current/venv/bin/python" -c "import sys; sys.path.insert(0, '$OPT/current'); \
from odnas.config import load_config; from odnas.db import DB; c=load_config(); \
DB(c.p_db).audit('system', sys.argv[1], sys.argv[2], {'from': sys.argv[3]})" "$@" || true; }
[[ "$CUR" == "$REL" ]] && { echo "$TAG is already current"; exit 0; }

say "1. fetch $TAG"
if [[ ! -d "$REL" ]]; then
  git clone --quiet --depth 1 --branch "$TAG" "$(git -C "$CUR" remote get-url origin)" "$REL"
  # tag signature verification: enable once the org + signing key exist (SPEC §14.9 OPEN)
  if [[ -n "${REQUIRE_SIGNED_TAGS:-}" ]]; then git -C "$REL" fetch --quiet --depth 1 origin "refs/tags/$TAG:refs/tags/$TAG" && git -C "$REL" verify-tag "$TAG"; fi
fi

say "2. build venv (hash-locked)"
if [[ ! -x "$REL/venv/bin/odnas" ]]; then
  python3.12 -m venv "$REL/venv"
  "$REL/venv/bin/pip" install --quiet --require-hashes --no-deps -r "$REL/requirements.lock"
  printf '#!/bin/sh\nPYTHONPATH=%s exec %s/venv/bin/python -m odnas "$@"\n' "$REL" "$REL" > "$REL/venv/bin/odnas"
  chmod 0755 "$REL/venv/bin/odnas"; chown -R root:root "$REL"; chmod -R go-w "$REL"
fi

say "3. smoke tests against the new venv"
(cd "$REL" && "$REL/venv/bin/python" -m pytest -q --smoke -p no:cacheprovider tests) || { echo "smoke tests failed; nothing changed" >&2; exit 1; }

say "4. drain worker (waits up to 30 min for running jobs)"
"$OPT/current/venv/bin/odnas" worker drain --timeout 1800 || { echo "drain timed out; aborting, nothing changed" >&2; "$OPT/current/venv/bin/odnas" worker undrain; exit 1; }

say "5. DB backup pre-$TAG"
CREDENTIALS_DIRECTORY="$ETC/keys" "$OPT/current/venv/bin/odnas" backup --tag "pre-$TAG"

say "6. migrate (expand-only)"
sudo -u "$SLUG" env ODNAS_CONFIG="$ODNAS_CONFIG" "$REL/venv/bin/odnas" db-upgrade

say "7. switch + restart + health check (60 s)"
ln -sfn "$CUR" "$OPT/previous"
ln -sfn "$REL" "$OPT/current"
systemctl restart "$SLUG-web" "$SLUG-worker"
healthy=0
for i in $(seq 1 12); do
  sleep 5
  if curl -fsS http://127.0.0.1:8080/healthz | grep -q '"worker_alive":true'; then healthy=1; break; fi
done
if (( ! healthy )); then
  echo "health check failed: rolling back to $(basename "$CUR")" >&2
  "$CUR/deploy/rollback.sh" --slug "$SLUG" --auto
  exit 1
fi

say "8. audit + prune (keep last 3 releases)"
audit deploy "$TAG" "$(basename "$CUR")"
ls -1dt "$OPT"/releases/v* | tail -n +4 | while read -r old; do
  [[ "$old" == "$(readlink -f "$OPT/current")" || "$old" == "$(readlink -f "$OPT/previous")" ]] || rm -rf "$old"
done
echo "updated to $TAG"
