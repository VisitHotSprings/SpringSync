#!/usr/bin/env bash
# Roll back to the previous release (SPEC §11.4 step 8). Run as root.
#   sudo /opt/springsync/current/deploy/rollback.sh [--slug springsync] [--restore-db]
# --restore-db restores the newest pre-<tag> DB backup (only needed if a migration
# was not backward compatible; migrations are expand-only within a minor version).
set -euo pipefail
SLUG="springsync"; RESTORE=0; AUTO=0
while [[ $# -gt 0 ]]; do case "$1" in --slug) SLUG="$2"; shift ;; --restore-db) RESTORE=1 ;; --auto) AUTO=1 ;;
  *) echo "unknown arg $1" >&2; exit 2 ;; esac; shift; done
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
OPT="/opt/$SLUG"; LIB="/var/lib/$SLUG"; ETC="/etc/$SLUG"
PREV="$(readlink -f "$OPT/previous" 2>/dev/null || true)"; CUR="$(readlink -f "$OPT/current")"
[[ -n "$PREV" && -d "$PREV" && "$PREV" != "$CUR" ]] || { echo "no previous release recorded" >&2; exit 1; }
systemctl stop "$SLUG-worker" "$SLUG-web"
if (( RESTORE )); then
  B="$(ls -1t "$LIB"/backups/db-pre-*.sqlite 2>/dev/null | head -1)"
  [[ -n "$B" ]] || { echo "no pre-<tag> DB backup found" >&2; exit 1; }
  DBP="$(sudo -u "$SLUG" env ODNAS_CONFIG="$ETC/$SLUG.toml" "$PREV/venv/bin/python" -c "import sys; sys.path.insert(0,'$PREV'); from odnas.config import load_config; print(load_config().p_db)")"
  cp -a "$DBP" "$DBP.rollback-$(date +%s)"; rm -f "$DBP-wal" "$DBP-shm"
  install -m 0600 -o "$SLUG" -g "$SLUG" "$B" "$DBP"; echo "restored DB from $B"
fi
ln -sfn "$PREV" "$OPT/current"; ln -sfn "$CUR" "$OPT/previous"
systemctl start "$SLUG-web" "$SLUG-worker"
for i in $(seq 1 12); do sleep 5; curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; done
curl -fsS http://127.0.0.1:8080/healthz && echo
echo "rolled back to $(basename "$PREV") $( (( AUTO )) && echo '(automatic)')"
