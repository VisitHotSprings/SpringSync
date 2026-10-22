#!/usr/bin/env bash
# Opt-in nightly auto-update (SPEC §11.4.1, v0.11). Run as root by <slug>-autoupdate.timer.
#
#   sudo /opt/springsync/current/deploy/auto-update.sh [--slug springsync]   # one check (+ install if due)
#   sudo /opt/springsync/current/deploy/auto-update.sh --check-only          # show the decision, install nothing
#   sudo /opt/springsync/current/deploy/auto-update.sh --reenable            # after a failed update turned it off
#
# OFF unless [auto_update] enabled = true in /etc/<slug>/<slug>.toml; then it exits 0 doing nothing.
# The decision (which tag, if any) is made by `odnas auto-update check`, run as the service account:
# newest normal published GitHub release (no draft/pre-release/suffix), same minor as the running release,
# at least 24 h after published_at, and no Mirror run, approval or safety hold pending. Before that, this
# script waits (max 15 min) for the 02:30 backup to finish and skips the night if update.sh or the 03:30
# maintenance job holds /run/lock/<slug>-update.lock. This script then verifies the tag signature
# (when require_signed_tags is on) and runs the normal update.sh <tag> (drain, pre-<tag> backup, smoke
# tests, health check, automatic rollback). If that fails, auto-update turns itself off
# (/etc/<slug>/auto-update.disabled) until an admin runs --reenable. Pull only: nothing pushes to the server.
set -euo pipefail
SLUG="springsync"; MODE="run"
while [[ $# -gt 0 ]]; do case "$1" in
  --slug) SLUG="$2"; shift ;; --check-only) MODE="check" ;; --reenable) MODE="reenable" ;;
  -h|--help) sed -n '2,15p' "$0"; exit 0 ;; *) echo "unknown arg $1" >&2; exit 2 ;; esac; shift; done
[[ "$SLUG" =~ ^[a-z][a-z0-9-]{1,30}$ ]] || { echo "bad slug" >&2; exit 2; }

# SPRINGSYNC_TEST_PREFIX: test suite only (fake /opt + /etc tree, no root, no sudo). Never set on a server.
PFX="${SPRINGSYNC_TEST_PREFIX:-}"
if [[ -z "$PFX" ]]; then [[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }; fi
OPT="$PFX/opt/$SLUG"; ETC="$PFX/etc/$SLUG"; FLAG="$ETC/auto-update.disabled"
TAG_RE='^v(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$'
export ODNAS_CONFIG="${ODNAS_CONFIG:-$ETC/$SLUG.toml}"

app() {  # the service account runs the Python side (DB files stay owned by it); no keys are needed
  if [[ -n "$PFX" ]]; then "$OPT/current/venv/bin/odnas" auto-update "$@"
  else sudo -u "$SLUG" env ODNAS_CONFIG="$ODNAS_CONFIG" "$OPT/current/venv/bin/odnas" auto-update "$@"; fi
}
current_tag() { basename "$(readlink -f "$OPT/current")"; }

# Test hooks (only with SPRINGSYNC_TEST_PREFIX): a fake systemctl and a short backup wait.
SYSTEMCTL="systemctl"; BACKUP_WAIT_S=900; BACKUP_POLL_S=30
if [[ -n "$PFX" ]]; then SYSTEMCTL="${FAKE_SYSTEMCTL:-false}"; BACKUP_WAIT_S="${FAKE_BACKUP_WAIT_S:-0}"; BACKUP_POLL_S=1; fi

# one run at a time (a manual run and the timer must not overlap)
LOCK="${PFX:-/run/lock}/$SLUG-autoupdate.lock"
# update.sh holds this one exclusively while it runs; the 03:30 maintenance job holds it shared (SPEC §11.4.1 rule 2)
UPDATE_LOCK="${PFX:-/run/lock}/$SLUG-update.lock"
exec 9>"$LOCK"; flock -n 9 || { echo "another auto-update run is in progress"; exit 0; }

CUR_TAG="$(current_tag)"
if [[ "$MODE" == "reenable" ]]; then
  rm -f "$FLAG"; app report --event reenabled --tag "$CUR_TAG" --from "$CUR_TAG"
  echo "auto-update re-enabled (it still needs [auto_update] enabled = true)"; exit 0
fi

# Off (the default): stop here, before waiting on anything.
if [[ "$(app status | jq -r '.enabled')" != "true" ]]; then echo "no update (disabled); running $CUR_TAG"; exit 0; fi

# SPEC §11.4.1 rule 2: never before the 02:30 backup has finished. Two timers don't order each other's runs
# (After= only orders jobs queued together), so look at the unit: wait up to 15 min, then skip tonight.
waited=0
while "$SYSTEMCTL" is-active --quiet "$SLUG-backup.service"; do
  if (( waited >= BACKUP_WAIT_S )); then
    app report --event backup_running --tag "$CUR_TAG" --from "$CUR_TAG"
    echo "no update (backup_running: $SLUG-backup.service still active after ${BACKUP_WAIT_S}s); running $CUR_TAG"; exit 0
  fi
  sleep "$BACKUP_POLL_S"; waited=$(( waited + BACKUP_POLL_S ))
done

# A manual update.sh or the maintenance job is running: skip tonight (not a failure).
busy() { app report --event busy --tag "$CUR_TAG" --from "$CUR_TAG"; echo "no update (update or maintenance running); running $CUR_TAG"; exit 0; }
exec 8>>"$UPDATE_LOCK"; flock -n 8 || busy; flock -u 8; exec 8>&-

OUT="$(app check --current "$CUR_TAG")"
ACTION="$(jq -r '.action' <<<"$OUT")"; REASON="$(jq -r '.reason' <<<"$OUT")"; TAG="$(jq -r '.tag' <<<"$OUT")"
NEWER_MINOR="$(jq -r '.newer_minor' <<<"$OUT")"
[[ -n "$NEWER_MINOR" ]] && echo "note: $NEWER_MINOR is a new minor/major; it waits for a manual update.sh"
if [[ "$ACTION" != "install" ]]; then echo "no update ($REASON${TAG:+, $TAG}); running $CUR_TAG"; exit 0; fi
[[ "$TAG" =~ $TAG_RE ]] || { echo "refusing non-release tag '$TAG'" >&2; exit 1; }
if [[ "$MODE" == "check" ]]; then echo "would install $TAG over $CUR_TAG (--check-only: nothing changed)"; exit 0; fi

# SPEC §11.4.1 rule 6: once tag signing is on, an unsigned tag (or one signed by a key not allowed) is refused.
SIGNED="$(jq -r '.require_signed_tags' <<<"$OUT")"; SIGNERS="$(jq -r '.allowed_signers' <<<"$OUT")"
if [[ "$SIGNED" == "true" || -n "${REQUIRE_SIGNED_TAGS:-}" ]]; then
  export REQUIRE_SIGNED_TAGS=1
  T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
  git init --quiet --bare "$T/r.git"
  if ! git -C "$T/r.git" fetch --quiet --depth 1 "$(git -C "$OPT/current" remote get-url origin)" "refs/tags/$TAG:refs/tags/$TAG"; then
    echo "could not fetch $TAG to check its signature; nothing changed, will retry next night" >&2; exit 0
  fi
  VCMD=(git -C "$T/r.git"); [[ -n "$SIGNERS" ]] && VCMD+=(-c "gpg.ssh.allowedSignersFile=$SIGNERS")
  if ! "${VCMD[@]}" verify-tag "$TAG" >/dev/null 2>&1; then
    app report --event refused_unsigned --tag "$TAG" --from "$CUR_TAG"
    echo "refused $TAG: unsigned or not signed by an allowed key; nothing changed" >&2; exit 0
  fi
fi

echo "auto-update: installing $TAG over $CUR_TAG"
rc=0; "$OPT/current/deploy/update.sh" "$TAG" --slug "$SLUG" || rc=$?
(( rc == 75 )) && busy   # update.sh could not get the update lock (EX_TEMPFAIL): nothing changed
if (( rc == 0 )) && [[ "$(current_tag)" == "$TAG" ]]; then
  app report --event installed --tag "$TAG" --from "$CUR_TAG"; echo "auto-update: now running $TAG"; exit 0
fi
# SPEC §11.4.1 rule 7: any failure (update.sh already rolled back if it had switched) turns auto-update off.
install -m 0644 /dev/null "$FLAG"
printf 'auto-update to %s failed (exit %s) at %s; was %s\n' "$TAG" "$rc" "$(date -Is)" "$CUR_TAG" > "$FLAG"
app report --event failed --tag "$TAG" --from "$(current_tag)"
echo "auto-update to $TAG FAILED (update.sh exit $rc); now running $(current_tag); auto-update is OFF until --reenable" >&2
exit 0
