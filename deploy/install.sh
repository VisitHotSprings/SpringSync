#!/usr/bin/env bash
# Idempotent installer for a fresh Ubuntu Server 24.04 LTS amd64 (SPEC §11.2). Run as root.
#
#   sudo ./install.sh --version v0.3.0 [--dry-run] [--slug springsync]
#
# Re-running converges. It never overwrites existing keys, the DB, or settings.
# Inputs (env vars, or prompted when interactive and the bootstrap toml is missing):
#   REPO_URL            git@github.com:<OWNER>/<REPO>.git   (org/account not created yet: OPEN)
#   TENANT_ID CLIENT_ID GROUP_USERS GROUP_ADMINS GROUP_AUDITORS
#   SYNC_HOST (sync.hotsprings.org)  ACME_EMAIL  GCP_ACME_PROJECT  ACME_ZONE
#   LAN_CIDRS ("10.0.0.0/16 10.8.0.0/24")  ADMIN_CIDR ("10.0.10.0/24")
#   LOG_READERS ("walter")  linux accounts added to group adm to read run logs
# Nothing in this script contacts Microsoft or changes DNS/Entra/NAS.
set -euo pipefail

# ---- pins (SPEC §3, §11.2) --------------------------------------------------
RCLONE_VERSION="1.75.2"
RCLONE_SHA256="349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702"   # rclone-v1.75.2-linux-amd64.zip
GO_VERSION="1.27.3"
GO_SHA256="65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40"  # go1.27.3.linux-amd64.tar.gz (SPEC v0.2 §3/§11.2; matches go.dev/dl JSON)
XCADDY_VERSION="v0.4.7"
CADDY_VERSION="v2.11.7"
CADDY_DNS_MODULE="github.com/caddy-dns/googleclouddns"
CADDY_DNS_VERSION="v1.1.0"   # tag = commit 6fcdbd98a8565df50ff40ff53411dc6c8d97dcd9 (proxy.golang.org .info Origin.Hash)
CADDY_DNS_H1="h1:SDxKxFh7d5Jq2/JPnu9Jv8ErOIdfXmK+Oad0qVzQi80="   # sum.golang.org record for v1.1.0
CADDY_DNS_PLUGIN="$CADDY_DNS_MODULE@$CADDY_DNS_VERSION"

SLUG="springsync"; PRODUCT="SpringSync"; VERSION=""; DRY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --version) VERSION="$2"; shift ;;
    --slug) SLUG="$2"; shift ;;
    --product) PRODUCT="$2"; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac; shift
done
[[ "$SLUG" =~ ^[a-z][a-z0-9-]{1,30}$ ]] || { echo "bad slug" >&2; exit 2; }
[[ -z "$VERSION" || "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "--version must be vX.Y.Z" >&2; exit 2; }

ETC="/etc/$SLUG"; LIB="/var/lib/$SLUG"; LOG="/var/log/$SLUG"; OPT="/opt/$SLUG"; MNT="/srv/$SLUG"
HELPER="/usr/local/lib/$SLUG/mount-helper"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # repo checkout this script came from

say()  { printf '\033[1m==> %s\033[0m\n' "$*"; }
plan() { printf '    [plan] %s\n' "$*"; }
run()  { if (( DRY )); then plan "$*"; else "$@"; fi; }
render() {  # render <template> <dest> <mode> <owner>: only rewrites when content differs
  local tmp; tmp="$(mktemp)"
  sed -e "s|@SLUG@|$SLUG|g" -e "s|@PRODUCT@|$PRODUCT|g" -e "s|@SYNC_HOST@|${SYNC_HOST:-sync.hotsprings.org}|g" \
      -e "s|@ACME_EMAIL@|${ACME_EMAIL:-it@hotsprings.org}|g" -e "s|@GCP_ACME_PROJECT@|${GCP_ACME_PROJECT:-REPLACE_ME}|g" \
      -e "s|@ACME_ZONE@|${ACME_ZONE:-REPLACE_ME}|g" "$1" > "$tmp"
  if [[ -f "$2" ]] && cmp -s "$tmp" "$2"; then rm -f "$tmp"; return 0; fi
  if (( DRY )); then plan "write $2 from $(basename "$1")"; rm -f "$tmp"; return 0; fi
  install -m "$3" -o "${4%%:*}" -g "${4##*:}" "$tmp" "$2"; rm -f "$tmp"; echo "    wrote $2"
}
mkd() { # mkd <dir> <mode> <owner:group>
  if [[ -d "$1" && "$(stat -c '%a %U:%G' "$1")" == "$2 $3" ]]; then return 0; fi
  run install -d -m "$2" -o "${3%%:*}" -g "${3##*:}" "$1"
}

# ---- 1. platform -----------------------------------------------------------
say "1. platform check"
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
. /etc/os-release
[[ "${VERSION_ID:-}" == "24.04" && "$(dpkg --print-architecture)" == "amd64" ]] \
  || { echo "requires Ubuntu 24.04 amd64 (found ${PRETTY_NAME:-?} $(dpkg --print-architecture))" >&2; exit 1; }

# ---- 2. apt -----------------------------------------------------------------
say "2. packages"
PKGS=(python3.12-venv python3-pip git curl unzip jq sqlite3 cifs-utils keyutils ufw ca-certificates
      debian-keyring debian-archive-keyring apt-transport-https unattended-upgrades)
MISSING=(); for p in "${PKGS[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || MISSING+=("$p"); done
if (( ${#MISSING[@]} )); then run apt-get update -q; run env DEBIAN_FRONTEND=noninteractive apt-get install -yq "${MISSING[@]}"; fi
if [[ ! -f /etc/apt/apt.conf.d/20auto-upgrades ]] || ! grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
  run sh -c 'printf "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n" > /etc/apt/apt.conf.d/20auto-upgrades'
fi  # Ubuntu's default 50unattended-upgrades allows only -security origins

# ---- 3. users and dirs ------------------------------------------------------
say "3. users and directories"
id "$SLUG" >/dev/null 2>&1 || run useradd --system --home-dir "$LIB" --shell /usr/sbin/nologin "$SLUG"
id caddy >/dev/null 2>&1 || run useradd --system --home-dir /var/lib/caddy --create-home --shell /usr/sbin/nologin caddy
mkd "$ETC" 0755 root:root
mkd "$ETC/keys" 0700 root:root
mkd "$ETC/creds" 0700 root:root
mkd "$ETC/deploy" 0700 root:root
mkd "$OPT" 0755 root:root
mkd "$OPT/releases" 0755 root:root
mkd "$LIB" 0750 "$SLUG:$SLUG"
mkd "$LIB/db" 0700 "$SLUG:$SLUG"
mkd "$LIB/bisync" 0700 "$SLUG:$SLUG"
mkd "$LIB/preflight" 0700 "$SLUG:$SLUG"
mkd "$LIB/backups" 0700 root:root
mkd "$LOG" 2750 "$SLUG:adm"          # setgid: run logs inherit group adm (0640 via UMask=0027)
mkd "$LOG/runs" 2750 "$SLUG:adm"
mkd "$MNT" 0755 root:root
mkd "$MNT/mnt" 0750 "$SLUG:$SLUG"
mkd "$MNT/verify" 0750 "$SLUG:$SLUG"
mkd "/usr/local/lib/$SLUG" 0755 root:root
for u in ${LOG_READERS:-}; do
  if id "$u" >/dev/null 2>&1 && ! id -nG "$u" | grep -qw adm; then run usermod -aG adm "$u"; fi
done

# ---- 4. rclone (pinned, checksum from this script, never fetched) ------------
say "4. rclone v$RCLONE_VERSION"
if [[ "$(/usr/local/bin/rclone version 2>/dev/null | head -1)" != "rclone v$RCLONE_VERSION" ]]; then
  if (( DRY )); then plan "download + verify + install rclone v$RCLONE_VERSION"; else
    T="$(mktemp -d)"; Z="rclone-v$RCLONE_VERSION-linux-amd64.zip"
    curl -fsSLo "$T/$Z" "https://downloads.rclone.org/v$RCLONE_VERSION/$Z"
    echo "$RCLONE_SHA256  $T/$Z" | sha256sum -c - || { echo "rclone checksum mismatch: ABORT" >&2; exit 1; }
    unzip -q "$T/$Z" -d "$T"; install -m 0755 -o root -g root "$T/rclone-v$RCLONE_VERSION-linux-amd64/rclone" /usr/local/bin/rclone
    rm -rf "$T"
  fi
fi

# ---- 5. Caddy (custom build with the Google Cloud DNS plugin) ----------------
say "5. caddy $CADDY_VERSION + googleclouddns"
plugin_pinned() {  # $1 = caddy binary; its Go build info must list the pinned module version AND go.sum hash
  [[ "$("$1" build-info 2>/dev/null | awk -v m="$CADDY_DNS_MODULE" '$1=="dep" && $2==m {print $3" "$4}')" == "$CADDY_DNS_VERSION $CADDY_DNS_H1" ]]; }
caddy_ok() { /usr/local/bin/caddy version 2>/dev/null | grep -q "^${CADDY_VERSION}" && \
             /usr/local/bin/caddy list-modules 2>/dev/null | grep -qx 'dns.providers.googleclouddns' && \
             plugin_pinned /usr/local/bin/caddy; }
if ! caddy_ok; then
  if (( DRY )); then plan "install Go $GO_VERSION to /usr/local/go-$SLUG, xcaddy $XCADDY_VERSION, build caddy"; else
    T="$(mktemp -d)"; G="go$GO_VERSION.linux-amd64.tar.gz"
    curl -fsSLo "$T/$G" "https://go.dev/dl/$G"
    echo "$GO_SHA256  $T/$G" | sha256sum -c - || { echo "Go checksum mismatch: ABORT" >&2; exit 1; }
    rm -rf "/usr/local/go-$SLUG"; mkdir -p "/usr/local/go-$SLUG"; tar -C "/usr/local/go-$SLUG" --strip-components=1 -xzf "$T/$G"
    export GOPATH="$T/gopath" GOCACHE="$T/gocache" PATH="/usr/local/go-$SLUG/bin:$PATH" GOFLAGS=-mod=mod GOTOOLCHAIN=local \
           GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GONOSUMDB= GOPRIVATE= GOINSECURE=
    go install "github.com/caddyserver/xcaddy/cmd/xcaddy@$XCADDY_VERSION"
    (cd "$T" && "$GOPATH/bin/xcaddy" build "$CADDY_VERSION" --with "$CADDY_DNS_PLUGIN" --output "$T/caddy")
    "$T/caddy" list-modules | grep -qx 'dns.providers.googleclouddns' || { echo "plugin missing from build" >&2; exit 1; }
    plugin_pinned "$T/caddy" || { echo "googleclouddns is not $CADDY_DNS_VERSION ($CADDY_DNS_H1) in the build: ABORT" >&2; exit 1; }
    "/usr/local/go-$SLUG/bin/go" version -m "$T/caddy" | grep googleclouddns
    install -m 0755 -o root -g root "$T/caddy" /usr/local/bin/caddy; rm -rf "$T"
  fi
fi
mkd /etc/caddy 0750 root:caddy
render "$SRC_DIR/deploy/caddy/caddy.service" /etc/systemd/system/caddy.service 0644 root:root

# ---- 6. app release -----------------------------------------------------------
say "6. app ${VERSION:-<no --version given>}"
if [[ -n "$VERSION" ]]; then
  REL="$OPT/releases/$VERSION"
  if [[ ! -x "$REL/venv/bin/odnas" ]]; then
    : "${REPO_URL:?set REPO_URL=git@github.com:<OWNER>/<REPO>.git}"
    [[ -f "$ETC/deploy/id_ed25519" ]] || { echo "place the read-only deploy key at $ETC/deploy/id_ed25519 (0400 root)" >&2; exit 1; }
    export GIT_SSH_COMMAND="ssh -i $ETC/deploy/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
    run git clone --quiet --depth 1 --branch "$VERSION" "$REPO_URL" "$REL"
    run python3.12 -m venv "$REL/venv"
    run "$REL/venv/bin/pip" install --quiet --require-hashes --no-deps -r "$REL/requirements.lock"
    if (( DRY )); then plan "write $REL/venv/bin/odnas wrapper"; else
      printf '#!/bin/sh\nPYTHONPATH=%s exec %s/venv/bin/python -m odnas "$@"\n' "$REL" "$REL" > "$REL/venv/bin/odnas"
      chmod 0755 "$REL/venv/bin/odnas"; chown -R root:root "$REL"; chmod -R go-w "$REL"
    fi
  fi
  [[ "$(readlink -f "$OPT/current" 2>/dev/null)" == "$REL" ]] || run ln -sfn "$REL" "$OPT/current"
  SRC_DIR="$OPT/current"
fi
render "$SRC_DIR/deploy/mount-helper" "$HELPER" 0755 root:root
[[ -e "/usr/local/bin/$SLUG" ]] || run ln -s "$OPT/current/venv/bin/odnas" "/usr/local/bin/$SLUG"

# ---- 7. keys ----------------------------------------------------------------------
say "7. keys (never overwritten)"
if [[ ! -f "$ETC/keys/data.key" ]]; then
  run sh -c "umask 077; head -c32 /dev/urandom > '$ETC/keys/data.key'"; run chmod 0400 "$ETC/keys/data.key"
  echo "    !! NEW data.key generated. Escrow an offline copy in the IT password manager now (SPEC §7.3)."
fi
if [[ ! -f "$ETC/keys/entra-app.key" ]]; then
  run openssl req -x509 -newkey rsa:2048 -nodes -days 730 -subj "/CN=$SLUG-entra-app" \
      -keyout "$ETC/keys/entra-app.key" -out "$ETC/keys/entra-app.crt"
  run chmod 0400 "$ETC/keys/entra-app.key"; run chmod 0444 "$ETC/keys/entra-app.crt"
  echo "    !! Upload $ETC/keys/entra-app.crt to the Entra app registration (Certificates & secrets)."
fi
CREDS=(data.key entra-app.key); [[ -f "$ETC/keys/entra-client-secret" ]] && CREDS+=(entra-client-secret)
for k in "${CREDS[@]}"; do
  if [[ ! -f "$ETC/creds/$k.cred" ]]; then
    run systemd-creds encrypt --name="$k" "$ETC/keys/$k" "$ETC/creds/$k.cred"   # host key (+TPM2 if present)
  fi
done
if [[ -f "$ETC/creds/entra-client-secret.cred" ]]; then   # fallback credential (secret mode / tmpfs_config)
  for svc in web worker; do
    D="/etc/systemd/system/$SLUG-$svc.service.d"; F="$D/client-secret.conf"
    want="[Service]
LoadCredentialEncrypted=entra-client-secret:$ETC/creds/entra-client-secret.cred"
    if [[ ! -f "$F" ]] || [[ "$(cat "$F")" != "$want" ]]; then run mkdir -p "$D"; (( DRY )) || printf '%s\n' "$want" > "$F"; fi
  done
fi

# ---- 8. config ---------------------------------------------------------------------
say "8. config"
if [[ ! -f "$ETC/$SLUG.toml" ]]; then
  if [[ -t 0 && -z "${TENANT_ID:-}" ]]; then
    read -rp "Tenant ID: " TENANT_ID; read -rp "Client ID: " CLIENT_ID
    read -rp "Users group ID: " GROUP_USERS; read -rp "Admins group ID: " GROUP_ADMINS; read -rp "Auditors group ID: " GROUP_AUDITORS
  fi
  : "${TENANT_ID:?}" "${CLIENT_ID:?}"
  if (( DRY )); then plan "create $ETC/$SLUG.toml"; else
    sed -e "s/^product_name = .*/product_name = \"$PRODUCT\"/" -e "s/^slug = .*/slug = \"$SLUG\"/" \
        -e "0,/^tenant_id = .*/s//tenant_id = \"$TENANT_ID\"/" -e "0,/^client_id = .*/s//client_id = \"$CLIENT_ID\"/" \
        -e "s/^group_users = .*/group_users = \"${GROUP_USERS:-}\"/" -e "s/^group_admins = .*/group_admins = \"${GROUP_ADMINS:-}\"/" \
        -e "s/^group_auditors = .*/group_auditors = \"${GROUP_AUDITORS:-}\"/" -e "s#/etc/springsync/#$ETC/#g" \
        "$SRC_DIR/deploy/config/springsync.toml.example" > "$ETC/$SLUG.toml"
    chmod 0644 "$ETC/$SLUG.toml"
  fi
fi
render "$SRC_DIR/deploy/caddy/Caddyfile.tmpl" /etc/caddy/Caddyfile 0640 root:caddy
render "$SRC_DIR/deploy/caddy/caddy.env.tmpl" /etc/caddy/caddy.env 0640 root:caddy
[[ -f /etc/caddy/gcp-acme-sa.json ]] || echo "    !! Place the ACME service-account key at /etc/caddy/gcp-acme-sa.json (0400 caddy:caddy)."

# ---- 9. DB ----------------------------------------------------------------------
say "9. database"
if (( DRY )); then plan "odnas db-upgrade"; else
  sudo -u "$SLUG" ODNAS_CONFIG="$ETC/$SLUG.toml" "$OPT/current/venv/bin/odnas" db-upgrade; fi

# ---- 10. sudoers + mount helper -------------------------------------------------
say "10. sudoers"
T="$(mktemp)"; sed "s|@SLUG@|$SLUG|g" "$SRC_DIR/deploy/sudoers/springsync" > "$T"
if ! cmp -s "$T" "/etc/sudoers.d/$SLUG" 2>/dev/null; then
  visudo -cf "$T" >/dev/null || { echo "sudoers file failed validation" >&2; exit 1; }
  run install -m 0440 -o root -g root "$T" "/etc/sudoers.d/$SLUG"
fi; rm -f "$T"

# ---- 11. firewall ------------------------------------------------------------------
say "11. ufw"
ufw_rule() { # ufw_rule <cidr> <port>: add only if missing
  ufw status | grep -qE "^$2/tcp +ALLOW( IN)? +${1//./\\.}( |$)" || run ufw allow from "$1" to any port "$2" proto tcp comment "$SLUG $2"
}
ufw status verbose | grep -q "deny (incoming)" || run ufw default deny incoming
for c in ${LAN_CIDRS:-}; do ufw_rule "$c" 443; ufw_rule "$c" 80; done
[[ -n "${ADMIN_CIDR:-}" ]] && ufw_rule "$ADMIN_CIDR" 22
[[ -n "${ADMIN_CIDR:-}" ]] || echo "    !! ADMIN_CIDR unset: not enabling ufw (would lock out SSH)."
[[ -n "${ADMIN_CIDR:-}" ]] && { ufw status | grep -q "Status: active" || run ufw --force enable; }

# ---- 12. systemd ---------------------------------------------------------------------
say "12. systemd units"
for u in "$SRC_DIR"/deploy/systemd/springsync-*; do
  name="$(basename "$u" | sed "s/^springsync/$SLUG/")"
  render "$u" "/etc/systemd/system/$name" 0644 root:root
done
run systemctl daemon-reload
for u in caddy "$SLUG-web" "$SLUG-worker" "$SLUG-backup.timer" "$SLUG-maint.timer"; do
  systemctl is-enabled --quiet "$u" 2>/dev/null || run systemctl enable "$u"
  systemctl is-active --quiet "$u" 2>/dev/null || run systemctl start "$u"
done

# ---- 13. smoke test ---------------------------------------------------------------------
say "13. smoke test"
if (( ! DRY )); then
  for i in $(seq 1 15); do curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 2; done
  curl -fsS http://127.0.0.1:8080/healthz && echo
  /usr/local/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null && echo "    caddy config valid"
fi
cat <<NEXT
Next steps:
  * The TLS certificate is issued on Caddy's first start (needs the CNAME + ACME SA in place; test T-C1 first).
  * Sign in at https://${SYNC_HOST:-sync.hotsprings.org} as a member of the Admins group, then fill Settings.
  * Run lab tests T-N1, T-S1, T-A3, T-A4, T-C1 before adding pilot users.
NEXT
