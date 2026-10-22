#!/usr/bin/env bash
# Cross-compiles caddy.exe for the Windows host (SPEC 11.5.7) with the SAME pins as deploy/install.sh:
# Go 1.27.3 (SHA-256 checked), xcaddy v0.4.7, Caddy v2.11.7, github.com/caddy-dns/googleclouddns v1.1.0
# with its go.sum hash. Run on any Linux box (the Ubuntu test box, or WSL on the Windows PC):
#
#   bash build-caddy-windows.sh /tmp/caddy-win      ->  /tmp/caddy-win/caddy.exe + caddy.exe.sha256
#
# Needs internet access to go.dev and proxy.golang.org (Go modules). Not run in the SpringSync build box
# (no Google endpoints from there); install.ps1 -CaddyExe verifies the result again on Windows.
set -euo pipefail
OUT="${1:?usage: build-caddy-windows.sh OUTDIR}"
HERE="$(cd "$(dirname "$0")" && pwd)"
pin() { sed -n "s/^$1=\"\([^\"]*\)\".*/\1/p" "$HERE/../install.sh"; }
GO_VERSION="$(pin GO_VERSION)"; GO_SHA256="$(pin GO_SHA256)"; XCADDY_VERSION="$(pin XCADDY_VERSION)"
CADDY_VERSION="$(pin CADDY_VERSION)"; MOD="$(pin CADDY_DNS_MODULE)"; MODV="$(pin CADDY_DNS_VERSION)"; H1="$(pin CADDY_DNS_H1)"
for v in GO_VERSION GO_SHA256 XCADDY_VERSION CADDY_VERSION MOD MODV H1; do [[ -n "${!v}" ]] || { echo "pin $v missing" >&2; exit 1; }; done
mkdir -p "$OUT"; T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
G="go$GO_VERSION.linux-amd64.tar.gz"
curl -fsSL -o "$T/$G" "https://go.dev/dl/$G"
echo "$GO_SHA256  $T/$G" | sha256sum -c - >/dev/null || { echo "Go checksum mismatch: ABORT" >&2; exit 1; }
tar -C "$T" -xzf "$T/$G"
export PATH="$T/go/bin:$PATH" GOPATH="$T/gopath" GOFLAGS="-modcacherw" GOTOOLCHAIN=local
go install "github.com/caddyserver/xcaddy/cmd/xcaddy@$XCADDY_VERSION"
(cd "$T" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 "$GOPATH/bin/xcaddy" build "$CADDY_VERSION" \
    --with "$MOD@$MODV" --output "$T/caddy.exe")
# the build info embedded in the .exe must list the pinned plugin version AND its go.sum hash
go version -m "$T/caddy.exe" | awk -v m="$MOD" '$1=="dep" && $2==m {print $3" "$4}' | grep -qx "$MODV $H1" \
  || { echo "googleclouddns is not $MODV ($H1) in the build: ABORT" >&2; exit 1; }
go version -m "$T/caddy.exe" | awk '$1=="dep" && $2=="github.com/caddyserver/caddy/v2" {print $3}' | grep -qx "$CADDY_VERSION" \
  || { echo "caddy is not $CADDY_VERSION: ABORT" >&2; exit 1; }
cp "$T/caddy.exe" "$OUT/caddy.exe"
(cd "$OUT" && sha256sum caddy.exe > caddy.exe.sha256)
cat "$OUT/caddy.exe.sha256"
echo "Copy caddy.exe to the Windows PC and run install.ps1 -CaddyExe <path>\\caddy.exe (it re-verifies)."
