# Restore (SPEC §10.3)

Backups (`/var/lib/<slug>/backups`, daily 02:30 America/Chicago, 14 kept) contain the
SQLite DB (`db-*.sqlite`) and `/etc/<slug>` + `/etc/caddy` as `config-*.tar.gz`
**without** `keys/`, `creds/`, `deploy/`, `*.key`, `*.cred`, `id_*` or `gcp-acme-sa.json`.
The DB holds only AES-256-GCM ciphertext; it is useless without `data.key`.

1. Fresh Ubuntu 24.04: `sudo ./deploy/install.sh --version <tag>` (creates users/dirs/units).
   Stop services: `systemctl stop <slug>-worker <slug>-web`.
2. Place keys from escrow (IT password manager), mode 0400 root:
   `/etc/<slug>/keys/data.key`, `/etc/<slug>/keys/entra-app.key` (+ `.crt`),
   `/etc/<slug>/deploy/id_ed25519`, `/etc/caddy/gcp-acme-sa.json` (0400 caddy).
   Delete `/etc/<slug>/creds/*.cred` and re-run install.sh so they are re-encrypted for this host.
3. Restore config: `tar -xzf config-<stamp>.tar.gz -C /tmp/r` and copy `<slug>.toml`, `Caddyfile`, `caddy.env`.
4. Restore DB: `install -m 0600 -o <slug> -g <slug> db-<stamp>.sqlite /var/lib/<slug>/db/<slug>.db`
   then `sudo -u <slug> /usr/local/bin/<slug> db-upgrade`.
5. Start: `systemctl start <slug>-web <slug>-worker`; check `/healthz` and the admin page.
6. If `data.key` is lost: users simply reconnect (Microsoft + NAS login). No file data is lost;
   files live on the NAS and in OneDrive.

The copy of backups to the IT-only NAS share (`IT-Backups/<slug>`) is not implemented in v0.1.
