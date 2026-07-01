#!/usr/bin/env bash
# install.sh — install kriyad as a hardened systemd service (the BOX skin). Run as root on the target
# Linux host. Idempotent: re-running upgrades the binaries + unit without clobbering your config/license.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root (installs to /usr/local/bin + /etc/kriyad + systemd)" >&2; exit 1; }

install -m 0755 "$HERE/kriyad"      /usr/local/bin/kriyad
install -m 0755 "$HERE/kriya-audit" /usr/local/bin/kriya-audit
install -d -m 0755 /usr/local/share/kriyad
install -m 0755 "$HERE/kriyd-ca.sh" /usr/local/share/kriyad/kriyd-ca.sh
install -d -m 0750 /etc/kriyad /etc/kriyad/ca
# Don't overwrite an existing operator config/license.
[ -f /etc/kriyad/kriyad.env ] || install -m 0640 "$HERE/kriyad.env.example" /etc/kriyad/kriyad.env
install -m 0644 "$HERE/kriyad.service" /etc/systemd/system/kriyad.service
systemctl daemon-reload

cat <<'NEXT'
✓ kriyad installed. Next steps (nothing has started yet):
  1) Drop a control-plane license at   /etc/kriyad/kriyad-license.json
  2) Bootstrap mTLS:                    /usr/local/share/kriyad/kriyd-ca.sh   (or put your own CA in /etc/kriyad/ca)
  3) Start it:                          systemctl enable --now kriyad
  4) Check:                             systemctl status kriyad
                                        systemctl is-active kriyad
                                        systemd-analyze security kriyad   # should NOT read UNSAFE
                                        curl -k https://localhost:8443/healthz
NEXT
