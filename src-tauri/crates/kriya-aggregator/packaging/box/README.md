# kriyad — BOX skin (static binary + systemd)

The pilot-default way to run **kriyad**, the customer-controlled evidence aggregator: one fully static
Linux binary + a hardened `systemd` unit + a bundled SQLite store. No container runtime, no orchestrator,
no outbound calls — the Vault/Consul deployment model, for air-gapped / high-assurance hosts.

## Contents
| File | What |
|---|---|
| `kriyad` | the aggregator — fully static (musl), no runtime deps |
| `kriya-audit` | the offline auditor (re-prove any evidence yourself) |
| `kriyad.service` | hardened systemd unit (DynamicUser, ProtectSystem=strict, empty CapabilityBoundingSet, `@system-service` syscall filter) |
| `kriyad.env.example` | the entire config surface — 5 env vars |
| `kriyd-ca.sh` | bootstrap an offline mTLS CA + server + role-stamped client certs |
| `install.sh` | install binaries + unit (run as root) |

## Install
```sh
sudo ./install.sh
# 1) drop a control-plane license at /etc/kriyad/kriyad-license.json
# 2) role-stamped mTLS certs (P6 — a device cert can't read the fleet, an operator cert can't post evidence):
sudo /usr/local/share/kriyad/kriyd-ca.sh /etc/kriyad/ca --operator
sudo /usr/local/share/kriyad/kriyd-ca.sh /etc/kriyad/ca --device <device_pub_hex>
#    …or put your own CA + role-stamped client certs in /etc/kriyad/ca
# 3) sudo systemctl enable --now kriyad
```

## Verify it's healthy
```sh
systemctl is-active kriyad                 # active
systemd-analyze security kriyad            # should NOT read UNSAFE

# mTLS gates every route (incl. /healthz) AND enforces the cert's role (P6). /healthz + the fleet reads
# below are operator-role, so present the operator cert:
CERTS="--cacert /etc/kriyad/ca/ca.pem --cert /etc/kriyad/ca/operator.pem --key /etc/kriyad/ca/operator.key"
curl $CERTS https://localhost:8443/healthz  # ok

# End-to-end (air-gap side-load → serve → re-prove), mirrors scripts/e2e-pilot.sh:
kriyad ingest-file /path/to/outbox.ndjson   # offline re-verify + ingest (no cert — sneaker-net)
curl $CERTS https://localhost:8443/v1/coverage  # operator reads the fleet; the device shows `current`
```

## Config
The 5 vars in `kriyad.env` (`KRIYAD_BIND`, `KRIYAD_DB`, `KRIYAD_LICENSE`, `KRIYAD_CA_DIR`, and the P6
migration grace `KRIYAD_ALLOW_LEGACY_CERTS` — default off; see the aggregator `INSTALL.md` §CERTS for the
reissue-then-enforce migration path). The SQLite store lives in `/var/lib/kriyad` (systemd
`StateDirectory`). Nothing leaves the host.
