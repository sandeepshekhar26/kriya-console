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
| `kriyad.env.example` | the entire config surface — 4 env vars |
| `kriyd-ca.sh` | bootstrap an offline mTLS CA + server/client certs |
| `install.sh` | install binaries + unit (run as root) |

## Install
```sh
sudo ./install.sh
# 1) drop a control-plane license at /etc/kriyad/kriyad-license.json
# 2) sudo /usr/local/share/kriyad/kriyd-ca.sh        # or put your own CA in /etc/kriyad/ca
# 3) sudo systemctl enable --now kriyad
```

## Verify it's healthy
```sh
systemctl is-active kriyad                 # active
systemd-analyze security kriyad            # should NOT read UNSAFE

# mTLS gates every route (incl. /healthz) — present a client cert chaining to the pinned CA:
CERTS="--cacert /etc/kriyad/ca/ca.pem --cert /etc/kriyad/ca/client-1.pem --key /etc/kriyad/ca/client-1.key"
curl $CERTS https://localhost:8443/healthz  # ok

# End-to-end (air-gap side-load → serve → re-prove), mirrors scripts/e2e-pilot.sh:
kriyad ingest-file /path/to/outbox.ndjson   # offline re-verify + ingest
curl $CERTS https://localhost:8443/v1/coverage  # the device shows `current`
```

## Config
Everything is the 4 vars in `kriyad.env` (`KRIYAD_BIND`, `KRIYAD_DB`, `KRIYAD_LICENSE`, `KRIYAD_CA_DIR`).
The SQLite store lives in `/var/lib/kriyad` (systemd `StateDirectory`). Nothing leaves the host.
