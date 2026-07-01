# kriyaD — install guide (BOX · K8S · air-gapped)

How a customer stands up **kriyad**, the on-prem evidence aggregator, inside their own boundary. Every
skin below runs the *same* single static binary; they differ only in how it's supervised and delivered.
Nothing in any flow makes an outbound call — kriyad re-verifies every device envelope offline with
`kriya-verify`, stores only signed metadata in append-only SQLite, and serves trustless read-back.

> Per-skin detail lives next to the artifacts: [`packaging/box/README.md`](packaging/box/README.md) ·
> [`packaging/airgap/INSTALL-AIRGAP.md`](packaging/airgap/INSTALL-AIRGAP.md). This page is the single
> entry point that ties them together.

---

## §0 — What kriyad is + the whole config surface

`kriyad` is a single-tenant, single static musl binary. It ingests signed `AttestationEnvelope`s (over
mTLS on the wire, or side-loaded from a file in the air-gap model), **re-verifies every signature +
hash-chain offline** (it never trusts the sending device), persists only signed metadata to append-only
SQLite, and exposes:

| Route | Method | Purpose |
|---|---|---|
| `/healthz` | GET | liveness (`ok`) |
| `/metrics` | GET | Prometheus counters |
| `/v1/envelopes` | POST | NDJSON batch ingest — verify each, gap-tolerant idempotent insert |
| `/v1/heartbeat` | POST | one signed heartbeat (the tail-truncation anchor) |
| `/v1/coverage` | GET | per-device `current` / `behind` / `silent` |
| `/v1/verify` | GET | trustless read-back: the **exact** stored signed bytes + latest heartbeat |

It refuses to start ingest without a valid **`control-plane`** license (verified on-device against the
pinned issuer key — no phone-home).

**The entire config surface is four environment variables** (`kriyad.env` — no other file, no flags):

| Variable | Default | What |
|---|---|---|
| `KRIYAD_BIND` | `0.0.0.0:8443` | address for the HTTPS (mTLS) listener |
| `KRIYAD_DB` | `/var/lib/kriyad/kriyad.sqlite` | the append-only SQLite store |
| `KRIYAD_LICENSE` | `/etc/kriyad/kriyad-license.json` | the offline `control-plane` license (start gate) |
| `KRIYAD_CA_DIR` | `/etc/kriyad/ca` | mTLS material — `{server.pem, server.key, ca.pem}` |

**mTLS is on when `KRIYAD_CA_DIR` holds those three files** (BOX + K8S + online modes). It requires *every*
client — including `/healthz` — to present a cert chaining to the pinned CA (`ca.pem`). If the directory
is absent, kriyad serves **plain HTTP** — dev/local only; never expose an un-pinned listener. Bootstrap a
dev CA + server cert + N device client certs with [`scripts/kriyd-ca.sh`](scripts/kriyd-ca.sh), or drop
your own CA into `KRIYAD_CA_DIR`. (The dev CA is the pilot enrollment stub; a real CA + per-device
single-use tokens is Phase 3.)

---

## §BOX — static binary + hardened systemd unit (the pilot default)

The Vault/Consul deployment model: one static binary, one hardened `systemd` unit, a bundled SQLite
store. No container runtime, no orchestrator. This is the recommended skin for a pilot host.

Artifact: `kriyad-<ver>-box-<arch>.tar.gz` (built by [`packaging/box/make-box.sh`](packaging/box/make-box.sh)) —
contains `kriyad`, `kriya-audit`, `kriyad.service`, `kriyad.env.example`, `install.sh`, `kriyd-ca.sh`, `README.md`.

### 1. Verify + extract
```sh
shasum -a 256 -c kriyad-<ver>-box-<arch>.tar.gz.sha256
tar -xzf kriyad-<ver>-box-<arch>.tar.gz && cd kriyad-<ver>-box-<arch>
```

### 2. Install (as root)
```sh
sudo ./install.sh
# → /usr/local/bin/{kriyad,kriya-audit}, the systemd unit, /etc/kriyad + /etc/kriyad/ca,
#   and /etc/kriyad/kriyad.env (your existing config/license are never clobbered on re-run).
```

### 3. License + mTLS
```sh
# a) drop your control-plane license (obtained from kriya; in the pilot it's issued via the dev issuer):
sudo cp your-control-plane-license.json /etc/kriyad/kriyad-license.json

# b) bootstrap mTLS — a dev CA, the kriyad server cert, and one device client cert:
sudo /usr/local/share/kriyad/kriyd-ca.sh /etc/kriyad/ca 1
#   …or drop your own {server.pem, server.key, ca.pem} into /etc/kriyad/ca instead.
```

### 4. Start + confirm it's healthy and hardened
```sh
sudo systemctl enable --now kriyad
systemctl is-active kriyad                 # → active
systemd-analyze security kriyad            # overall exposure should NOT read UNSAFE

# /healthz over mTLS — a client cert is required (the CA pins both ends):
curl --cacert /etc/kriyad/ca/ca.pem \
     --cert /etc/kriyad/ca/client-1.pem --key /etc/kriyad/ca/client-1.key \
     https://localhost:8443/healthz        # → ok
```

### 5. Prove the trust loop — ingest → serve → auditor re-proves offline
Once a device is pushing evidence (or you side-load an outbox file carried from one), you can re-prove the
stored bytes yourself — the aggregator is never trusted:
```sh
DEVICE=<the device's ed25519 public key hex>

# read the EXACT stored signed bytes back over mTLS:
curl --cacert /etc/kriyad/ca/ca.pem \
     --cert /etc/kriyad/ca/client-1.pem --key /etc/kriyad/ca/client-1.key \
     "https://localhost:8443/v1/verify?device_pub=$DEVICE" > readback.json

# re-verify them fully offline: signatures + hash-chain + merkle root + tail-truncation anchor:
kriya-audit --readback readback.json       # exit 0 = authentic; a tampered/truncated set exits 1

curl --cacert /etc/kriyad/ca/ca.pem \
     --cert /etc/kriyad/ca/client-1.pem --key /etc/kriyad/ca/client-1.key \
     "https://localhost:8443/v1/coverage"   # the device reads `current`
```

For a self-contained, runnable demo of this exact loop (ingest → serve → read-back → coverage) over the
real binaries, see [`scripts/e2e-pilot.sh`](scripts/e2e-pilot.sh) — it runs the sequence over a local
build (plain HTTP for zero external deps); the BOX host runs the identical steps over mTLS as above.

---

## §K8S — the distroless image in a cluster (demand-pulled)

The image ships today: a `<15 MB` distroless-static-nonroot OCI image
([`packaging/Dockerfile`](packaging/Dockerfile), built by
[`packaging/build-image.sh`](packaging/build-image.sh)) — the smallest defensible base for a single static
binary. It runs unchanged in any orchestrator.

> **A packaged Helm chart is demand-pulled (Phase 5), not shipped yet.** Until then, run the image with a
> plain manifest. **`replicas: 1` is required** — kriyad is single-tenant SQLite (single-writer); a
> Postgres store + HPA is the deferred SHIP-PG/Phase-5 work.

Load the image into your registry (from `build-image.sh`, or the air-gap bundle's `image/…image.tar`),
then apply a minimal Deployment + Service + Secret + PVC:

```yaml
apiVersion: v1
kind: Secret
metadata: { name: kriyad-config }
stringData:
  kriyad-license.json: |   # your control-plane license
    { ... }
  ca.pem: |                # the pinned client CA
    -----BEGIN CERTIFICATE-----
  server.pem: |            # the kriyad server cert (SAN = the Service DNS name)
    -----BEGIN CERTIFICATE-----
  server.key: |            # the server key
    -----BEGIN PRIVATE KEY-----
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: kriyad-data }
spec: { accessModes: [ReadWriteOnce], resources: { requests: { storage: 10Gi } } }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: kriyad }
spec:
  replicas: 1                      # REQUIRED: single-writer SQLite until Postgres (SHIP-PG, deferred)
  selector: { matchLabels: { app: kriyad } }
  template:
    metadata: { labels: { app: kriyad } }
    spec:
      securityContext: { runAsNonRoot: true }
      containers:
        - name: kriyad
          image: kriyad:<ver>
          ports: [ { containerPort: 8443 } ]
          env:
            - { name: KRIYAD_BIND,    value: "0.0.0.0:8443" }
            - { name: KRIYAD_DB,      value: "/data/kriyad.sqlite" }
            - { name: KRIYAD_LICENSE, value: "/etc/kriyad/kriyad-license.json" }
            - { name: KRIYAD_CA_DIR,  value: "/etc/kriyad/ca" }
          volumeMounts:
            - { name: data,    mountPath: /data }
            - { name: license, mountPath: /etc/kriyad/kriyad-license.json, subPath: kriyad-license.json, readOnly: true }
            - { name: ca,      mountPath: /etc/kriyad/ca, readOnly: true }
      volumes:
        - { name: data,    persistentVolumeClaim: { claimName: kriyad-data } }
        - { name: license, secret: { secretName: kriyad-config, items: [ { key: kriyad-license.json, path: kriyad-license.json } ] } }
        - { name: ca,      secret: { secretName: kriyad-config, items: [ { key: ca.pem, path: ca.pem }, { key: server.pem, path: server.pem }, { key: server.key, path: server.key } ] } }
---
apiVersion: v1
kind: Service
metadata: { name: kriyad }
spec: { selector: { app: kriyad }, ports: [ { port: 8443, targetPort: 8443 } ] }
```

When the Helm chart lands, this becomes `helm install kriyad … --set replicaCount=1` with the license/CA as
chart-managed Secrets and the store as a PVC.

---

## §AIR-GAPPED — a signed `.tar.zst` carried across the gap

For fully disconnected / high-assurance hosts. A single **cosign key-signed** `.tar.zst` that a
disconnected site re-verifies offline against a **pinned** public key (`kriya-release.pub`, obtained
out-of-band). Updates = carry the next signed bundle across the gap. Built by
[`packaging/airgap/make-bundle.sh`](packaging/airgap/make-bundle.sh); full flow in
[`packaging/airgap/INSTALL-AIRGAP.md`](packaging/airgap/INSTALL-AIRGAP.md).

```sh
# 0. Verify before you trust — cosign signature (tlog ignored, no network) + SHA256SUMS:
bash verify-bundle.sh kriyad-<ver>-airgap-<arch>.tar.zst \
                      kriyad-<ver>-airgap-<arch>.tar.zst.cosign.bundle \
                      kriya-release.pub

# 1. Extract:
zstd -dc kriyad-<ver>-airgap-<arch>.tar.zst | tar -xf - && cd kriyad-<ver>-airgap-<arch>

# 2. Install the static binaries (then follow §BOX for the systemd unit), or load the bundled image:
sudo install -m0755 binaries/kriyad binaries/kriya-audit /usr/local/bin/
#   docker load -i image/kriyad-<ver>.image.tar        # if the image was bundled

# 3. License + mTLS (offline):
sudo cp kriyad-license.example.json /etc/kriyad/kriyad-license.json   # replace with your real license
sudo ./kriyd-ca.sh /etc/kriyad/ca 1

# 4. Ingest side-loaded evidence, serve, and re-prove — entirely offline:
kriyad ingest-file /media/approved/outbox.ndjson     # offline re-verify on ingest
kriyad &                                             # serve the store
kriya-audit --readback <(curl -sk --cacert /etc/kriyad/ca/ca.pem \
     --cert /etc/kriyad/ca/client-1.pem --key /etc/kriyad/ca/client-1.key \
     "https://localhost:8443/v1/verify?device_pub=<pub>")
```

The signature check, the ingest re-verification, and the auditor read-back are all local — the guarantee
holds with the network cable pulled.

---

## Which skin?

| | supervision | delivery | use it when |
|---|---|---|---|
| **BOX** | systemd | tarball | pilot default; a single VM/host inside your boundary |
| **K8S** | Deployment (replicas 1) | OCI image | you already run k8s and want it there (SQLite-single-tenant caveat) |
| **AIR** | systemd *or* image | signed `.tar.zst` | fully disconnected / sneaker-net updates |
