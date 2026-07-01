# kriyad — air-gapped install

A single signed `.tar.zst` that stands up **kriyad** on a fully disconnected host. Every step below runs
offline; nothing phones home. Updates = carry the next signed bundle across the gap.

## 0. Verify before you trust (on the disconnected host)
Check the bundle against the **pinned** public key you obtained out-of-band (compare its fingerprint to
what kriya published):
```sh
bash verify-bundle.sh kriyad-<ver>-airgap-<arch>.tar.zst \
                      kriyad-<ver>-airgap-<arch>.tar.zst.cosign.bundle \
                      kriya-release.pub
# → cosign signature ok (tlog ignored, no network) + SHA256SUMS ok. A tampered byte fails here.
```

## 1. Extract
```sh
zstd -dc kriyad-<ver>-airgap-<arch>.tar.zst | tar -xf -
cd kriyad-<ver>-airgap-<arch>
```

## 2. Install the binary (BOX model) or load the image
- **Static binary:** `sudo install -m0755 binaries/kriyad binaries/kriya-audit /usr/local/bin/` — then
  follow the BOX `README.md` (systemd unit) if you want it supervised.
- **Container:** `docker load -i image/kriyad-<ver>.image.tar` (if the image was bundled).

## 3. License + mTLS (offline)
```sh
cp kriyad-license.example.json /etc/kriyad/kriyad-license.json   # replace with your real control-plane license
sudo ./kriyd-ca.sh                                              # or drop your own CA into KRIYAD_CA_DIR
```

## 4. Run + prove it works — entirely offline
```sh
kriyad ingest-file /media/approved/outbox.ndjson    # side-load device evidence, re-verified on ingest
kriyad &                                            # serve the store
curl -k https://localhost:8443/v1/coverage          # the device shows `current`
kriya-audit --readback <(curl -sk https://localhost:8443/v1/verify?device_pub=<pub>)   # re-prove the bytes yourself
```

Nothing in this flow makes an outbound call. The signature check, the ingest re-verification, and the
auditor read-back are all local — the guarantee holds with the network cable pulled.
