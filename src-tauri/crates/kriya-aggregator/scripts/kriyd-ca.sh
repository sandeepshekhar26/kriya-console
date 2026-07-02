#!/usr/bin/env bash
# kriyd-ca (DEV/PILOT stub) — the enrollment stub (real CA + per-device single-use tokens = Phase 3).
# Generates an offline dev CA, a kriyad server cert (SAN localhost/127.0.0.1), and N device client
# certs, all signed by the CA. mTLS pins the CA on both ends. Usage: kriyd-ca.sh [dir] [N]
set -euo pipefail
DIR="${1:-ca}"
N="${2:-1}"
mkdir -p "$DIR"
cd "$DIR"

eckey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

# Offline-rooted CA.
eckey ca.key
openssl req -x509 -new -key ca.key -days 3650 -subj "/CN=kriyad-dev-ca" -out ca.pem 2>/dev/null

# kriyad server cert (SAN for localhost + 127.0.0.1; v3 extensions — webpki requires them).
eckey server.key
openssl req -new -key server.key -subj "/CN=kriyad" -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1") \
  -out server.pem 2>/dev/null

# N device client certs (the per-device transport identity; Phase 3 binds device_pub into the SAN).
# The -extfile block is LOAD-BEARING: without it `openssl x509 -req` mints an x509 **v1** cert, and
# kriyad's WebPkiClientVerifier (rustls/webpki) rejects v1 leaves with "certificate unknown" —
# proven on a real host by CI kriyad-release run 3 (2026-07-02); the rustls unit tests never
# handshook with these files and the e2e ran plain HTTP, so only CI could catch it.
for i in $(seq 1 "$N"); do
  eckey "client-$i.key"
  openssl req -new -key "client-$i.key" -subj "/CN=device-$i" -out "client-$i.csr" 2>/dev/null
  openssl x509 -req -in "client-$i.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth") \
    -out "client-$i.pem" 2>/dev/null
done

rm -f ./*.csr ca.srl
echo "wrote dev CA + kriyad server cert + $N device client cert(s) to $DIR/"
