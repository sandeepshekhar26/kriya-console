#!/usr/bin/env bash
# kriyd-ca — dev/pilot mTLS CA + role-stamped cert bootstrapper (the enrollment stub; a real
# enrollment CA + CSR-binding + per-device single-use tokens is Phase 3, doc 13).
#
# REGENERATE-SAFE: the CA (ca.key/ca.pem) and the kriyad server cert are generated only when ABSENT and
# REUSED when present, so re-running to mint one more cert never rotates the CA — which would orphan
# every already-issued cert. Leaf certs are (re)written on each run.
#
# ROLE STAMPING (P6, doc 22 §11-B2): each client cert carries a SAN URI naming its role. kriyad parses
# it post-handshake (tls.rs) and gates routes on it, so a stolen/misused cert is contained:
#   * a DEVICE cert cannot read the fleet (/v1/coverage, /v1/verify) or publish policy;
#   * an OPERATOR cert cannot POST device evidence (/v1/envelopes, /v1/heartbeat, /v1/device-info);
#   * a DEVICE cert is BOUND to one device_pub, so it cannot post heartbeats/inventory or pull policy
#     for any other device (closes the coverage/inventory-poisoning vector, doc 13's two-key binding).
# The SAN URIs:
#   operator :  URI = kriya://role=operator
#   device   :  URI = kriya://role=device;device_pub=<lowercase-hex ed25519 evidence pubkey>
# (The device_pub here is the device's RECEIPT-SIGNING pubkey — the same key that signs its envelopes —
# so a device cert can only introduce evidence the cert itself is bound to.)
#
# Usage:
#   kriyd-ca.sh <dir> [N]                        LEGACY: N role-LESS client certs (client-1..N), exactly
#                                                as pre-P6. kriyad accepts these ONLY under the migration
#                                                grace window (KRIYAD_ALLOW_LEGACY_CERTS=1); with grace
#                                                off (the default) they are 403'd — so the shipped
#                                                default is secure and legacy is an explicit opt-in.
#   kriyd-ca.sh <dir> --operator                 mint an operator cert  -> operator.pem / operator.key
#   kriyd-ca.sh <dir> --device <device_pub_hex>  mint a device cert     -> device.pem   / device.key
#   (--operator and --device may be combined in one invocation)
#
# MIGRATION (grace-off is the goal): run with KRIYAD_ALLOW_LEGACY_CERTS=1, reissue every cert with a
# role (--operator / --device <pub>) onto the SAME CA, roll them out, then unset the env var to enforce.
set -euo pipefail
DIR="${1:?usage: kriyd-ca.sh <dir> [N | --operator | --device <hex> ...]}"
shift || true
mkdir -p "$DIR"
cd "$DIR"

eckey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

# Offline-rooted CA — generated once, then REUSED (never rotated on a re-run).
if [ ! -f ca.pem ] || [ ! -f ca.key ]; then
  eckey ca.key
  openssl req -x509 -new -key ca.key -days 3650 -subj "/CN=kriyad-dev-ca" -out ca.pem 2>/dev/null
fi

# kriyad server cert (SAN for localhost + 127.0.0.1; v3 extensions — webpki requires them). Reused if present.
if [ ! -f server.pem ] || [ ! -f server.key ]; then
  eckey server.key
  openssl req -new -key server.key -subj "/CN=kriyad" -out server.csr 2>/dev/null
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1") \
    -out server.pem 2>/dev/null
  rm -f server.csr
fi

# Mint a client leaf: $1 = basename, $2 = OPTIONAL SAN URI (absent => a role-LESS legacy cert).
# The -extfile block is LOAD-BEARING even absent a SAN: without v3 extensions `openssl x509 -req` mints
# an x509 **v1** cert, and kriyad's WebPkiClientVerifier (rustls/webpki) rejects v1 leaves with
# "certificate unknown" — proven on a real host by CI kriyad-release run 3 (2026-07-02).
mint_client() {
  local base="$1" san_uri="${2:-}"
  local ext="basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth"
  if [ -n "$san_uri" ]; then ext="$ext\nsubjectAltName=URI:$san_uri"; fi
  eckey "$base.key"
  openssl req -new -key "$base.key" -subj "/CN=$base" -out "$base.csr" 2>/dev/null
  openssl x509 -req -in "$base.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 \
    -extfile <(printf "%b" "$ext") -out "$base.pem" 2>/dev/null
  rm -f "$base.csr"
}

if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
  # LEGACY positional form: N role-less client certs (byte-for-byte the pre-P6 behavior).
  N="$1"
  for i in $(seq 1 "$N"); do mint_client "client-$i"; done
  echo "wrote dev CA + kriyad server cert + $N role-less (legacy) client cert(s) to $DIR/"
elif [ "$#" -eq 0 ]; then
  # No cert args (e.g. `kriyd-ca.sh <dir>` alone) — default to one legacy client cert, as pre-P6.
  mint_client "client-1"
  echo "wrote dev CA + kriyad server cert + 1 role-less (legacy) client cert to $DIR/"
else
  MINTED=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --operator)
        mint_client "operator" "kriya://role=operator"
        MINTED="$MINTED operator"; shift ;;
      --device)
        pub="${2:?--device needs a device_pub hex}"
        mint_client "device" "kriya://role=device;device_pub=$pub"
        MINTED="$MINTED device($pub)"; shift 2 ;;
      *) echo "kriyd-ca.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
  done
  echo "wrote dev CA + kriyad server cert + role-stamped cert(s):$MINTED to $DIR/"
fi
