# SETUP — run kriya Console + kriyaD on a fresh machine

A from-zero developer setup for **both halves** of the control plane:

- **kriya Console** — the Tauri desktop app (React + compiled Rust). This is what ships as the `.dmg`.
- **kriyaD** — the headless aggregator (`kriya-aggregator` crate → the `kriyad` binary). The on-prem box
  the Console's paid fleet cockpit talks to over mTLS.

> Everything runs on-device; nothing here phones home. macOS is the primary target (the shipped app is
> macOS); the kriyad server also builds/runs on Linux.

---

## 0. Repo layout (clone these side-by-side)

The Console **bundles the runtime binaries** as Tauri sidecars, so it needs the **public runtime repo**
next to it:

```
software_for_agents/
├── kriya-console/     ← this repo (private, the paid Console + kriyad)
│   └── dev-keys/      ← dev secrets (gitignored): issuer-dev-seed.hex, AuthKey_*.p8
└── experiment1/       ← the public kriya runtime (github.com/sandeepshekhar26/kriya)
```

```sh
cd ~/software_for_agents            # or wherever you keep them
git clone git@github.com:sandeepshekhar26/kriya-console.git
git clone git@github.com:sandeepshekhar26/kriya.git experiment1
```

If you put `experiment1` somewhere else, export `KRIYA_REPO=/abs/path/to/experiment1` before any build.

---

## 1. Toolchain (one-time)

| Tool | Version | Install |
|---|---|---|
| **Rust** | ≥ 1.77 (stable) | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| **Node** | ≥ 20 (22+ for the `.mts` demo/scripts) | `brew install node` or nvm |
| **Xcode Command Line Tools** (macOS) | latest | `xcode-select --install` |
| **Tauri v2 prerequisites** | — | CLT above is enough on macOS; see [tauri.app/start/prerequisites](https://tauri.app/start/prerequisites/) for Linux (`webkit2gtk`, `libssl`, etc.) |

Add the macOS build targets (needed for a **universal** release build):

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
```

Optional: the trust-spine has cross-language verifier parity tests (TS ↔ Rust ↔ Python ↔ Java). You only
need a JVM/Python if you run those specific parity suites; the core build does not.

---

## 2. kriya Console — dev + build

```sh
cd kriya-console
npm install                       # JS deps
npm test                          # vitest — the trust spine (TS↔Rust parity, policy, compliance). Should be all green.
npx tsc --noEmit                  # type-check
```

**Run the frontend alone (browser, no native app)** — fastest inner loop for UI work:

```sh
npm run dev                       # vite on http://localhost:1420
```

**Run the full desktop app** (Tauri) — this needs the sidecars staged first:

```sh
scripts/bundle-gateway.sh release # builds kriya-gateway/kriya-hook/kriya-hermes-hook from ../experiment1
npm run tauri dev                 # launches the real desktop app
```

> `bundle-gateway.sh` fails with `kriya crate not found` if `../experiment1` (or `$KRIYA_REPO`) is missing
> — that's the #1 fresh-machine gotcha.

**Rust backend tests** (two feature configs — the paid control-plane code is behind a Cargo feature):

```sh
cd src-tauri
cargo test                            # default (free-tier) build
cargo test --features control-plane   # + the fleet cockpit / policy downlink / evidence export
cargo clippy --features control-plane --all-targets
```

**Dev licenses** (to exercise the paid tier locally): the paid features are license-gated. A dev issuer
seed lives at `dev-keys/issuer-dev-seed.hex`; the test/demo helpers (`license::dev_issue`) mint a local
`pro` / `fleet-console` / `control-plane` token from it. See `dev-keys/LICENSES-LOCAL.md`. Without the seed,
the paid paths stay dormant (that's the free-tier firewall working, not a bug).

---

## 3. kriyaD — build + run the aggregator

`kriyad` is a separate binary in the same Cargo workspace. Build and run it:

```sh
cd kriya-console/src-tauri
cargo build -p kriya-aggregator       # → target/debug/kriyad
```

**Its entire config surface is five env vars** (no config file, no flags):

| Var | Default | What |
|---|---|---|
| `KRIYAD_BIND` | `127.0.0.1:8443` | listen address (HTTPS/mTLS when a CA dir is present) |
| `KRIYAD_DB` | `kriyad.sqlite` | the append-only SQLite store (backup = copy the file) |
| `KRIYAD_LICENSE` | `kriyad-license.json` | the offline `control-plane` license (start gate) |
| `KRIYAD_CA_DIR` | `ca` | mTLS material: `{server.pem, server.key, ca.pem}` + role-stamped client certs |
| `KRIYAD_ALLOW_LEGACY_CERTS` | *(off)* | P6 migration grace: honor pre-role certs (default **off** — roles enforced) |

**Local plain-HTTP run** (dev only — no certs; roles not enforced):

```sh
KRIYAD_CA_DIR=/tmp/none \
KRIYAD_LICENSE=crates/kriya-aggregator/fixtures/dev-control-plane-license.json \
KRIYAD_BIND=127.0.0.1:8455 \
target/debug/kriyad                       # run from src-tauri/
curl -s http://127.0.0.1:8455/healthz     # (plain HTTP: any peer; mTLS: needs a cert)
```

**mTLS run with P6 role-stamped certs** (how it really ships):

```sh
# bootstrap a dev CA + server cert + role-stamped client certs:
bash crates/kriya-aggregator/scripts/kriyd-ca.sh /tmp/ca --operator
bash crates/kriya-aggregator/scripts/kriyd-ca.sh /tmp/ca --device <device_pub_hex>

KRIYAD_CA_DIR=/tmp/ca \
KRIYAD_LICENSE=crates/kriya-aggregator/fixtures/dev-control-plane-license.json \
KRIYAD_BIND=127.0.0.1:8455 \
target/debug/kriyad     # now on https:// with role gating (device≠operator, doc 22 §11-B2)

# an operator-role client (device certs are 403'd on fleet reads — that's P6 working):
curl --cacert /tmp/ca/ca.pem --cert /tmp/ca/operator.pem --key /tmp/ca/operator.key \
     https://localhost:8455/v1/coverage
```

**The one-command end-to-end proof** (build both binaries → air-gap ingest → serve over mTLS →
auditor re-proves offline → the P6 role 403s, all live):

```sh
bash crates/kriya-aggregator/scripts/e2e-pilot.sh
```

Full customer-facing install (BOX systemd / K8S / air-gap) lives in
[`src-tauri/crates/kriya-aggregator/INSTALL.md`](src-tauri/crates/kriya-aggregator/INSTALL.md).

---

## 4. Shipping a signed macOS release (maintainer only)

Needs an Apple **Developer ID Application** cert in the login keychain + notarization creds (an App Store
Connect API key `.p8`, or an Apple ID app-specific password). See the header of
[`scripts/macos/release.sh`](scripts/macos/release.sh).

```sh
scripts/bump-version.sh 0.2.4                      # sync version across package.json/Cargo/tauri.conf
export APPLE_SIGNING_IDENTITY="Developer ID Application: <NAME> (<TEAMID>)"
export APPLE_API_KEY=<KeyID> APPLE_API_ISSUER=<IssuerID> \
       APPLE_API_KEY_PATH=$PWD/dev-keys/AuthKey_<KeyID>.p8
scripts/macos/release.sh --universal               # build → sign → notarize → staple → sha256
#   add --gh-release to publish the .dmg + .sha256 to the PUBLIC repo as console-v<version>
```

Verify a built/downloaded dmg like a real user would:

```sh
xcrun stapler validate <dmg>                       # ticket present
spctl -a -vvv -t open --context context:primary-signature <dmg>   # → accepted, Notarized Developer ID
```

---

## 5. Fresh-machine checklist / troubleshooting

- [ ] `experiment1` cloned next to `kriya-console` (or `KRIYA_REPO` set) — else `bundle-gateway.sh` fails.
- [ ] `rustup target add aarch64-apple-darwin x86_64-apple-darwin` — else `--universal` release fails.
- [ ] `npm test` green before building — the fastest confidence check the toolchain is right.
- [ ] Paid features dormant? That's expected without a dev license (`dev-keys/issuer-dev-seed.hex`).
- [ ] `kriyad` says "no mTLS certs; serving plain HTTP" — expected when `KRIYAD_CA_DIR` has no certs.
- [ ] kriyad 403s every route under mTLS? Your client cert has no role SAN — reissue with `kriyd-ca.sh
      --operator`/`--device`, or set `KRIYAD_ALLOW_LEGACY_CERTS=1` during migration.

Orientation for the codebase itself is in [`CLAUDE.md`](CLAUDE.md) and [`README.md`](README.md).
