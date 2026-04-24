# verify-svelio

Standalone open-source verifier for **Svelio integrity proof bundles**
(spec `svelio-integrity-v1`).

Published at **[verify.svelio.app](https://verify.svelio.app)**.

Runs entirely in the browser — no backend, no Svelio services, **no runtime
dependency on any CDN**. All JavaScript dependencies are vendored locally in
the `vendor/` folder and served from the same origin as the verifier itself.

## What it verifies

Given a `.zip` bundle downloaded from a `https://svelio.app/v/<id>` page:

- Parses `manifest.json`, reports project metadata and presence of the
  ancillary proof files (`ots.bin`, `tsr.bin`, Ed25519 public key).
- Recomputes the **Merkle root** from the manifest's SHA-256 values using the
  specification below, and compares it against `manifest.merkleRoot`.
- Computes **SHA-256** of arbitrary files the user drops in and matches each
  hash against the manifest entries.
- Displays the exact CLI invocations required to verify the external proofs
  (OpenTimestamps and FreeTSA RFC 3161) with standard open-source tools.

## The spec — `svelio-integrity-v1`

```
manifest.json
  spec              string   always "svelio-integrity-v1"
  verifyId          string   public identifier of the delivery
  version           integer  monotonic per (verifyId)
  sealedAt          integer  epoch milliseconds (UTC)
  project.title     string   display title shown to client
  project.sender    string   display sender name
  files             array    each item: { name, size, sha256 }
  merkleRoot        hex64
```

Hashing: each `files[i].sha256` is the SHA-256 of the raw file bytes, as
lowercase hex.

Merkle root:

1. Take all `sha256` values as lowercase hex strings.
2. Sort them lexicographically (string compare).
3. Decode each from hex to 32 bytes.
4. Pair consecutive buffers; if the layer has an odd number, duplicate the
   last.
5. Concatenate each pair (`left || right`) and SHA-256 the result.
6. Repeat steps 4–5 on the resulting layer until a single buffer remains.
7. That buffer, lowercase-hex encoded, is `merkleRoot`.

External proofs bundled alongside the manifest:

- `ots.bin` — [OpenTimestamps](https://opentimestamps.org/) proof over the
  Merkle root. Verify with `ots verify ots.bin --target manifest.json`.
- `tsr.bin` — [RFC 3161](https://datatracker.ietf.org/doc/html/rfc3161)
  TimeStampResp over `SHA-256(manifest.json bytes)`, issued by
  [FreeTSA](https://freetsa.org).
- `<keyId>.pub` — Svelio Ed25519 public key used to sign download receipts.
  Not required to validate the seal; included for future receipt auditing.

## Running locally

Any static file server works:

```bash
python3 -m http.server --directory verify-svelio 8080
# open http://localhost:8080
```

No build step. The site is pure HTML/CSS/ES modules.

## Deployment — GitHub Pages

This directory is mirrored as the standalone public repository
`svelio-app/verifier`, served on GitHub Pages at
<https://verify.svelio.app>. Source of truth stays here in the main Svelio
monorepo; a sync workflow pushes changes to `svelio-app/verifier` on every
merge to `main` that touches this folder.

Setup done once on `svelio-app/verifier`:

1. GitHub org `svelio-app` → repo `verifier` (public).
2. Settings → Pages → Source: **GitHub Actions**.
3. Settings → Pages → Custom domain: `verify.svelio.app`.
4. Cloudflare DNS record: `CNAME verify → svelio-app.github.io`
   (DNS-only during initial cert provisioning, then re-enable Cloudflare
   proxy with SSL mode **Full (strict)**).

The workflow at `.github/workflows/deploy.yml` inside `svelio-app/verifier`
publishes the site on every push to `main`. A matching file lives in this
folder as `.github/workflows/deploy.yml` (alongside `index.html`, etc.) so
the sync preserves it.

## Why it exists

Svelio's primary guarantee to delivery recipients is **independent
verifiability**: even if Svelio ceases to exist, the proofs can still be
validated. This repository is part of that guarantee — the verification
logic is public, auditable, and not tied to Svelio infrastructure.

## Pinned dependencies (SHA-256)

All third-party JavaScript is vendored under `vendor/`. The current bytes
are locked to these SHA-256 digests:

```
933ad10567764b625253f1701934876c5adc904cdaca0a4373ef31d60001fd41  vendor/jszip.js
00c4ad71d472ef9137e713dbfd72ed48d9bd862214747c63af8ed55c5f8f3d14  vendor/noble-ed25519.js
6500ad4629fbbb9d9aed414a3fe91d4d67eae603ecf72675d684f54a6983bbd0  vendor/noble-hashes-crypto.js
b712ff3233b3601df38e8741381884f4aba624c5fbd2b38ccc9e2c60a7abe7bd  vendor/noble-hashes-sha512.js
2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438  vendor/freetsa-ca.pem
```

The FreeTSA root CA certificate (`vendor/freetsa-ca.pem`) is pinned additionally by its embedded X.509 SHA-256 fingerprint, hard-coded in `lib/tsr-verify.js` as `FREETSA_CA_FINGERPRINT`. Fetched from the FreeTSA website: <https://freetsa.org/files/cacert.pem>.

Verify locally: `shasum -a 256 vendor/*.js`.

Upstream sources, version-pinned:

- `jszip@3.10.1` (MIT, <https://github.com/Stuk/jszip>) — fetched via
  `https://cdn.jsdelivr.net/npm/jszip@3.10.1/+esm`.
- `@noble/ed25519@2.1.0` (MIT, <https://github.com/paulmillr/noble-ed25519>) —
  fetched via `https://cdn.jsdelivr.net/npm/@noble/ed25519@2.1.0/+esm`.
- `@noble/hashes@1.5.0` (MIT, <https://github.com/paulmillr/noble-hashes>) —
  fetched via `https://cdn.jsdelivr.net/npm/@noble/hashes@1.5.0/sha512/+esm`
  (plus its sibling `crypto/+esm` rewritten to a relative import).

To refresh a dependency, re-fetch the bundle, re-compute the digest, update
this section in the same PR, and have at least one reviewer confirm the
digests match the upstream npm release artifacts.

## Content Security Policy

The page declares a strict CSP via `<meta http-equiv>`:

```
default-src 'none';
script-src 'self';
style-src 'self';
img-src 'self' data:;
font-src 'self';
connect-src 'self';
form-action 'none';
frame-ancestors 'none';
base-uri 'self';
```

Any unexpected network activity (telemetry, third-party scripts) will be
blocked by the browser. The verifier genuinely makes zero outbound requests
after the initial page load.

## License

MIT — see `LICENSE`.
