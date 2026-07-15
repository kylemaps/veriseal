# web/ — client-side verifier

[`verify.html`](verify.html) is a single, self-contained page that verifies a veriseal-sealed
log **without a server, a backend, or any network call**. It is the neutrality story made
literal: a third party who trusts neither the operator nor veriseal can drop the files in and
check the evidence on their own machine.

## What it does

Given a `.mcap` and its `.seal.json`, in the browser it:

1. **Verifies the Ed25519 signature** over the canonical manifest (WebCrypto `Ed25519`).
2. **Recomputes the RFC 6962 Merkle root** from the leaf hashes and compares it to the signed root.
3. **Hashes the `.mcap` bytes** (SHA-256) and compares to `source.sha256` + `size_bytes` — this
   catches any post-seal modification of the log.

All three must pass for a **VERIFIED** verdict; any failure is **TAMPERED**.

## Using it

Open `verify.html` in a recent Chrome, Edge, or Safari (WebCrypto Ed25519 is required), or host
it on any static file server. There is no build step. The **Load a sample sealed log** link
loads an embedded synthetic log so you can see a pass and then flip a byte live.

## Fidelity to the CLI

The JS in `verify.html` mirrors the Python reference implementation byte-for-byte:

| Browser (JS) | Python (`src/veriseal/`) |
|---|---|
| `canonicalize()` | `canonical.canonical_json` (sorted keys, no whitespace, UTF-8) |
| `leaf` sort + `merkleRoot()` | `merkle.merkle_root` (RFC 6962, `0x00`/`0x01` domain separation) |
| `verifySignature()` | `signing.verify` (Ed25519 over the manifest sans `signature`/`anchor`) |
| `sha256(file)` | `mcap_io.file_digest` |

If the manifest format or hashing changes in the Python code, update `verify.html` to match.

## Scope / limitations

- **Full-file integrity, not per-message localization.** The file-digest check catches any
  change to the log. Pinpointing *which* message changed (as `veriseal verify` does on the CLI)
  needs an MCAP parser + decompressor, which a CSP-locked single file can't carry; the digest
  check is the honest, format-agnostic neutrality proof.
- **Anchor status is informational here.** Confirming OpenTimestamps depth against Bitcoin is
  left to the CLI (`veriseal verify --require-anchor`).
- To pin a signer you already trust, compare the key fingerprint on a VERIFIED result against
  the one you hold out-of-band.
