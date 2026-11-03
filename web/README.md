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

It also has a **signer key** field: paste the signer's public key, obtained out-of-band, to pin it.
The verdict is one of:

- **VERIFIED** (green): all three checks pass and the manifest was signed by the pinned key.
- **AUTHENTICITY NOT ESTABLISHED** (amber): all three checks pass, but no key is pinned. The
  embedded key alone proves nothing about who signed, so a tampered re-seal would look the same.
- **SIGNER MISMATCH**: the log is internally consistent but was not signed by the pinned key.
- **TAMPERED**: any check fails.

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

It also parses the manifest as strictly as Python does: integers only (so `1.7e18` or `1.0` is
rejected, as the Python canonicaliser rejects floats), integers beyond 2^53 kept exact, and
well-formed Unicode only. [`conformance/parse-cases.json`](../conformance/parse-cases.json) lists
the inputs that must be accepted or rejected; the tests run the page's own parser against it.

## Hostile files

The page renders values read from the files it checks, so it treats them as hostile:

- The page is built with text nodes only (no `innerHTML`), so a value such as
  `<img src=x onerror=alert(1)>` in a seal file appears on the page as plain text.
- A `Content-Security-Policy` meta tag allows only the page's own inline script and style,
  pinned by SHA-256 hash, so the page cannot make network requests, load other scripts or run
  inline event handlers. If you edit the `<script>` or `<style>`, update the hashes;
  `tests/test_web_verifier_hardening.py` fails and prints the new policy.

## Scope / limitations

- **Full-file integrity, not per-message localization.** The file-digest check catches any
  change to the log. Pinpointing *which* message changed (as `veriseal verify` does on the CLI)
  needs an MCAP parser + decompressor, which this dependency-free single file doesn't carry; the
  digest check is the honest, format-agnostic neutrality proof.
- **Anchor status is informational here.** The page shows whether an OpenTimestamps proof is
  embedded but does not check it against Bitcoin, because that needs block data from the
  network. `veriseal verify --check-bitcoin` does, as does the OpenTimestamps client with a
  Bitcoin node.
- Pinning only helps if the key you paste really is the signer's: get it from the signer through
  a channel the log's holder doesn't control.
