# veriseal Seal Check — version history

## Unreleased

- Signer-key pinning: paste the signer's public key into the panel. The badge is green only
  when the seal was signed by the pinned key.
- Badge labels are now **SIGNER VERIFIED** (pinned key matches), **AUTHENTICITY NOT
  ESTABLISHED** (valid but no key pinned), **MANIFEST INVALID** (inconsistent manifest, or a
  key other than the pinned one), and **CANNOT CHECK** (the seal file couldn't be parsed or
  checked).

## 0.1.0

- Initial panel: load a `.seal.json` and get a live **SEALED & AUTHENTIC** / **SEAL INVALID**
  badge inside Foxglove.
- Verifies the manifest signature (Ed25519) and Merkle root (RFC 6962) via WebCrypto.
- Shows the sealed window (message count, time range, anchor status) and flags loaded topics the
  seal does not cover.
- Verification core (`sealcore.ts`) is tested for byte-for-byte equivalence with the Python
  `veriseal` reference.
