# veriseal Seal Check — version history

## 0.1.0

- Initial panel: load a `.seal.json` and get a live **SEALED & AUTHENTIC** / **SEAL INVALID**
  badge inside Foxglove.
- Verifies the manifest signature (Ed25519) and Merkle root (RFC 6962) via WebCrypto.
- Shows the sealed window (message count, time range, anchor status) and flags loaded topics the
  seal does not cover.
- Verification core (`sealcore.ts`) is tested for byte-for-byte equivalence with the Python
  `veriseal` reference.
