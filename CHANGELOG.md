# Changelog

## Unreleased

### Breaking

- `veriseal seal` needs a signer key: `--key PATH` for an existing key, or `--new-key PATH` to create one. It never creates or overwrites a key on its own any more. Library: `seal(path, key_path=...)` or `seal(path, new_key_path=...)`.
- `veriseal verify` exits `3`, not `0`, when the log is INTACT but no key was pinned with `--pubkey`. Pass `--allow-unpinned` to get `0` in that case. Scripts that treat any non-zero exit as tampering should pin the key or pass the flag. Exit codes are listed in the README.
- `--require-anchor` now passes only for an anchor verified against a Bitcoin block, and so needs the network.

### Added

- `verify --check-bitcoin` and `pack --check-bitcoin`: check the anchor's Bitcoin attestation against the block header, fetched from mempool.space and blockstream.info, which must agree. The result is "verified against Bitcoin" (with block hash and time), "FALSE" (the block doesn't contain the proof) or "could not check" (with the reason).
- `verify --allow-unpinned`.

### Fixed

- A Bitcoin attestation that hasn't been checked against Bitcoin is reported as "calendar-attested, not checked against Bitcoin", never as confirmed, in `verify`, the pack report and the web verifier.
- Documentation now states exactly what the Merkle root, the file hash and the pack cover.
- The test suite fails any test that opens a network connection.
- Dependency caps raised to tested versions: cryptography <50, typer <0.27, rich <16.
