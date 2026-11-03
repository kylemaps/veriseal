# Changelog

## Unreleased

### Breaking

- `veriseal seal` needs a signer key: `--key PATH` for an existing key, or `--new-key PATH` to create one. It never creates or overwrites a key on its own any more. Library: `seal(path, key_path=...)` or `seal(path, new_key_path=...)`.
- `veriseal verify` exits `3`, not `0`, when the log is INTACT but no key was pinned with `--pubkey`. Pass `--allow-unpinned` to get `0` in that case. Scripts that treat any non-zero exit as tampering should pin the key or pass the flag. Exit codes are listed in the README.
- `--require-anchor` now passes only for an anchor verified against a Bitcoin block, and so needs the network.

### Added

- `verify --check-bitcoin` and `pack --check-bitcoin`: check the anchor's Bitcoin attestation against the block header, fetched from mempool.space and blockstream.info, which must agree. The result is "verified against Bitcoin" (with block hash and time), "FALSE" (the block doesn't contain the proof) or "could not check" (with the reason).
- `bench/measure.py`: measures what sealing costs on a given computer (time, CPU, peak memory, and energy where a power sensor exists: Jetson, Raspberry Pi 5, Intel RAPL, battery). See `bench/README.md`.
- `--key-passphrase-env VAR`: `keygen` encrypts the new key with the passphrase in environment variable `VAR`, and `seal` uses it to decrypt the key.

### Changed

- `seal` and `verify` hash each message as they read it instead of loading the whole log first, so memory no longer grows with the log's size: sealing a 1 GB camera log peaks at 74 MB instead of 1 GB, and runs about 2.5 times faster. Output is byte-for-byte unchanged.
- The `seal` summary always states the anchor: pending, none (`--no-anchor`), or UNANCHORED when OpenTimestamps could not be reached (before, that was a single warning line).
- Private keys from `keygen` and `seal --new-key` are created readable by their owner only (mode 0600), and an existing file is never replaced (`keygen --force` still replaces one on purpose).

### Security

- Web verifier: a seal file could inject HTML and run script in the page (for example through `messages.count` or `source.size_bytes`). The page now builds its content with text only and ships a Content-Security-Policy that allows only its own inline script and style.
- Web verifier and Foxglove panel: a manifest with a float such as `1.7e18` was read as an integer and could pass, although the Python verifier rejects it. Both now parse as strictly as Python; the cases are in `conformance/parse-cases.json`.

### Fixed

- A Bitcoin attestation that hasn't been checked against Bitcoin is reported as "calendar-attested, not checked against Bitcoin", never as confirmed, in `verify`, the pack report and the web verifier.
- Documentation now states exactly what the Merkle root, the file hash and the pack cover.
- The test suite fails any test that opens a network connection.
- Dependency caps raised to tested versions: cryptography <50, typer <0.27, rich <16.
