# veriseal

For incident investigators and safety teams who need to prove a robot/autonomy log wasn't altered after the fact.

A CLI that seals a robot/autonomy log (MCAP) with an Ed25519 signature and an OpenTimestamps proof anchored in Bitcoin, producing a `.seal.json` manifest. A disinterested party can later prove "this log matches a seal made by key K", but only if the verifier **pins the signer's key** (`--pubkey`). Without key pinning, a tampered re-seal with a new key still passes. The seal also carries an OpenTimestamps proof that it existed no later than a given Bitcoin block, and `veriseal verify --check-bitcoin` checks that proof against the block itself.

> **Status:** early v0.1, solo project: seal/verify/inspect/pack work end-to-end, but APIs may change. Adversarial feedback welcome: [open an issue](https://github.com/kylemaps/veriseal/issues).

![CI](https://github.com/kylemaps/veriseal/actions/workflows/ci.yml/badge.svg)

![demo](https://raw.githubusercontent.com/kylemaps/veriseal/main/demo/demo.gif)

## Install

> **Not on PyPI yet.** Install directly from GitHub:

```bash
pip install git+https://github.com/kylemaps/veriseal
```

Or for development:

```bash
git clone https://github.com/kylemaps/veriseal.git
cd veriseal
pip install -e .
```

## Quickstart

No log handy? In a clone of this repo, `python demo/make_sample.py log.mcap` writes the synthetic 198-message log the outputs below come from. `tests/test_readme_quickstart.py` runs this block as written, so the outputs stay accurate.

```bash
# Generate a reusable signer key (and its public key, to share for pinning)
veriseal keygen --out signer.key.pem --pub signer.pub.pem

# Seal a log (submits Merkle root to OpenTimestamps by default)
veriseal seal log.mcap --key signer.key.pem --out log.seal.json

# Or seal fully offline, without OpenTimestamps (same key)
veriseal seal log.mcap --key signer.key.pem --no-anchor --out log.seal.json

# Verify integrity without pinning a key: exits 3, because the embedded key is trusted
veriseal verify log.mcap log.seal.json
# INTACT (signer not pinned): signature valid, 198 messages, root 9bfe72f8a52c5ad5...
#   WARNING: no --pubkey: trusting the key embedded in the manifest; ...

# Verify and pin the signer's key: the only way to catch a tampered re-seal
veriseal verify log.mcap log.seal.json --pubkey signer.pub.pem
# INTACT: signature valid, 198 messages, root 9bfe72f8a52c5ad5...

# Tamper detection: flip one byte inside a decoded message and re-verify.
# MCAP messages are chunk-compressed, so flipping a raw file byte usually
# breaks decompression outright rather than cleanly changing one message;
# decode first, flip, re-encode (see demo/tamper.py for the same approach).
python -c "
from mcap.reader import make_reader
from mcap.writer import Writer

rows, schemas, channels, flipped = [], {}, {}, False
with open('log.mcap', 'rb') as f:
    rows = list(make_reader(f).iter_messages())
with open('tampered.mcap', 'wb') as f:
    w = Writer(f); w.start()
    for sc, ch, m in rows:
        schemas.setdefault(ch.schema_id, 0 if (sc is None or ch.schema_id == 0) else
            w.register_schema(name=sc.name, encoding=sc.encoding, data=sc.data))
        channels.setdefault(ch.id, w.register_channel(
            topic=ch.topic, message_encoding=ch.message_encoding,
            schema_id=schemas[ch.schema_id], metadata=ch.metadata))
        data = m.data
        if ch.topic == '/pose' and not flipped:
            data, flipped = bytes([m.data[0] ^ 0xFF]) + m.data[1:], True
        w.add_message(channel_id=channels[ch.id], log_time=m.log_time,
                       data=data, publish_time=m.publish_time, sequence=m.sequence)
    w.finish()
"
veriseal verify tampered.mcap log.seal.json --pubkey signer.pub.pem
# TAMPERED
#   Source digest mismatch
#     expected 79d83f92510271e5...
#     actual   5e73e3ba4abc6267...
#   Merkle root mismatch
#     expected 9bfe72f8a52c5ad5...
#     actual   0816a35ad0908c74...
#   MODIFIED  topic='/pose' log_time=1750032000000000000

# Inspect an incident time-window (ISO-8601 or nanoseconds since epoch)
veriseal inspect log.mcap \
    --from 2025-06-16T00:00:01Z \
    --to   2025-06-16T00:00:04Z \
    --topic /pose

# Export window as a new MCAP (openable in Foxglove Studio)
veriseal inspect log.mcap \
    --from 2025-06-16T00:00:01Z \
    --to   2025-06-16T00:00:04Z \
    --out  incident.mcap

# Build a portable, independently re-verifiable incident-evidence bundle
veriseal pack log.mcap log.seal.json --out incident-pack/
veriseal pack log.mcap log.seal.json --out incident-pack --zip   # single .zip to hand off

# Later, fetch a pending timestamp's Bitcoin attestation from the calendars
veriseal anchor upgrade log.seal.json
```

### Signer keys

`veriseal keygen` and `seal --new-key` create the private key readable by its owner only (mode 0600; on Windows the folder's permissions apply), and never overwrite an existing file (`keygen --force` replaces one on purpose). To encrypt the key, put a passphrase in an environment variable and name the variable with `--key-passphrase-env`, for both commands:

```bash
veriseal keygen --out signer.key.pem --pub signer.pub.pem --key-passphrase-env SIGNER_PASS
veriseal seal log.mcap --key signer.key.pem --key-passphrase-env SIGNER_PASS
```

Whoever holds the private key can seal anything in your name. Keep it out of the folders where logs are recorded, packed or shared, so copying evidence never copies the key.

### Exit codes

`veriseal verify` exits with:

| Code | Meaning |
|---|---|
| `0` | INTACT, and signed by the key you pinned with `--pubkey` (or you passed `--allow-unpinned`) |
| `1` | TAMPERED, signed by a different key than the pinned one, or `--require-anchor` not met |
| `2` | Error: unreadable log, manifest or key file |
| `3` | INTACT, but no key was pinned. The key inside the manifest was trusted, so a re-seal by anyone with any key would also pass |

Scripts that only care about integrity of their own seals can pass `--allow-unpinned` to turn `3` into `0`. `veriseal pack` exits `0` or `1`; its report says whether the key was pinned.

### OpenTimestamps anchor

By default, `veriseal seal` submits the signed manifest's digest to public [OpenTimestamps](https://opentimestamps.org) calendar servers. The embedded proof starts as `status: "pending"`. Once a Bitcoin block includes the calendar's commitment (typically a few hours later), `veriseal anchor upgrade log.seal.json` fetches the Bitcoin attestation from the calendars and records it in place (`status` -> `confirmed`, block height recorded). The anchor is excluded from the signed payload, so this never invalidates the signature.

An OpenTimestamps proof is a chain of SHA-256 steps from the manifest's digest to the Merkle root in one Bitcoin block header. Checked against that header, it shows the manifest existed no later than that block, without trusting the calendars, the sealer or veriseal. Unchecked, it is only the calendar's claim, and `verify` reports it as "calendar-attested, not checked against Bitcoin".

`veriseal verify --check-bitcoin` does the check. It fetches the header of the block the proof names from two independent block explorers ([mempool.space](https://mempool.space) and [blockstream.info](https://blockstream.info)), requires both to return the same header and the header to hash to the block hash they report, then compares the header's Merkle root with what the proof computes. That relies on the two explorers not both serving the same fake block. To rely on nobody, check the proof (`veriseal pack` writes it out as `anchor.ots`) with the OpenTimestamps client and your own Bitcoin node.

`veriseal verify` reports the anchor for information only. It doesn't change the INTACT/TAMPERED verdict or the exit code unless `--require-anchor` is set. Without `--check-bitcoin` it stays offline:

```
INTACT: signature valid, 198 messages, root 9bfe72f8a52c5ad5...
  Source file unchanged (SHA-256 79d83f92510271e5...)
  Anchor: calendar-attested, Bitcoin block #812345 (not checked against Bitcoin; add --check-bitcoin)
```

With `--check-bitcoin`:

```
  Anchor: verified against Bitcoin, block #812345 (2023-10-15 17:24 UTC)
    The manifest existed no later than this block. Header from mempool.space and blockstream.info:
    block hash 00000000000000000000be714343a77f56af9599d8f477e8d0b00a617a7ba85f
```

The block time is set by the miner; Bitcoin's rules keep it within about two hours of real time. If the block doesn't contain the proof, the anchor is reported as FALSE (forged or corrupted). If an explorer can't be reached or the two disagree, it stays calendar-attested and the reason is printed. `veriseal pack --check-bitcoin` records the same result in the pack's `report.txt`.

Skip anchoring for offline workflows or CI:

```bash
veriseal seal log.mcap --key signer.key.pem --no-anchor
```

`--require-anchor` fails unless the anchor commits to this manifest and is verified against a Bitcoin block. It implies `--check-bitcoin`, so it needs the network. A missing or pending anchor fails it, and so does an unreachable or disagreeing explorer:

```bash
veriseal verify log.mcap log.seal.json --pubkey signer.pub.pem --require-anchor
```

### Auto-sealing every recording

Add one step to your ROS 2 recording workflow so every log is sealed the moment it finishes: generate a signer key once with `veriseal keygen`, then run `veriseal seal` on the recorder's exit (a post-record one-liner, or an `OnProcessExit` handler in a launch file). Copy-paste snippets: [docs/auto-seal.md](https://github.com/kylemaps/veriseal/blob/main/docs/auto-seal.md).

To see what sealing costs on the robot's own computer (time, memory, and energy where it has a power sensor), run [`bench/measure.py`](https://github.com/kylemaps/veriseal/blob/main/bench/README.md) on a few of its recordings.

### ROS 1 rosbags and other formats

veriseal hashes `(topic, log_time, payload)` message triples, which aren't MCAP-specific. It seals MCAP natively and ROS 1 `.bag` files directly via the optional `rosbags` reader (pure Python, no ROS install): `pip install "veriseal[ros1]"`, then `veriseal seal drive.bag ...`. `seal`, `verify`, and `pack` work the same across formats (the manifest records `source.format`); `inspect`'s window export is MCAP-only. See [docs/ros1.md](https://github.com/kylemaps/veriseal/blob/main/docs/ros1.md).

### Independent web verifier

[`web/verify.html`](https://github.com/kylemaps/veriseal/blob/main/web/verify.html) lets someone who trusts neither the operator nor veriseal check a seal. It is a single page: drop in an `.mcap` and its `.seal.json`, and it recomputes the Ed25519 signature, the RFC 6962 Merkle root and the SHA-256 file digest in the browser (WebCrypto; the page makes no network calls and uploads nothing). For a green VERIFIED you also paste the signer's public key, obtained out-of-band, and the page pins it. Without a pinned key the result stays amber, because the embedded key alone says nothing about who signed. Open the file locally or host it on any static server, and an insurer or investigator can check a sealed log without installing anything.

### Foxglove panel

[`veriseal-panel/`](https://github.com/kylemaps/veriseal/tree/main/veriseal-panel) is a [Foxglove Studio](https://foxglove.dev) extension that checks a seal without leaving Foxglove. Open a log and load its `.seal.json`; the panel checks the signature and Merkle root against the signer's Ed25519 key and shows a badge: SIGNER VERIFIED (when you pin the signer's key), AUTHENTICITY NOT ESTABLISHED (signature and Merkle root valid, no key pinned), MANIFEST INVALID, or CANNOT CHECK if the seal file can't be read. A panel only sees decoded messages, never the raw file bytes, so whole-file integrity stays with the CLI and the web verifier. The panel's verification core uses the same logic as the web verifier and is tested against the Python reference.

### Incident-evidence pack

`veriseal pack` builds an evidence package to keep with an already-sealed log. It holds the manifest, a plain-English verification report, the OpenTimestamps proof if there is one (with its state: pending, calendar-attested, or verified against Bitcoin when you pass `--check-bitcoin`), an offline copy of the [web verifier](https://github.com/kylemaps/veriseal/blob/main/web/verify.html) and a cover sheet that says what the seal proves and what it does not. The log itself is not copied in, so keep the two together. The report comes from the same verification code as `veriseal verify`, so it cannot drift from what the CLI says.

```bash
veriseal pack log.mcap log.seal.json --out incident-pack/        # a directory
veriseal pack log.mcap log.seal.json --out incident-pack --zip    # a single .zip to hand off
```

The pack is evidence infrastructure, not a compliance certificate: it supports disclosure obligations under things like the EU Product Liability Directive (2024/2853) or AI Act Article 73 by making a log's integrity independently checkable, but it never asserts the log's *contents* are true, and it never claims to satisfy any regulation on its own.

## Threat model

A seal proves that this log matches a seal made by key K at time T. Anyone can check that independently, provided two things hold: the verifier knows and pins the signer's public key (`--pubkey`), and the anchor has been checked against Bitcoin (`--check-bitcoin`). Without `--pubkey`, a tampered log re-sealed with a fresh key still passes. Without a checked anchor, the time rests only on what the sealer (or the calendar) says.

A seal does not prove that the log is a truthful record of what happened. It cannot undo data that was false when it was captured. Integrity ≠ veracity.

Neutrality comes from sealing as early as possible, ideally at capture, and anchoring the root in a public append-only log, so that no single party, the custodian included, can backdate or alter it.

> The Merkle root covers message content: each message's topic, log time and payload bytes. `source.sha256` is a separate byte-level check of the whole file, and both must pass for INTACT. A losslessly re-muxed MCAP with identical messages therefore verifies TAMPERED, but with only a source-digest mismatch: no Merkle mismatch and no MODIFIED/ADDED/REMOVED lines, which tells you the messages themselves are unchanged.

## How it works

1. Each message is domain-separated and hashed with SHA-256: `SHA-256(b"\x00" + b"veriseal-leaf-v1\x00" + len(topic) + topic + log_time + payload)`.
2. The leaf hashes are sorted by `(log_time, topic, leaf_hash)` and combined into a Merkle root with the [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) Merkle Tree Hash algorithm. Changing any message's topic, log time or payload changes the root, and the leaf diff pinpoints the affected (topic, log_time) group. Edits outside message content (schemas, attachments, metadata, file layout) leave the root unchanged; only the whole-file SHA-256 (`source.sha256`) catches those, and `verify` checks it too.
3. The manifest (root, all leaves and metadata) is serialized as canonical JSON and signed with Ed25519. The signer's public key is embedded in the manifest.
4. The signed manifest is hashed with SHA-256 and submitted to the public [OpenTimestamps](https://opentimestamps.org) calendars. A Bitcoin block later commits to it. Checked against that block's header, this shows the manifest existed no later than the block, with no trust in the calendars or the sealer. `verify --check-bitcoin` performs that check (see the trust model under [OpenTimestamps anchor](#opentimestamps-anchor)).

The `.seal.json` format is fully documented in [SPEC-manifest.md](https://github.com/kylemaps/veriseal/blob/main/SPEC-manifest.md): a conforming verifier needs only that document, the MCAP, and standard crypto libraries.

## Architecture

```
seal     ingest MCAP → hash every message → RFC 6962 Merkle tree →
         sign manifest (Ed25519) → anchor root (OpenTimestamps/Bitcoin) → *.seal.json

verify   recompute Merkle tree from MCAP → check signature → compare roots →
         INTACT or TAMPERED (locate modified/added/removed messages)
         informational: anchor status (pending / calendar-attested / invalid)
         optional: --pubkey to pin the signer's key; --check-bitcoin to check the
                   anchor against Bitcoin (verified / false); --require-anchor to enforce it

inspect  filter MCAP to time window → print chronological event timeline →
         export window as incident.mcap (openable in Foxglove Studio)
```

## Roadmap

- **v0.1:** seal / verify / inspect / pack on MCAP + OpenTimestamps anchor; independent web verifier; Foxglove panel
- **v0.2:** chain-of-custody log; RFC 3161 + Sigstore/Rekor option; ROS 2 SQLite (`.db3`) bag ingest; HTML report
- **v0.3:** web viewer; sealing daemon; pluggable transparency-log backend

## License

Apache-2.0 © Kyle Mapue
