# veriseal

For incident investigators and safety teams who need to prove a robot/autonomy log wasn't altered after the fact.

A CLI that seals a robot/autonomy log (MCAP) with an Ed25519 signature and an OpenTimestamps proof anchored in Bitcoin, producing a `.seal.json` manifest. A disinterested party can later prove "this log matches a seal made by key K", but only if the verifier **pins the signer's key** (`--pubkey`). Without key pinning, a tampered re-seal with a new key still passes. The seal also carries an OpenTimestamps proof that it existed no later than a given Bitcoin block; that holds once the proof is checked against Bitcoin, which veriseal doesn't do yet.

> **Status:** early v0.1, solo project: seal/verify/inspect/pack work end-to-end, but APIs may change. Adversarial feedback welcome: [open an issue](https://github.com/kylemaps/veriseal/issues).

![CI](https://github.com/kylemaps/veriseal/actions/workflows/ci.yml/badge.svg)

![demo](https://raw.githubusercontent.com/kylemaps/veriseal/main/demo/demo.gif)

---

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

---

## Quickstart

No log handy? In a clone of this repo, `python demo/make_sample.py log.mcap` writes the synthetic 198-message log the outputs below come from. `tests/test_readme_quickstart.py` runs this block as written, so the outputs stay accurate.

```bash
# Generate a reusable signer key (and its public key, to share for pinning)
veriseal keygen --out signer.key.pem --pub signer.pub.pem

# Seal a log (submits Merkle root to OpenTimestamps by default)
veriseal seal log.mcap --key signer.key.pem --out log.seal.json

# Or seal fully offline, without OpenTimestamps (same key)
veriseal seal log.mcap --key signer.key.pem --no-anchor --out log.seal.json

# Verify integrity (WARNING: without --pubkey the embedded key is trusted unconditionally)
veriseal verify log.mcap log.seal.json
# INTACT: signature valid, 198 messages, root 9bfe72f8a52c5ad5...
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

### OpenTimestamps anchor

By default, `veriseal seal` submits the signed manifest's digest to public [OpenTimestamps](https://opentimestamps.org) calendar servers. The embedded proof starts as `status: "pending"`. Once a Bitcoin block includes the calendar's commitment (typically a few hours later), `veriseal anchor upgrade log.seal.json` fetches the Bitcoin attestation from the calendars and records it in place (`status` -> `confirmed`, block height recorded). The anchor is excluded from the signed payload, so this never invalidates the signature.

**Trust model.** An OpenTimestamps proof is a chain of SHA-256 steps from the manifest's digest to the Merkle root in one Bitcoin block header. Checked against that header, it shows the manifest existed no later than that block, without trusting the calendars, the sealer or veriseal. Unchecked, it is only the calendar's claim. veriseal does not check it against Bitcoin yet, so `verify` reports the anchor as **calendar-attested, not checked against Bitcoin**. Until it can, check the proof (`veriseal pack` writes it out as `anchor.ots`) with the OpenTimestamps client and a Bitcoin node.

`veriseal verify` reports the anchor for information only. It doesn't change the INTACT/TAMPERED verdict or the exit code unless `--require-anchor` is set:

```
INTACT: signature valid, 198 messages, root 9bfe72f8a52c5ad5...
  Source file unchanged (SHA-256 79d83f92510271e5...)
  Anchor: calendar-attested, Bitcoin block #812345 (not checked against Bitcoin)
```

Skip anchoring for offline workflows or CI:

```bash
veriseal seal log.mcap --key signer.key.pem --no-anchor
```

`--require-anchor` fails unless the anchor has been checked against Bitcoin. veriseal can't do that check yet, so for now it fails for every anchor, pending or calendar-attested, rather than accept one it hasn't verified:

```bash
veriseal verify log.mcap log.seal.json --pubkey signer.pub.pem --require-anchor
```

### Auto-sealing every recording

Add one step to your ROS 2 recording workflow so every log is sealed the moment it finishes: generate a signer key once with `veriseal keygen`, then run `veriseal seal` on the recorder's exit (a post-record one-liner, or an `OnProcessExit` handler in a launch file). Copy-paste snippets: [docs/auto-seal.md](https://github.com/kylemaps/veriseal/blob/main/docs/auto-seal.md).

### ROS 1 rosbags and other formats

veriseal hashes `(topic, log_time, payload)` message triples, which aren't MCAP-specific. It seals **MCAP** natively and **ROS 1 `.bag`** directly via the optional `rosbags` reader (pure Python, no ROS install): `pip install "veriseal[ros1]"`, then `veriseal seal drive.bag ...`. `seal`, `verify`, and `pack` work the same across formats (the manifest records `source.format`); `inspect`'s window export is MCAP-only. See [docs/ros1.md](https://github.com/kylemaps/veriseal/blob/main/docs/ros1.md).

### Independent web verifier

The whole point of the seal is that *someone who trusts neither the operator nor veriseal* can still check it. [`web/verify.html`](https://github.com/kylemaps/veriseal/blob/main/web/verify.html) is a single self-contained page that does exactly that: drop an `.mcap` and its `.seal.json`, and it recomputes the Ed25519 signature, the RFC 6962 Merkle root, and the SHA-256 file digest **entirely in the browser** (WebCrypto, no network calls, nothing uploaded). To reach a green **VERIFIED** it also asks you to paste the signer's expected public key (obtained out-of-band) and pins it; without a pinned key the result stays amber, since the embedded key alone proves nothing about who signed. Open the file locally, or host it anywhere static. An insurer or investigator can verify a sealed log on their own machine without installing anything.

### Foxglove panel

[`veriseal-panel/`](https://github.com/kylemaps/veriseal/tree/main/veriseal-panel) is a [Foxglove Studio](https://foxglove.dev) extension that checks a seal **in-workflow**, without leaving your visualization. Open a log, load its `.seal.json`, and a live badge reports **SIGNER VERIFIED** (when you pin the signer's key), **AUTHENTICITY NOT ESTABLISHED** (signature + Merkle valid but no key pinned), or **MANIFEST INVALID** — verifying the signature and Merkle root against the signer's Ed25519 key. (Whole-file byte integrity stays the CLI/web-verifier's job, since a panel only sees decoded messages, never the raw file bytes.) The panel's verification core is the same logic as the web verifier and is tested against the Python reference.

### Incident-evidence pack

`veriseal pack` builds a portable evidence package to keep alongside an already-sealed log (the log itself is not copied in, so keep the two together): the manifest, a plain-English verification report, the OpenTimestamps proof (if any, with its honest pending/calendar-attested state), an offline copy of the [web verifier](https://github.com/kylemaps/veriseal/blob/main/web/verify.html), and a cover sheet explaining what the seal proves — and doesn't. It re-runs the exact same verification `veriseal verify` performs (one code path, two renderings), so the report can never drift from what the CLI would say.

```bash
veriseal pack log.mcap log.seal.json --out incident-pack/        # a directory
veriseal pack log.mcap log.seal.json --out incident-pack --zip    # a single .zip to hand off
```

The pack is evidence infrastructure, not a compliance certificate: it supports disclosure obligations under things like the EU Product Liability Directive (2024/2853) or AI Act Article 73 by making a log's integrity independently checkable, but it never asserts the log's *contents* are true, and it never claims to satisfy any regulation on its own.

---

## Threat model

**What it PROVES:** this log matches a seal made by key K at time T. "Independently verifiable" requires two things: (1) the verifier knows and pins the signer's public key (`--pubkey`); (2) the anchor has been checked against Bitcoin. Without `--pubkey`, a tampered re-seal with a fresh key still passes. Without a checked anchor, time claims rest only on the sealer's (or the calendar's) assertion.

**What it does NOT prove:** that the log is a truthful record of physical reality at capture time. A seal cannot un-fabricate data captured falsely. Integrity ≠ veracity.

**Where neutrality actually comes from:** sealing as early as possible (ideally at/near capture) and anchoring the root in a public append-only log, so no single party (including the custodian) can backdate or alter it. The closer the seal is to capture and the more public the anchor, the more "neutral" the evidence.

> **Content vs bytes:** the Merkle root covers message **content**: each message's topic, log time and payload bytes. `source.sha256` is a separate byte-level check of the whole file, and both must pass for INTACT. A losslessly re-muxed MCAP with identical messages therefore verifies **TAMPERED**, but with only a source-digest mismatch: no Merkle mismatch and no MODIFIED/ADDED/REMOVED lines, which tells you the messages themselves are unchanged.

---

## How it works

1. **Hash**: each MCAP message is domain-separated and SHA-256 hashed: `SHA-256(b"\x00" + b"veriseal-leaf-v1\x00" + len(topic) + topic + log_time + payload)`.
2. **Merkle tree**: leaves sorted by `(log_time, topic, leaf_hash)` and combined with the [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) binary Merkle Tree Hash algorithm. Changing any message's topic, log time or payload changes the root, and the leaf diff pinpoints the affected (topic, log_time) group. Edits outside message content (schemas, attachments, metadata, file layout) leave the root unchanged; only the whole-file SHA-256 (`source.sha256`) catches those, and `verify` checks it too.
3. **Sign**: the manifest (root + all leaves + metadata) is serialized as canonical JSON and signed with Ed25519. The signer's public key is embedded in the manifest.
4. **Anchor**: the signed manifest is SHA-256 hashed and submitted to [OpenTimestamps](https://opentimestamps.org) public calendars. A Bitcoin block later commits to it. Checked against that block's header, this shows the manifest existed no later than the block, with no trust in the calendars or the sealer; veriseal doesn't perform that check yet (see the trust model under [OpenTimestamps anchor](#opentimestamps-anchor)).

The `.seal.json` format is fully documented in **[SPEC-manifest.md](https://github.com/kylemaps/veriseal/blob/main/SPEC-manifest.md)**: a conforming verifier needs only that document, the MCAP, and standard crypto libraries.

---

## Architecture

```
seal     ingest MCAP → hash every message → RFC 6962 Merkle tree →
         sign manifest (Ed25519) → anchor root (OpenTimestamps/Bitcoin) → *.seal.json

verify   recompute Merkle tree from MCAP → check signature → compare roots →
         INTACT or TAMPERED (locate modified/added/removed messages)
         informational: anchor status (pending / calendar-attested / invalid)
         optional: --pubkey to pin the signer's key, --require-anchor to enforce anchor

inspect  filter MCAP to time window → print chronological event timeline →
         export window as incident.mcap (openable in Foxglove Studio)
```

---

## Roadmap

- **v0.1:** seal / verify / inspect / pack on MCAP + OpenTimestamps anchor; independent web verifier; Foxglove panel
- **v0.2:** chain-of-custody log; RFC 3161 + Sigstore/Rekor option; ROS 2 bag ingest; HTML report
- **v0.3:** web viewer; sealing daemon; pluggable transparency-log backend

---

## License

Apache-2.0 © Kyle Mapue
