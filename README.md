# veriseal

For incident investigators and safety teams who need to prove a robot/autonomy log wasn't altered after the fact.

A CLI that seals a robot/autonomy log (MCAP) with an Ed25519 signature and a Bitcoin timestamp (OpenTimestamps), producing a `.seal.json` manifest. A disinterested party can later prove "this log matches a seal made by key K, anchored at time T", but only if the verifier **pins the signer's key** (`--pubkey`). Without key pinning, a tampered re-seal with a new key still passes.

> **Status:** early v0.1, solo project: seal/verify/inspect work end-to-end, but APIs may change. Adversarial feedback welcome: [open an issue](https://github.com/kylemaps/veriseal/issues).

![CI](https://github.com/kylemaps/veriseal/actions/workflows/ci.yml/badge.svg)

![demo](demo/demo.gif)

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

```bash
# Seal a log (generates a fresh key; submits Merkle root to OpenTimestamps by default)
veriseal seal log.mcap --out log.seal.json

# Seal without OpenTimestamps, fast, fully offline
veriseal seal log.mcap --no-anchor --out log.seal.json

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
```

### OpenTimestamps anchor

By default, `veriseal seal` submits the signed Merkle root to public Bitcoin calendar servers ([OpenTimestamps](https://opentimestamps.org)). The embedded proof starts as `status: "pending"` and becomes `"confirmed"` once a Bitcoin block includes the Merkle path (~1 hour later).

`veriseal verify` reports anchor status **informational**: the INTACT/TAMPERED verdict and exit code are unaffected by anchor state unless `--require-anchor` is set:

```
INTACT: signature valid, 198 messages, root 9bfe72f8a52c5ad5...
  Anchor: pending (not yet Bitcoin-confirmed)
```

Skip anchoring for offline workflows or CI:

```bash
veriseal seal log.mcap --no-anchor
```

Require a valid anchor (useful in audit pipelines):

```bash
veriseal verify log.mcap log.seal.json --pubkey signer.pub.pem --require-anchor
```

### ROS 1 rosbags

veriseal seals MCAP; it doesn't read ROS 1 `.bag` directly. Convert first, then seal: see [docs/ros1.md](docs/ros1.md).

### Independent web verifier

The whole point of the seal is that *someone who trusts neither the operator nor veriseal* can still check it. [`web/verify.html`](web/verify.html) is a single self-contained page that does exactly that: drop an `.mcap` and its `.seal.json`, and it recomputes the Ed25519 signature, the RFC 6962 Merkle root, and the SHA-256 file digest **entirely in the browser** (WebCrypto, no network calls, nothing uploaded). Open the file locally, or host it anywhere static. An insurer or investigator can verify a sealed log on their own machine without installing anything.

---

## Threat model

**What it PROVES:** this log matches a seal made by key K at time T. "Independently verifiable" requires two things: (1) the verifier knows and pins the signer's public key (`--pubkey`); (2) the anchor is trusted. Without `--pubkey`, a tampered re-seal with a fresh key still passes. Without the anchor, time claims rest only on the sealer's assertion.

**What it does NOT prove:** that the log is a truthful record of physical reality at capture time. A seal cannot un-fabricate data captured falsely. Integrity ≠ veracity.

**Where neutrality actually comes from:** sealing as early as possible (ideally at/near capture) and anchoring the root in a public append-only log, so no single party (including the custodian) can backdate or alter it. The closer the seal is to capture and the more public the anchor, the more "neutral" the evidence.

> **Content vs bytes:** `verify` checks message **content**, not file bytes: a losslessly re-muxed MCAP with identical messages still verifies INTACT. `source.sha256` is the separate strict byte-level check, reported alongside the Merkle result.

---

## How it works

1. **Hash**: each MCAP message is domain-separated and SHA-256 hashed: `SHA-256(b"\x00" + b"veriseal-leaf-v1\x00" + len(topic) + topic + log_time + payload)`.
2. **Merkle tree**: leaves sorted by `(log_time, topic, leaf_hash)` and combined with the [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) binary Merkle Tree Hash algorithm. Any single-byte change flips the root; the leaf diff pinpoints the affected (topic, log_time) group.
3. **Sign**: the manifest (root + all leaves + metadata) is serialized as canonical JSON and signed with Ed25519. The signer's public key is embedded in the manifest.
4. **Anchor**: the signed manifest is SHA-256 hashed and submitted to [OpenTimestamps](https://opentimestamps.org) public calendars. A Bitcoin block later commits to it, providing a trustless timestamp no single party (including the sealer) can backdate.

The `.seal.json` format is fully documented in **[SPEC-manifest.md](SPEC-manifest.md)**: a conforming verifier needs only that document, the MCAP, and standard crypto libraries.

---

## Architecture

```
seal     ingest MCAP → hash every message → RFC 6962 Merkle tree →
         sign manifest (Ed25519) → anchor root (OpenTimestamps/Bitcoin) → *.seal.json

verify   recompute Merkle tree from MCAP → check signature → compare roots →
         INTACT or TAMPERED (locate modified/added/removed messages)
         informational: anchor status (pending / confirmed / invalid)
         optional: --pubkey to pin the signer's key, --require-anchor to enforce anchor

inspect  filter MCAP to time window → print chronological event timeline →
         export window as incident.mcap (openable in Foxglove Studio)
```

---

## Running the demo

```bash
cd demo
python make_sample.py          # generates sample.mcap (synthetic AV log, ~198 msgs)
bash demo.sh                   # seal → verify INTACT → tamper → verify TAMPERED → inspect
```

To record `demo.gif` using [VHS](https://github.com/charmbracelet/vhs) (requires Docker):

```bash
docker build -f Dockerfile.vhs -t veriseal-vhs .
docker run --rm -v "$(pwd):/vhs" veriseal-vhs demo/demo.tape
```

---

## Part of a pipeline

veriseal seals telemetry; **[Rating Bridge](https://github.com/kylemaps/rating-bridge)** turns
a sealed log into a signed, underwriting-grade exposure report; **[Agent Loss Record](https://github.com/kylemaps/agent-loss-record)**
is the open standard incidents get recorded into. Each stands alone; together they're the
path from "here's a robot log" to "here's what it costs to insure."

## Roadmap

- **v0.1:** seal / verify / inspect on MCAP + OpenTimestamps anchor
- **v0.2:** chain-of-custody log; RFC 3161 + Sigstore/Rekor option; ROS 2 bag ingest; HTML report
- **v0.3:** web viewer; sealing daemon; pluggable transparency-log backend

---

## License

Apache-2.0 © Kyle Mapue
