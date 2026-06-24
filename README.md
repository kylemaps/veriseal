# veriseal

A CLI that takes a robot/autonomy log (MCAP) and produces a **tamper-evident, independently-verifiable incident package** — so a disinterested party can later prove "this log has not been altered since it was sealed, here is exactly what the machine decided in the incident window."

> **Status:** v0.1 scaffold — stubs only. Real implementation coming.

---

## Install

```bash
pip install veriseal
```

Or from source:

```bash
git clone https://github.com/kylemaps/veriseal.git
cd veriseal
pip install -e .
```

---

## Usage

```bash
# Seal a log
veriseal seal path/to/log.mcap --key my_key.pem --out log.seal.json

# Verify integrity
veriseal verify path/to/log.mcap log.seal.json

# Inspect an incident window
veriseal inspect path/to/log.mcap --from 2024-01-01T12:00:00Z --to 2024-01-01T12:05:00Z --topic /vehicle/pose
```

---

## Threat model

**What it PROVES:** the log has not been altered since it was sealed; the seal was made by a specific key at a specific, independently-anchored time; tampering can be detected and located. What it does NOT prove: that the log is a truthful record of reality at capture time. Integrity is not veracity. Neutrality comes from sealing as early as possible and anchoring the root in a public, append-only log.

---

## Architecture (v0.1)

```
seal     ingest MCAP → hash every message → build Merkle tree →
         sign root (Ed25519) → anchor root (OpenTimestamps/Bitcoin) → write *.seal.json

verify   recompute from MCAP + manifest → check signature + OTS proof →
         report INTACT or TAMPERED (locate first divergent message)

inspect  extract incident time-window → print chronological event/decision timeline →
         export window as new MCAP (open in Foxglove)
```

---

## Roadmap

- **v0.1:** seal / verify / inspect on MCAP + OpenTimestamps anchor
- **v0.2:** chain-of-custody log; RFC 3161 + Sigstore/Rekor option; ROS 2 bag ingest; HTML report
- **v0.3:** web viewer; sealing daemon; pluggable transparency-log backend

---

## License

Apache-2.0 © Kyle Mapue
