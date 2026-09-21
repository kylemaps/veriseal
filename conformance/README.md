# veriseal conformance vectors

Test vectors for anyone writing an independent verifier against
[SPEC-manifest.md](../SPEC-manifest.md). A conforming implementation needs only that
document, these files, and standard SHA-256 / Ed25519 libraries — not this codebase.

Every vector here is exercised in CI by
[`tests/test_conformance_vectors.py`](../tests/test_conformance_vectors.py), so the
expected results below cannot silently drift from what the tool actually does.

## Vectors

| Files | Format | Expected result |
|---|---|---|
| `sample_ros1.mcap` + `sample_ros1.seal.json` | MCAP | **INTACT** — all checks pass |
| `sample_ros1.tampered.mcap` + `sample_ros1.seal.json` | MCAP | **TAMPERED** — see below |
| `sample.bag` + `sample.bag.seal.json` + `sample.bag.pub.pem` | ROS 1 bag | **INTACT**, including a signer-key pin |

### `sample_ros1.mcap` — the INTACT vector

10 messages across `/pose` and `/status`.

```
source.sha256   f8e502bce22c7130ccd70aaadef1e651a72296b93a7be9ace6c665e9993d1651
source.size     4563 bytes
merkle.root     9a75174f04a956e947427887468f63381b3914cafbc3f83b052620a2bc04a581
```

This manifest is also the cross-core anchor for the whole project: it is byte-identical
to `veriseal-panel/test/fixtures/sample.seal.json`, and its root is the constant both
JavaScript verifier cores are pinned to. If your implementation reproduces
`9a75174f…` from these leaves, your canonical JSON, leaf preimage, leaf hash, sort
order, and RFC 6962 tree all agree with the reference.

Two properties worth knowing, because they are deliberate:

- `tool_version` is `0.1.1.dev0` and `source.format` is **absent**. This manifest
  predates the `source.format` field, so it doubles as a backward-compatibility
  vector: a verifier MUST accept a `veriseal-manifest-v1` manifest with no
  `source.format` key.
- `anchor` is `null`. Anchoring is not required for a valid seal.

### `sample_ros1.tampered.mcap` — the TAMPERED vector

The same log with one message altered. Verified against the *unmodified*
`sample_ros1.seal.json`, a conforming verifier MUST report all three of:

```
source digest mismatch   actual a7b48a5f36b30967…  (expected f8e502bc…)
merkle root mismatch     actual 8095f522ea7eb07d…  (expected 9a75174f…)
modified message         topic='/status'  log_time=1700000000200000000
```

The third line is the localisation requirement in SPEC §7 step 8: it is not enough to
say "something changed", a conforming verifier identifies *which* message.

### `sample.bag` — the ROS 1 and key-pinning vector

The same 10 messages in a ROS 1 bag, proving the leaf triples
`(topic, log_time, payload)` are container-agnostic (SPEC §2).

```
source.format   rosbag1
source.sha256   cbe8c5d07b6b9f60…
merkle.root     0ea10129c602fb8f16edd2692117cbb9d52381c916224b758785e3b16be9208b
```

Unlike the MCAP vector, this one ships `sample.bag.pub.pem` so you can exercise
**signer-key pinning** (SPEC §8) — the check that separates "signed by somebody" from
"signed by this key". Without a pinned key a verifier MUST NOT present the result as
fully verified.

**This vector is reproducible.** It was sealed with a published, deterministic test
key and a fixed timestamp:

```python
SEED = bytes(range(32))  # 00 01 02 … 1f
key = Ed25519PrivateKey.from_private_bytes(SEED)
time = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
```

> **The seed is a test constant, published on purpose** — the same convention as the
> Ed25519 test vectors in RFC 8032. It exists so anyone can regenerate this vector and
> get byte-identical output. It is not a key, it protects nothing, and it must never be
> used to seal anything real. The private key for the MCAP vector is deliberately **not**
> in this repository.

## Checking your implementation

```bash
veriseal verify conformance/sample_ros1.mcap          conformance/sample_ros1.seal.json      # INTACT
veriseal verify conformance/sample_ros1.tampered.mcap conformance/sample_ros1.seal.json      # TAMPERED
veriseal verify conformance/sample.bag conformance/sample.bag.seal.json \
    --pubkey conformance/sample.bag.pub.pem                                                  # INTACT, pinned
```

Reading the ROS 1 vector needs the optional reader: `pip install "veriseal[ros1]"`.

## What these vectors do not cover

Stated plainly, so nobody mistakes passing them for full conformance:

- **Anchors.** Every vector here has `anchor: null`. OpenTimestamps proof verification
  (SPEC §6, §7 step 9) has no vector yet.
- **Scale.** Ten messages. The multi-level Merkle guard lives separately in
  `veriseal-panel/test/fixtures/large-leaves.json` (1,237 leaves) and is not wired in
  here.
- **Astral-plane topic names.** SPEC §1 warns that Python (code point) and JavaScript
  (UTF-16 code unit) sort orders can disagree above U+FFFF. No vector pins that
  behaviour; topics are expected to be ASCII.
- **Unknown schema versions.** There is no vector for how a verifier should treat a
  `schema_version` it does not recognise, because the spec does not yet say.
