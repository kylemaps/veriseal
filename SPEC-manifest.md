# veriseal Manifest Specification — v1

> Schema version identifier: `"veriseal-manifest-v1"`

This document specifies the `.seal.json` manifest format produced by `veriseal seal` and consumed by `veriseal verify`. A conforming verifier needs only this document, the source MCAP, and standard SHA-256 / Ed25519 libraries — it does not need the `veriseal` codebase.

---

## 1. Canonical JSON encoding

All JSON serialization in this spec uses **canonical JSON** with the following normative rules:

- Object keys sorted lexicographically (`sort_keys=True`)
- No insignificant whitespace (`separators=(",", ":")`)
- Non-ASCII characters encoded as-is, not escaped (`ensure_ascii=False`)
- NaN and Infinity are forbidden (`allow_nan=False`)
- Output encoded as UTF-8

In Python:

```python
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
    "utf-8"
)
```

> **Note:** This is NOT RFC 8785 (JCS). JCS requires Unicode escape sequences for certain code points and has additional constraints not present here.

> **No floating-point numbers.** The signed payload MUST contain only integers, never floats. Python and JavaScript serialize floats differently (e.g. `1.0` vs `1`, and they disagree on precision/exponent formatting), which would make the canonical bytes — and thus the signature — diverge between a Python and a browser verifier. veriseal's schema is all-integer (nanosecond times, byte sizes, counts); `veriseal seal` rejects any float in the payload rather than emit non-portable canonical bytes.

> **String ordering.** Object keys and leaf sort keys are ordered by Unicode **code point** (Python's default string comparison). A conforming verifier that compares strings by UTF-16 code unit (JavaScript's default `<`) agrees for the Basic Multilingual Plane, but can disagree for astral-plane characters (above U+FFFF). Topic strings are expected to be ASCII; do not rely on a particular ordering of astral-plane topic names.

---

## 2. Leaf preimage and leaf hash

For each MCAP message, the leaf preimage is:

```
preimage = b"veriseal-leaf-v1\x00"
         + uint32_big_endian(len(topic_utf8))
         + topic_utf8
         + uint64_big_endian(log_time_ns)
         + payload_bytes
```

where:
- `topic_utf8` is the MCAP topic string encoded as UTF-8
- `log_time_ns` is the MCAP `log_time` field (nanoseconds since Unix epoch, unsigned 64-bit big-endian)
- `payload_bytes` is the raw MCAP message data bytes

The **leaf hash** is (RFC 6962 domain separator `0x00` for leaf nodes):

```
leaf_hash = SHA-256( b"\x00" + preimage )
```

---

## 3. Merkle tree (RFC 6962 §2.1)

Leaves are sorted ascending by `(log_time_ns, topic_utf8, leaf_hash_hex)` before tree construction. This ordering is normative and recorded in `merkle.ordering`.

The **Merkle Tree Hash (MTH)** is computed recursively:

```
MTH([])     = SHA-256(b"")
MTH([h])    = h                    ← single leaf: root equals the leaf hash (already hashed)
MTH(D[n])   = SHA-256( b"\x01" + MTH(D[:k]) + MTH(D[k:]) )
```

where `k` is the largest power of two strictly less than `n`:

```python
k = 1 << ((n - 1).bit_length() - 1)
```

`b"\x01"` is the RFC 6962 domain separator for internal nodes.

> **Note:** Input leaves are **already hashed** (the `0x00`-prefixed leaf hashes from §2). `MTH([h])` returns `h` directly without double-hashing.

---

## 4. Signed payload

The Ed25519 signature covers **canonical JSON of the manifest with `"signature"` and `"anchor"` keys removed**:

```python
signed_payload = canonical_json(
    {k: v for k, v in manifest.items() if k not in ("signature", "anchor")}
)
```

This commits to: `schema_version`, `tool_version`, `created_utc`, `source`, `messages`, `hash_alg`, `merkle` (scheme, root, ordering), and all `leaves`.

---

## 5. Full manifest schema

```jsonc
{
  // ── Identity ────────────────────────────────────────────────────────────────
  "schema_version": "veriseal-manifest-v1",   // literal — identifies this spec
  "tool_version": "0.1.1",                     // semver of the sealing tool

  "created_utc": "2026-06-24T04:44:08Z",      // ISO 8601, UTC, second precision, Z suffix

  // ── Source file ─────────────────────────────────────────────────────────────
  "source": {
    "filename": "log.mcap",                   // basename of the sealed file
    "format": "mcap",                         // "mcap" | "rosbag1" — container the leaves came from
    "sha256": "<64 lower-case hex chars>",    // SHA-256 of raw file bytes
    "size_bytes": 123456                      // byte length of the file (integer)
  },

  // ── Message summary ─────────────────────────────────────────────────────────
  "messages": {
    "count": 42,                              // total message count (integer)
    "log_time_min": 1000000,                  // minimum log_time_ns (integer)
    "log_time_max": 9000000                   // maximum log_time_ns (integer)
  },

  "hash_alg": "SHA-256",                      // hash algorithm used for leaves and Merkle

  // ── Merkle tree ─────────────────────────────────────────────────────────────
  "merkle": {
    "scheme": "RFC6962-SHA256",               // identifies the tree construction
    "root": "<64 lower-case hex chars>",      // MTH of all leaves (see §3)
    "ordering": "log_time,topic,leaf_hash asc" // normative leaf sort key
  },

  // ── Leaf index ──────────────────────────────────────────────────────────────
  "leaves": [
    {
      "index": 0,                             // 0-based position in sorted leaf order
      "topic": "/pose",                       // MCAP topic string
      "log_time": 1000000,                    // MCAP log_time (nanoseconds, integer)
      "leaf_hash": "<64 lower-case hex chars>" // SHA-256 leaf hash (see §2)
    }
    // … one object per message, sorted by (log_time, topic, leaf_hash) asc
  ],

  // ── Signature ───────────────────────────────────────────────────────────────
  "signature": {
    "alg": "Ed25519",                         // signature algorithm
    "public_key": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n",
    "value": "<128 lower-case hex chars>"     // 64-byte Ed25519 signature over signed_payload
  },

  // ── Anchor — null if --no-anchor (see §6) ───────────────────────────────────
  "anchor": null
}
```

---

## 6. Anchor block (OpenTimestamps)

When `--anchor` is used (the default), `"anchor"` is replaced with:

```jsonc
{
  "type": "opentimestamps",
  "commitment_alg": "SHA-256",

  // anchor_digest = SHA-256( canonical_json(manifest WITHOUT "anchor" key) )
  // This commits to the entire signed manifest, including the "signature" field.
  "commits": "<64 lower-case hex chars>",

  // base64-encoded DetachedTimestampFile bytes (OTS binary wire format)
  "ots_base64": "<base64 string>",

  // "pending" → "confirmed" once a Bitcoin block includes the Merkle path
  "status": "pending",

  "submitted_utc": "2026-06-24T04:44:08Z",   // ISO 8601 UTC time of OTS submission

  // Present ONLY when status == "confirmed" (added by `veriseal anchor upgrade`):
  // the Bitcoin block height whose header attests the committed digest.
  "bitcoin_block_height": 812345
}
```

When `status` is `"pending"`, the `bitcoin_block_height` key is absent. `veriseal anchor upgrade` asks the OpenTimestamps calendars whether the proof has been included in a Bitcoin block; if so, it rewrites `ots_base64` with the upgraded proof, sets `status` to `"confirmed"`, and records `bitcoin_block_height`. It sets `"confirmed"` only when the upgraded proof actually carries a `BitcoinBlockHeaderAttestation`.

**Excluded from signed payload.** The `"anchor"` key is removed before computing the Ed25519 signed payload (§4), so the anchor can be updated (e.g., upgraded from `pending` to `confirmed`) without invalidating the signature.

**Informational in verify.** `veriseal verify` reports anchor status separately after the INTACT/TAMPERED verdict; anchor state does not change the exit code.

---

## 7. Independent verification algorithm

A verifier without the `veriseal` library can verify a sealed manifest as follows:

1. **Parse** `seal.json` as JSON.
2. **Source check (byte-level):** compute `SHA-256(raw_mcap_bytes)` and `len(raw_mcap_bytes)`. Compare against `source.sha256` and `source.size_bytes`. Failure here means the file changed at the byte level (re-mux, rewrite, etc.).
3. **Reconstruct leaves:** for each MCAP message, compute the leaf preimage and leaf hash per §2.
4. **Sort:** sort the recomputed leaves by `(log_time_ns, topic_utf8, leaf_hash_hex)` ascending.
5. **Recompute MTH:** apply the RFC 6962 MTH function per §3 over the sorted leaf hashes.
6. **Merkle check:** recomputed root must equal `merkle.root`.
7. **Signature check:** build `manifest_without_signature_and_anchor` (remove `"signature"` and `"anchor"` keys), serialize as canonical JSON (§1), verify the Ed25519 signature `signature.value` using `signature.public_key` over that payload.
8. **Tamper localisation:** diff the recomputed leaf multiset against the manifest `leaves` array to identify modified/added/removed messages.
9. **Anchor (informational):** recompute `SHA-256(canonical_json(manifest WITHOUT "anchor"))` and compare against `anchor.commits`. Decode `anchor.ots_base64` as a `DetachedTimestampFile` and verify the OTS proof per the [OpenTimestamps specification](https://opentimestamps.org).

### 7.1 Overall verdict (normative)

A seal proves the source file is byte-for-byte unchanged since sealing. The single **INTACT** verdict therefore requires **all** of:

- the **source check** (step 2) passes — the file's bytes match `source.sha256`/`size_bytes`;
- the **Merkle check** (step 6) passes;
- the **signature check** (step 7) passes;
- and, when the verifier was given an expected signer key out-of-band, that key matches the manifest's key (see §8).

If any of these fails, the verdict is **TAMPERED**. This is the same verdict on every surface: the `veriseal verify` exit code (`0` = INTACT), the incident-pack report, the standalone web verifier, and (for the checks it can compute) the Foxglove panel. The panel is the one exception in *scope*, not in semantics: it never sees the raw file bytes, so it verifies only signature + Merkle root and explicitly labels its pass state "manifest authentic — raw file not checked in-panel," directing the reader to `veriseal verify` or the web verifier for byte integrity.

> **Note:** steps 2–7 are independent *checks*, and `veriseal verify` reports each one's PASS/FAIL separately so a re-muxed MCAP with byte-identical message payloads is visibly distinguishable (it fails step 2 but passes steps 5–7). They are independent in *diagnosis* but not in *verdict*: any failing check makes the overall verdict TAMPERED.

---

## 8. Signer-key pinning (trust anchoring)

The signature check (step 7) proves only that the manifest was signed by *whoever holds the private key named in the manifest itself* — an attacker who tampers with a log can re-hash it and re-sign with **their own** freshly generated key, and step 7 alone will still pass. Authenticity therefore requires **pinning** the signer's key: comparing the manifest's `signature.public_key` against a key the verifier obtained **out-of-band** (a fingerprint the sealing party published or handed over separately), not merely trusting the embedded key.

- `veriseal verify --pubkey <key.pem>` pins the key: the raw 32-byte Ed25519 public key from the manifest must equal the raw key of the supplied PEM, or the verdict is TAMPERED.
- When **no** key is pinned, no authenticity to a real-world identity is established. Verifiers MUST NOT present an unpinned pass as fully verified: the CLI prints a warning, and the browser verifiers render a distinct amber/neutral state ("authenticity not independently established — pin the signer's key"), never a green VERIFIED.
- The comparison is over the raw key bytes (SPKI/PEM encoding differences do not matter), matching `veriseal verify --pubkey`.
