# veriseal streaming seal specification, draft v0

> Schema identifiers: `"veriseal-start-v0"`, `"veriseal-head-v0"`, `"veriseal-receipt-v0"`

**Status: draft.** The streaming seal is experimental. Every identifier here ends in `-v0`, and the format can change without notice until a `-v1` is published. The whole-file seal in [SPEC-manifest.md](SPEC-manifest.md) is stable and does not depend on this document.

This document specifies the records a recorder writes while a log is being recorded, and how a verifier checks a finished log against them. A conforming verifier needs this document, [SPEC-manifest.md](SPEC-manifest.md) sections 1 to 3, the log, and standard SHA-256 and Ed25519 libraries.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Overview

A recording is cut into **epochs**, fixed spans of log time. When an epoch ends, the recorder signs a **head**: the number of messages so far, a Merkle root over them, and the hash of the previous head. Each epoch is signed with its own key, which is erased as soon as the head is saved. The public halves of all those keys are fixed in advance by a signed **start record**.

A **witness** is a service off the robot. It stores each head it is sent and returns a signed **receipt**.

What this gives, and what it does not:

- A head that was signed before the recorder was taken over cannot be re-signed afterwards, because its key no longer exists. A changed log then fails verification, or shows a visible interruption.
- A head that has reached a witness cannot be withdrawn or replaced.
- Nothing here shows that the recorded data is true. A recorder that was already compromised signs whatever it is given.

## 2. Shared definitions

- **Canonical JSON**: as in SPEC-manifest.md section 1. Records MUST NOT contain floating-point numbers.
- **Leaf hash**: as in SPEC-manifest.md section 2, over `(topic, log_time_ns, payload)`.
- **Merkle root**: RFC 6962 section 2.1 over a list of 32-byte leaf hashes, as in SPEC-manifest.md section 3. The root of the empty list is `SHA-256("")`.
- **Signature**: Ed25519. Signatures are carried as standard base64 with padding. Hashes and public keys are carried as lowercase hexadecimal.
- **Domain prefix**: every signed or derived value is prefixed with an ASCII label followed by one zero byte, written here as `"label" || 0x00`.
- Times are integers in nanoseconds on the clock the recorder stamps `log_time` with.

## 3. Epoch keys

A recorder prepares one signing key per epoch before recording starts.

```
seed[0]      = 32 random bytes
private[i]   = Ed25519 private key with seed bytes SHA-256("veriseal-epoch-key-v0" || 0x00 || seed[i])
seed[i + 1]  = SHA-256("veriseal-epoch-seed-v0" || 0x00 || seed[i])
```

Epoch `i` is signed with `private[i]`. After the head for epoch `i` is saved, the recorder MUST overwrite `seed[i]` with `seed[i + 1]` and keep no copy of `private[i]`. A seed gives every later key and no earlier one.

The **key commitment** fixes every public key:

```
commit_leaf[i]  = SHA-256("veriseal-epoch-commit-v0" || 0x00 || public[i])     (public[i]: 32 raw bytes)
key_commitment  = hex(MerkleRoot(commit_leaf[0], commit_leaf[1], ...))
```

The list of public keys travels with the seal. A recording that outlasts its keys MUST start a new segment (section 7).

## 4. Start record

A start record ties a task to an identity key and to one chain of epoch keys.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `"veriseal-start-v0"` |
| `task_id` | string | The task this recording belongs to |
| `executor` | string | Who carries the task out |
| `segment` | integer | 0 for the first stretch of recording, then 1, 2, ... after each restart |
| `epoch_ns` | integer | Epoch length in nanoseconds, above zero |
| `block_hash` | string | A value that did not exist before the task was assigned, such as the hash of the block that assigned it |
| `key_commitment` | string | Section 3 |
| `alg` | string | Signature algorithm of the identity key. Only `"Ed25519"` is defined |
| `kid` | string | `hex(SHA-256(identity public key, 32 raw bytes))` |
| `signature` | string | Identity key's signature over `"veriseal-start-v0" || 0x00 || canonical_json(record without "signature")` |

```
start_hash = hex(SHA-256(canonical_json(record including "signature")))
```

The start hash MUST be published somewhere the recorder cannot later change, such as a ledger or a witness, before recording starts. Until it is, whoever controls the recorder can replace the whole key chain.

## 5. Heads

### 5.1 Epochs and order

`origin_ns` is the log time of the first message the recorder seals, unless the recorder is given another origin. A message with log time `t` belongs to epoch `floor((t - origin_ns) / epoch_ns)`.

Each epoch's messages join the tree sorted by `(log_time_ns, leaf_hash)`, the leaf hash compared as bytes. The tree therefore depends only on which messages the log holds, and not on the order a recorder wrote them or a reader returns them. Rewriting the file in another order or with other compression keeps the seal valid.

A message that reaches the recorder after its own epoch has been signed is **late**. It joins the next head to be signed, in the same sorted order as that head's own messages, and that head names its leaf hash in `late`. A message stamped before `origin_ns` is late in epoch 0.

A recorder SHOULD wait long enough before signing an epoch that late messages are rare. A head MUST be written for every epoch, including one with no messages, so a gap in the epoch numbers always means a head was removed.

### 5.2 Head record

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `"veriseal-head-v0"` |
| `task_id` | string | As in the start record |
| `start` | string | The start hash of this segment |
| `epoch` | integer | 0, 1, 2, ... with no gaps |
| `origin_ns` | integer | Section 5.1. The same in every head of a segment. `null` only while no message has been sealed |
| `epoch_ns` | integer | As in the start record |
| `tree_size` | integer | Messages sealed up to the end of this epoch |
| `root` | string | Merkle root over those messages' leaf hashes, in tree order |
| `late` | array of strings | Leaf hashes of the late messages this head adds, sorted by `(log_time_ns, leaf_hash)` |
| `prev_head` | string | Head hash of the previous head. 64 zeros in the first head |
| `final` | boolean | `true` only in the last head of a recording that ended properly |
| `signature` | string | Epoch key's signature over `"veriseal-head-v0" || 0x00 || canonical_json(head without "signature")` |

```
head_hash = hex(SHA-256(canonical_json(head including "signature")))
```

A recorder MUST save a head durably before it erases that epoch's key.

## 6. Verifying one segment

Given the log's messages, the heads in order, the public keys and the start hash:

1. For every head, in order, check that:
   - `schema` is known, and `epoch` equals the head's position, counted from 0
   - `task_id` and `start` are the expected ones
   - `prev_head` is the hash of the head before it
   - `origin_ns` and `epoch_ns` are the same as in the first head
   - `tree_size` does not go down
   - `late` holds no more entries than the head adds to `tree_size`
   - the signature checks against `public[epoch]`
   - no head follows one with `final: true`
2. Assign every message to an epoch. A message whose leaf hash is in some head's `late` list belongs to that head's epoch, and each listed entry is used once. Every other message belongs to the epoch its log time falls in.
3. For a late message in the head of epoch `e`, with `begins = origin_ns + e * epoch_ns`:
   - `log_time_ns` MUST be below `begins`. Otherwise the message was on time and the head mislabels it.
   - `begins - log_time_ns` MUST NOT exceed the verifier's limit (section 6.1).
4. A message whose epoch has no head is **unprotected**. In the last segment this is a failure. In an earlier, interrupted segment it is counted and reported.
5. Rebuild the tree epoch by epoch, each epoch's messages in the order of section 5.1. After each epoch, the size and root MUST equal that head's `tree_size` and `root`.
6. The last segment MUST end with a head that has `final: true`.

### 6.1 Verdicts

A verifier reports one of three outcomes for a segment:

| Verdict | Meaning |
|---|---|
| **OK** | Every check passes |
| **LATE** | Every check passes except the limit in step 3: the log matches every head, but some messages were sealed longer after their log times than the limit allows |
| **FAILED** | Anything else |

The limit exists because a late entry is signed with a later epoch's key. Without a limit, someone who takes over the recorder could add messages stamped with times from before the takeover, and a replay in time order would show them as part of the protected past. The reference verifier's default limit is 100 ms.

A recorder that paused for longer than it waits before signing produces LATE as well. A verifier MUST report how many messages were late and by how much, so that the two cases can be weighed. LATE MUST NOT be reported as OK.

## 7. Segments and tasks

A recording can stop and restart, for example after a power loss. Each stretch is a **segment** with its own start record, numbered from 0, and its own key chain. No secret has to survive a restart.

A task verifies when:

1. The start hashes published for the task match the segments submitted, in number and order.
2. Each start record has a known `schema` and `alg`, names the expected task and `block_hash`, carries its position as `segment`, has a `kid` that matches the identity key, has a `key_commitment` that matches the public keys supplied, and is signed by the identity key.
3. Each segment verifies as in section 6. Only the last needs a final head. An earlier segment without one is reported as **interrupted**, with the number of unprotected messages.
4. A segment with a final head is not followed by another.
5. Segments do not overlap in time, beyond the limit of section 6.1. The gap before each restart is reported.
6. No message is older than the task's assignment, when the verifier knows that time.
7. No message in a segment is older than the moment its start hash was published, when the verifier knows that time.

An interruption is not a failure, and it is not proof of honesty either. A verifier MUST report every interruption and its gap.

## 8. Witness

### 8.1 Receipt

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `"veriseal-receipt-v0"` |
| `hash` | string | The start hash or head hash received |
| `epoch` | integer or null | The head's epoch. `null` for a start record |
| `received_ns` | integer | The witness's clock when it accepted the record |
| `signature` | string | Witness key's signature over `"veriseal-receipt-v0" || 0x00 || canonical_json(receipt without "signature")` |

A witness MUST NOT return a receipt before the record is on durable storage.

### 8.2 Rules

- A start record is accepted when its `key_commitment` matches the public keys sent with it.
- A head is accepted when its start record is known and its signature checks against the committed key for its epoch.
- The witness keeps the first head it accepts for an epoch. A different head for the same epoch MUST be refused and kept as a **conflict**: two signed versions of one epoch are evidence of tampering.
- A head older than the newest one held MUST be refused, and so MUST any head after a final one.
- Sending a head again returns the same receipt.

Because each head carries the hash of the one before, a recorder only ever needs to send its newest head. After a lost link, one head covers the whole gap.

### 8.3 HTTP interface

The reference witness speaks JSON over HTTP. It has no authentication and belongs on a private network.

| Request | Body | Reply |
|---|---|---|
| `POST /start` | `{"record": start record, "public_keys": [hex, ...]}` | `200` and a receipt |
| `POST /heads` | a head | `200` and a receipt |
| `GET /heads/<start_hash>` | | `200` and the heads held for that start record, oldest first |

A refusal is `409` with `{"error": reason}`. A malformed request is `400`, an empty or oversized body `413`.

### 8.4 Checking a submission against a witness

Every head the witness holds for a task MUST appear, unchanged, among the heads submitted. A missing or different head is a failure.

## 9. Windows (informative)

Two intervals describe what someone who takes over the recorder at time `T` can still do. Both are measured back from `T`.

- **Change unnoticed.** With epoch keys: back to the end of the last epoch whose head was signed before `T`. This is at most one epoch plus the time the recorder waits before signing. With one long-lived key instead: back to the last head that reached a witness.
- **Remove.** Back to the last head that reached a witness before `T`, whichever kind of key is used. A removal shows as an interruption.

Before the start hash is published, both windows cover the whole recording. `bench/window.py` measures both for a given link and sending interval.

## 10. Files written by the reference recorder (informative)

`python -m veriseal.tail seal LOG --out-dir DIR` writes:

| File | Content |
|---|---|
| `start.json` | The start record, canonical JSON |
| `keys.json` | `{"identity": PEM public key, "public_keys": [hex, ...]}` |
| `heads.jsonl` | One head per line, canonical JSON |
| `leaves.bin` | The 32-byte leaf hashes in tree order. Lets a verifier name the first message that differs. A leaf hash can confirm a guess at a message's content, so handle this file with the same care as the log |
| `stats.json` | Counts and delays of the run. Not part of the seal |
| `deliveries.jsonl` | One line per head closed and per attempt to send one. Not part of the seal |

`python -m veriseal.tail verify LOG --out-dir DIR` exits `0` for OK, `2` for LATE and `1` for FAILED. It trusts the identity key and start record found in `DIR`. A real check takes both from where they were published.

## 11. Not yet specified

- A signed summary that ties all segments of a task and the log files' digests together. The code has a draft under `"veriseal-manifest-v2-draft"`.
- More than one witness, and how a verifier weighs them.
- Identity keys held in hardware, and other signature algorithms.
- Hiding message content from someone who holds only the leaf hashes.
