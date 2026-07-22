"""The re-seal-with-attacker-key attack, and why key pinning is the only defense.

An attacker who can modify a log can also re-hash it and re-sign it with their
OWN freshly generated key. Verifying that tampered log against the attacker's own
new seal returns INTACT — the signature is self-consistent. This is not a bug;
it is the reason authenticity REQUIRES pinning the original signer's key
(out-of-band). These tests document the limitation and prove the pin closes it,
mirroring web/verify.html and the Foxglove panel (SPEC-manifest.md 8).
"""

from __future__ import annotations

import json
from pathlib import Path

from mcap.writer import Writer

from veriseal.seal import seal
from veriseal.verify import verify_seal


def _write_mcap(path: Path, messages: list[tuple[str, int, bytes]]) -> Path:
    topics = sorted({t for t, _, _ in messages})
    with open(path, "wb") as f:
        writer = Writer(f)
        writer.start()
        schema_id = writer.register_schema(name="raw", encoding="", data=b"")
        ch = {
            t: writer.register_channel(topic=t, message_encoding="", schema_id=schema_id)
            for t in topics
        }
        for topic, log_time, data in messages:
            writer.add_message(
                channel_id=ch[topic], log_time=log_time, data=data, publish_time=log_time
            )
        writer.finish()
    return path


_GENUINE = [("/pose", 1_000_000, b"\x01"), ("/pose", 2_000_000, b"\x02")]
_TAMPERED = [("/pose", 1_000_000, b"\xff"), ("/pose", 2_000_000, b"\x02")]


def test_reseal_with_attacker_key(tmp_path: Path) -> None:
    # 1. Genuine seal by the real signer (key1). Capture key1's public key.
    genuine = _write_mcap(tmp_path / "genuine.mcap", _GENUINE)
    genuine_seal = tmp_path / "genuine.seal.json"
    seal(genuine, key_path=None, out_path=genuine_seal, do_anchor=False)
    real_pub = tmp_path / "real.pub.pem"
    real_pub.write_text(json.loads(genuine_seal.read_bytes())["signature"]["public_key"])

    # 2. Attacker tampers the log and re-seals with a FRESH key (key2), producing
    #    a fully self-consistent seal signed by a key they control.
    tampered = _write_mcap(tmp_path / "tampered.mcap", _TAMPERED)
    attacker_seal = tmp_path / "tampered.seal.json"
    seal(tampered, key_path=None, out_path=attacker_seal, do_anchor=False)

    # The attacker's key MUST differ from the real signer's key.
    real_key = json.loads(genuine_seal.read_bytes())["signature"]["public_key"]
    attacker_key = json.loads(attacker_seal.read_bytes())["signature"]["public_key"]
    assert real_key != attacker_key

    # 3. Without pinning, the attacker's self-consistent seal verifies INTACT.
    #    This documents the limitation the pitch is honest about.
    assert verify_seal(tampered, attacker_seal) == 0

    # 4. Pinning the ORIGINAL signer's key catches it: the manifest was signed by
    #    a different (attacker) key -> exit 1.
    assert verify_seal(tampered, attacker_seal, pubkey_path=real_pub) == 1

    # 5. And the genuine log still passes when pinned to the real key.
    assert verify_seal(genuine, genuine_seal, pubkey_path=real_pub) == 0
