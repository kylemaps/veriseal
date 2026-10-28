"""Forged-anchor detection using the REAL verify_anchor (no mock).

A doctored anchor whose `commits` field is edited to match the manifest but whose
`ots_base64` proof actually binds a DIFFERENT digest must be rejected under
--require-anchor. The commits string alone is attacker-controlled text; the proof
bytes are what bind a digest, and verify_anchor cross-checks them. A proof that binds
the right digest to a made-up Bitcoin attestation must not pass either: without a check
against the Bitcoin block header it is only a claim.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from mcap.writer import Writer
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from veriseal.canonical import canonical_json
from veriseal.seal import seal
from veriseal.verify import verify_seal


def _confirmed_ots(digest: bytes, height: int) -> bytes:
    ts = Timestamp(digest)
    ts.attestations.add(BitcoinBlockHeaderAttestation(height))
    dtf = DetachedTimestampFile(OpSHA256(), ts)
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes()


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


_MSGS = [("/pose", 1_000_000, b"\x01"), ("/pose", 2_000_000, b"\x02")]


def test_forged_anchor_commits_but_proof_binds_other_digest(tmp_path: Path) -> None:
    mcap = _write_mcap(tmp_path / "m.mcap", _MSGS)
    seal_path = tmp_path / "m.seal.json"
    seal(mcap, new_key_path=mcap.with_suffix(".key.pem"), out_path=seal_path, do_anchor=False)
    manifest = json.loads(seal_path.read_bytes())

    # The correct commit digest (what an honest anchor would commit to).
    payload = {k: v for k, v in manifest.items() if k != "anchor"}
    correct_digest = hashlib.sha256(canonical_json(payload)).digest()

    # Forge: set commits = the correct hex (passes the cheap string check), but
    # build the OTS proof over a DIFFERENT digest, so verify_anchor's real
    # deserialization finds file_digest != correct_digest and raises.
    other_digest = hashlib.sha256(b"not the manifest").digest()
    assert other_digest != correct_digest
    forged_ots = _confirmed_ots(other_digest, 820000)

    manifest["anchor"] = {
        "type": "opentimestamps",
        "commitment_alg": "SHA-256",
        "commits": correct_digest.hex(),  # doctored to match the manifest
        "ots_base64": base64.b64encode(forged_ots).decode("ascii"),
        "status": "confirmed",
        "bitcoin_block_height": 820000,
        "submitted_utc": "2026-01-01T00:00:00Z",
    }
    forged_seal = tmp_path / "forged.seal.json"
    forged_seal.write_bytes(canonical_json(manifest))

    # Under --require-anchor the forged proof must fail (exit 1), via the real
    # verify_anchor raising on the digest mismatch.
    assert verify_seal(mcap, forged_seal, require_anchor=True) == 1


def _seal_with_made_up_attestation(tmp_path: Path) -> tuple[Path, Path]:
    """A proof that binds the right digest to a Bitcoin attestation no block ever made."""
    mcap = _write_mcap(tmp_path / "h.mcap", _MSGS)
    seal_path = tmp_path / "h.seal.json"
    seal(mcap, new_key_path=mcap.with_suffix(".key.pem"), out_path=seal_path, do_anchor=False)
    manifest = json.loads(seal_path.read_bytes())

    payload = {k: v for k, v in manifest.items() if k != "anchor"}
    digest = hashlib.sha256(canonical_json(payload)).digest()
    made_up_ots = _confirmed_ots(digest, 820001)

    manifest["anchor"] = {
        "type": "opentimestamps",
        "commitment_alg": "SHA-256",
        "commits": digest.hex(),
        "ots_base64": base64.b64encode(made_up_ots).decode("ascii"),
        "status": "confirmed",
        "bitcoin_block_height": 820001,
        "submitted_utc": "2026-01-01T00:00:00Z",
    }
    made_up_seal = tmp_path / "made_up.seal.json"
    made_up_seal.write_bytes(canonical_json(manifest))
    return mcap, made_up_seal


def test_unchecked_bitcoin_attestation_fails_require_anchor(tmp_path: Path) -> None:
    """Nothing here checks the attestation against Bitcoin, so it must not satisfy the flag."""
    mcap, made_up_seal = _seal_with_made_up_attestation(tmp_path)
    assert verify_seal(mcap, made_up_seal, require_anchor=True) == 1


def test_unchecked_attestation_is_reported_as_calendar_attested(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mcap, made_up_seal = _seal_with_made_up_attestation(tmp_path)
    assert verify_seal(mcap, made_up_seal) == 0  # anchors stay informational by default
    out = " ".join(capsys.readouterr().out.split())
    assert "Anchor: calendar-attested, Bitcoin block #820001 (not checked against Bitcoin)" in out
    assert "confirmed" not in out.lower()


def test_pack_report_does_not_vouch_for_unchecked_attestation(tmp_path: Path) -> None:
    from veriseal.pack import build_pack

    mcap, made_up_seal = _seal_with_made_up_attestation(tmp_path)
    result = build_pack(mcap, made_up_seal, tmp_path / "pack")
    report = (result.out / "report.txt").read_text(encoding="utf-8")
    assert "NOT CHECKED AGAINST BITCOIN" in report
    assert "independent, public timestamp" not in report
