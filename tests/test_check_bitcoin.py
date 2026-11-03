"""Checking an anchor against Bitcoin block headers (`verify --check-bitcoin`).

Hermetic: the block explorers are fakes that serve the two Esplora endpoints veriseal
uses, so every outcome (verified, false, unreachable, disagreeing, malformed) can be
produced without the network.
"""

from __future__ import annotations

import base64
import hashlib
import json
from functools import partial
from pathlib import Path

import pytest
from mcap.writer import Writer
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

import veriseal.anchor as anchor_mod
from veriseal.anchor import block_hash, check_bitcoin, fetch_block_header
from veriseal.canonical import canonical_json
from veriseal.seal import seal
from veriseal.verify import verify_seal

SOURCES = ("https://one.example/api", "https://two.example/api")

# Bitcoin's genesis block: a header everyone can check by hand.
GENESIS_HEADER = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd"
    "7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
)
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

BLOCK_TIME = 1_786_939_553  # 2026-08-17 04:05:53 UTC


# ── helpers ──────────────────────────────────────────────────────────────────


def _header(merkle_root: bytes, nonce: int = 0) -> bytes:
    """An 80-byte header whose Merkle root field is *merkle_root*."""
    return (
        (0x20000000).to_bytes(4, "little")
        + bytes(32)
        + merkle_root
        + BLOCK_TIME.to_bytes(4, "little")
        + (0x17030000).to_bytes(4, "little")
        + nonce.to_bytes(4, "little")
    )


def _ots(digest: bytes, *attestations) -> bytes:
    ts = Timestamp(digest)
    for att in attestations:
        ts.attestations.add(att)
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), ts).serialize(ctx)
    return ctx.getbytes()


def _explorers(blocks: dict[str, dict[int, bytes]]):
    """A fake `get` serving {source: {height: header}}; anything else is unreachable."""
    requests: list[str] = []

    def get(url: str) -> str:
        requests.append(url)
        for base, served in blocks.items():
            if not url.startswith(base + "/"):
                continue
            path = url[len(base) :]
            for height, header in served.items():
                if path == f"/block-height/{height}":
                    return block_hash(header)
                if path == f"/block/{block_hash(header)}/header":
                    return header.hex()
            raise OSError(f"HTTP 404 for {url}")
        raise OSError(f"cannot reach {url}")

    return get, requests


def _everywhere(blocks: dict[int, bytes]) -> dict[str, dict[int, bytes]]:
    return {base: blocks for base in SOURCES}


DIGEST = hashlib.sha256(b"a manifest").digest()
PROOF_900K = _ots(DIGEST, BitcoinBlockHeaderAttestation(900_000))


# ── block headers ────────────────────────────────────────────────────────────


def test_genesis_header_hashes_to_the_genesis_block() -> None:
    assert block_hash(GENESIS_HEADER) == GENESIS_HASH
    assert int.from_bytes(GENESIS_HEADER[68:72], "little") == 1_231_006_505  # 2009-01-03
    assert GENESIS_HEADER[36:68][::-1].hex() == (
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    )


def test_fetch_block_header_needs_every_source_to_agree() -> None:
    get, _ = _explorers(_everywhere({0: GENESIS_HEADER}))
    assert fetch_block_header(0, SOURCES, get) == (GENESIS_HEADER, GENESIS_HASH)


def test_fetch_block_header_rejects_a_header_that_does_not_hash_to_the_reported_block() -> None:
    def get(url: str) -> str:
        if "/block-height/" in url:
            return GENESIS_HASH
        return _header(DIGEST).hex()  # a different header

    with pytest.raises(anchor_mod.BlockSourceError, match="does not hash to"):
        fetch_block_header(0, SOURCES, get)


def test_a_malformed_block_hash_never_reaches_a_url() -> None:
    requests: list[str] = []

    def get(url: str) -> str:
        requests.append(url)
        return "../../somewhere-else"

    with pytest.raises(anchor_mod.BlockSourceError, match="malformed block hash"):
        fetch_block_header(0, SOURCES, get)
    assert requests == [f"{SOURCES[0]}/block-height/0"]


# ── check_bitcoin ────────────────────────────────────────────────────────────


def test_verified_when_every_source_returns_the_attested_block() -> None:
    header = _header(DIGEST)
    get, _ = _explorers(_everywhere({900_000: header}))
    result = check_bitcoin(DIGEST, PROOF_900K, SOURCES, get)
    assert result.status == "verified"
    assert result.height == 900_000
    assert result.block_hash == block_hash(header)
    assert result.block_time == BLOCK_TIME
    assert result.sources == SOURCES


def test_false_when_the_block_does_not_contain_the_proof() -> None:
    other = hashlib.sha256(b"some other block's transactions").digest()
    get, _ = _explorers(_everywhere({900_000: _header(other)}))
    result = check_bitcoin(DIGEST, PROOF_900K, SOURCES, get)
    assert result.status == "false"
    assert result.height == 900_000


def test_unchecked_when_a_source_is_unreachable() -> None:
    get, _ = _explorers({SOURCES[0]: {900_000: _header(DIGEST)}})
    result = check_bitcoin(DIGEST, PROOF_900K, SOURCES, get)
    assert result.status == "unchecked"
    assert SOURCES[1] in result.detail


def test_one_source_cannot_vouch_for_a_block_alone() -> None:
    """Source one serves a matching header, source two a different one: not verified."""
    get, _ = _explorers(
        {
            SOURCES[0]: {900_000: _header(DIGEST)},
            SOURCES[1]: {900_000: _header(hashlib.sha256(b"x").digest())},
        }
    )
    result = check_bitcoin(DIGEST, PROOF_900K, SOURCES, get)
    assert result.status == "unchecked"
    assert "disagree" in result.detail


def test_pending_proof_is_unchecked_without_going_online() -> None:
    get, requests = _explorers({})
    proof = _ots(DIGEST, PendingAttestation("https://a.pool.opentimestamps.org"))
    result = check_bitcoin(DIGEST, proof, SOURCES, get)
    assert result.status == "unchecked"
    assert requests == []


def test_proof_for_another_digest_is_rejected() -> None:
    get, requests = _explorers({})
    other = hashlib.sha256(b"not this manifest").digest()
    with pytest.raises(ValueError, match="commits to"):
        check_bitcoin(DIGEST, _ots(other, BitcoinBlockHeaderAttestation(900_000)), SOURCES, get)
    assert requests == []


def test_earliest_block_that_checks_out_wins() -> None:
    header = _header(DIGEST)
    get, _ = _explorers(_everywhere({900_001: header, 900_005: _header(DIGEST, nonce=5)}))
    proof = _ots(
        DIGEST, BitcoinBlockHeaderAttestation(900_005), BitcoinBlockHeaderAttestation(900_001)
    )
    assert check_bitcoin(DIGEST, proof, SOURCES, get).height == 900_001


def test_a_later_block_still_verifies_when_an_earlier_one_cannot_be_fetched() -> None:
    get, _ = _explorers(_everywhere({900_005: _header(DIGEST)}))
    proof = _ots(
        DIGEST, BitcoinBlockHeaderAttestation(900_001), BitcoinBlockHeaderAttestation(900_005)
    )
    result = check_bitcoin(DIGEST, proof, SOURCES, get)
    assert result.status == "verified"
    assert result.height == 900_005


# ── verify ───────────────────────────────────────────────────────────────────


def _write_mcap(path: Path) -> Path:
    with open(path, "wb") as f:
        writer = Writer(f)
        writer.start()
        schema_id = writer.register_schema(name="raw", encoding="", data=b"")
        ch = writer.register_channel(topic="/pose", message_encoding="", schema_id=schema_id)
        for i, t in enumerate((1_000_000, 2_000_000)):
            writer.add_message(channel_id=ch, log_time=t, data=bytes([i]), publish_time=t)
        writer.finish()
    return path


def _anchored_seal(tmp_path: Path, height: int) -> tuple[Path, Path, bytes]:
    """A sealed log whose anchor carries a Bitcoin attestation for block *height*."""
    mcap = _write_mcap(tmp_path / "log.mcap")
    seal_path = tmp_path / "log.seal.json"
    seal(mcap, new_key_path=tmp_path / "signer.key.pem", out_path=seal_path, do_anchor=False)
    manifest = json.loads(seal_path.read_bytes())
    payload = {k: v for k, v in manifest.items() if k != "anchor"}
    digest = hashlib.sha256(canonical_json(payload)).digest()
    manifest["anchor"] = {
        "type": "opentimestamps",
        "commitment_alg": "SHA-256",
        "commits": digest.hex(),
        "ots_base64": base64.b64encode(_ots(digest, BitcoinBlockHeaderAttestation(height))).decode(
            "ascii"
        ),
        "status": "confirmed",
        "bitcoin_block_height": height,
        "submitted_utc": "2026-08-17T03:53:13Z",
    }
    seal_path.write_bytes(canonical_json(manifest))
    return mcap, seal_path, digest


def _use_explorers(monkeypatch: pytest.MonkeyPatch, blocks: dict[str, dict[int, bytes]]) -> None:
    get, _ = _explorers(blocks)
    monkeypatch.setattr(
        anchor_mod, "check_bitcoin", partial(anchor_mod.check_bitcoin, sources=SOURCES, get=get)
    )


def _out(capsys: pytest.CaptureFixture[str]) -> str:
    return " ".join(capsys.readouterr().out.split())


def test_require_anchor_passes_once_checked_against_bitcoin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mcap, seal_path, digest = _anchored_seal(tmp_path, 900_000)
    _use_explorers(monkeypatch, _everywhere({900_000: _header(digest)}))
    assert verify_seal(mcap, seal_path, require_anchor=True) == 0
    out = _out(capsys)
    assert "Anchor: verified against Bitcoin, block #900000 (2026-08-17 04:05 UTC)" in out
    assert f"block hash {block_hash(_header(digest))}" in out
    assert "one.example and two.example" in out


def test_require_anchor_fails_when_the_block_contradicts_the_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mcap, seal_path, _ = _anchored_seal(tmp_path, 900_000)
    _use_explorers(monkeypatch, _everywhere({900_000: _header(bytes(32))}))
    assert verify_seal(mcap, seal_path, require_anchor=True) == 1
    out = _out(capsys)
    assert "Anchor: FALSE: Bitcoin block #900000 does not contain this proof" in out
    assert "--require-anchor not met" in out


def test_require_anchor_fails_when_bitcoin_cannot_be_reached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mcap, seal_path, _ = _anchored_seal(tmp_path, 900_000)
    _use_explorers(monkeypatch, {})
    assert verify_seal(mcap, seal_path, require_anchor=True) == 1
    out = _out(capsys)
    assert "Anchor: calendar-attested, Bitcoin block #900000 (could not check against" in out
    assert "Anchor: verified" not in out


def test_check_bitcoin_reports_without_changing_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Like every anchor result, a false attestation only fails under --require-anchor."""
    mcap, seal_path, _ = _anchored_seal(tmp_path, 900_000)
    _use_explorers(monkeypatch, _everywhere({900_000: _header(bytes(32))}))
    assert verify_seal(mcap, seal_path, check_bitcoin=True) == 0
    assert "Anchor: FALSE" in _out(capsys)


def test_verify_stays_offline_unless_asked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No flag, no request: the autouse network guard fails this test if one is made."""
    mcap, seal_path, _ = _anchored_seal(tmp_path, 900_000)
    assert verify_seal(mcap, seal_path) == 0
    assert "(not checked against Bitcoin; add --check-bitcoin)" in _out(capsys)


def test_cli_check_bitcoin_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from veriseal.cli import app

    mcap, seal_path, digest = _anchored_seal(tmp_path, 900_000)
    _use_explorers(monkeypatch, _everywhere({900_000: _header(digest)}))
    result = CliRunner().invoke(app, ["verify", str(mcap), str(seal_path), "--check-bitcoin"])
    assert result.exit_code == 0
    assert "verified against Bitcoin" in " ".join(result.stdout.split())


# ── pack ─────────────────────────────────────────────────────────────────────


def _report(tmp_path: Path, mcap: Path, seal_path: Path, check: bool) -> str:
    from veriseal.pack import build_pack

    result = build_pack(mcap, seal_path, tmp_path / "pack", check_bitcoin=check)
    return (result.out / "report.txt").read_text(encoding="utf-8")


def test_pack_report_records_a_verified_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mcap, seal_path, digest = _anchored_seal(tmp_path, 900_000)
    _use_explorers(monkeypatch, _everywhere({900_000: _header(digest)}))
    report = _report(tmp_path, mcap, seal_path, check=True)
    assert "Status: VERIFIED AGAINST BITCOIN, block #900000" in report
    assert f"Block hash: {block_hash(_header(digest))}" in report
    assert "Block time: 2026-08-17 04:05 UTC" in report
    assert "NOT CHECKED AGAINST BITCOIN" not in report


def test_pack_report_flags_a_false_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mcap, seal_path, _ = _anchored_seal(tmp_path, 900_000)
    _use_explorers(monkeypatch, _everywhere({900_000: _header(bytes(32))}))
    report = _report(tmp_path, mcap, seal_path, check=True)
    assert "Status: FALSE ATTESTATION, Bitcoin block #900000" in report
    assert "VERIFIED AGAINST BITCOIN" not in report


def test_pack_report_says_when_the_check_could_not_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mcap, seal_path, _ = _anchored_seal(tmp_path, 900_000)
    _use_explorers(monkeypatch, {})
    report = _report(tmp_path, mcap, seal_path, check=True)
    assert "NOT CHECKED AGAINST BITCOIN. veriseal tried" in report
    assert "cannot reach" in report


def test_pack_stays_offline_unless_asked(tmp_path: Path) -> None:
    mcap, seal_path, _ = _anchored_seal(tmp_path, 900_000)
    report = _report(tmp_path, mcap, seal_path, check=False)
    assert "report was built without comparing it with the block itself" in report
