"""veriseal verify — recompute and check a sealed MCAP.

The verification logic lives in `run_verification()`, which returns a structured
`VerificationResult` with no I/O or presentation. `verify_seal()` (the CLI entry
point) and `veriseal.pack` both call it, so there is exactly one verification
code path — the CLI's Rich console output and the incident-pack report are two
renderings of the same result, never two computations.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)
from rich.console import Console

from veriseal.canonical import canonical_json
from veriseal.formats import iter_messages
from veriseal.mcap_io import file_digest
from veriseal.merkle import leaf_hash, merkle_root
from veriseal.signing import verify as ed25519_verify

console = Console()

# (topic, log_time) → Counter[leaf_hash_hex]
_Multiset = dict[tuple[str, int], Counter[str]]


def _build_multiset(entries: list[tuple[str, int, str]]) -> _Multiset:
    result: _Multiset = defaultdict(Counter)
    for topic, log_time, lh in entries:
        result[(topic, log_time)][lh] += 1
    return dict(result)


@dataclass
class AnchorResult:
    """Outcome of checking the manifest's embedded OpenTimestamps proof, if any."""

    present: bool = False
    commits_ok: bool | None = None
    status: str | None = None  # "pending" | "confirmed"
    block_height: int | None = None
    error: str | None = None


@dataclass
class VerificationResult:
    """Structured outcome of verifying an MCAP against a .seal.json manifest.

    Pure data: no console output. `ok` is the same INTACT/TAMPERED verdict the
    CLI exit code encodes (0 iff `ok and not anchor_required_but_failed`).
    """

    manifest: dict
    mcap_path: Path
    actual_sha256: str
    actual_size: int
    source_ok: bool
    sig_ok: bool
    pubkey_ok: bool
    pubkey_pinned: bool
    recomputed_root: str
    root_ok: bool
    modifications: list[tuple[str, int]] = field(default_factory=list)
    removals: list[tuple[str, int]] = field(default_factory=list)
    additions: list[tuple[str, int]] = field(default_factory=list)
    anchor: AnchorResult = field(default_factory=AnchorResult)

    @property
    def intact(self) -> bool:
        """Message-level integrity: the signed manifest is authentic and its
        leaves fold to the signed root. This is NOT the full verdict — it says
        nothing about whether the raw file on disk still matches (see `ok`)."""
        return self.sig_ok and self.root_ok

    @property
    def ok(self) -> bool:
        """The overall INTACT verdict, identical across CLI, pack, and web
        verifier: the manifest is authentic (`intact`), signed by the pinned key
        if one was given (`pubkey_ok`), AND the file is byte-for-byte unchanged
        since sealing (`source_ok`). A seal proves file integrity, so a file
        whose bytes differ from the sealed digest is TAMPERED even if the
        manifest itself verifies."""
        return self.intact and self.pubkey_ok and self.source_ok


def run_verification(
    mcap_path: Path,
    manifest: dict,
    pubkey_path: Path | None = None,
) -> VerificationResult:
    """Recompute and check *manifest* against *mcap_path*. Pure — no console output.

    Raises on I/O or parse errors (unreadable MCAP, unreadable --pubkey file);
    callers decide how to present those as CLI errors vs. pack failures.
    """
    actual_sha256, actual_size = file_digest(mcap_path)
    source_ok = (
        actual_sha256 == manifest["source"]["sha256"]
        and actual_size == manifest["source"]["size_bytes"]
    )

    # ── Signature check ───────────────────────────────────────────────────────
    pub_pem_str = manifest["signature"]["public_key"]
    try:
        payload_dict = {k: v for k, v in manifest.items() if k not in ("signature", "anchor")}
        signed_payload = canonical_json(payload_dict)
        sig_bytes = bytes.fromhex(manifest["signature"]["value"])
        sig_ok = ed25519_verify(pub_pem_str, signed_payload, sig_bytes)
    except Exception:
        sig_ok = False

    # ── Pubkey pin check ─────────────────────────────────────────────────────
    pubkey_pinned = pubkey_path is not None
    pubkey_ok = True
    if pubkey_path is not None:
        expected_key = load_pem_public_key(pubkey_path.read_bytes())
        manifest_key = load_pem_public_key(pub_pem_str.encode())
        raw_expected = expected_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        raw_manifest = manifest_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        pubkey_ok = raw_expected == raw_manifest

    # ── Recompute leaves from MCAP ────────────────────────────────────────────
    raw_messages = list(iter_messages(mcap_path))
    recomputed_entries = [
        (topic, log_time, leaf_hash(topic, log_time, payload).hex())
        for topic, log_time, payload in raw_messages
    ]
    manifest_entries = [
        (leaf["topic"], leaf["log_time"], leaf["leaf_hash"]) for leaf in manifest["leaves"]
    ]

    # ── Recompute Merkle root (same sort as seal) ─────────────────────────────
    # (log_time, topic, leaf_hash). Python sorts strings by Unicode code point;
    # the JS verifiers use `<` (UTF-16 code unit). Same as manifest.py: agrees on
    # the BMP, can diverge for astral-plane topics — keep this in lockstep.
    sorted_recomputed = sorted(recomputed_entries, key=lambda x: (x[1], x[0], x[2]))
    recomputed_hashes = [bytes.fromhex(lh) for _, _, lh in sorted_recomputed]
    recomputed_root = merkle_root(recomputed_hashes).hex()
    root_ok = recomputed_root == manifest["merkle"]["root"]

    # ── Tamper localisation via (topic, log_time) multisets ──────────────────
    manifest_ms = _build_multiset(manifest_entries)
    recomputed_ms = _build_multiset(recomputed_entries)

    all_keys = set(manifest_ms) | set(recomputed_ms)
    modifications: list[tuple[str, int]] = []
    removals: list[tuple[str, int]] = []
    additions: list[tuple[str, int]] = []

    for key in sorted(all_keys, key=lambda k: (k[1], k[0])):
        in_man = manifest_ms.get(key)
        in_rec = recomputed_ms.get(key)
        if in_man and in_rec:
            if in_man != in_rec:
                modifications.append(key)
        elif in_man:
            removals.append(key)
        else:
            additions.append(key)

    # ── Anchor check (informational) ──────────────────────────────────────────
    anchor_result = AnchorResult()
    anchor = manifest.get("anchor")
    if anchor and anchor.get("type") == "opentimestamps":
        anchor_result.present = True
        try:
            payload_for_anchor = {k: v for k, v in manifest.items() if k != "anchor"}
            expected_digest = hashlib.sha256(canonical_json(payload_for_anchor)).digest()

            if expected_digest.hex() != anchor.get("commits", ""):
                anchor_result.commits_ok = False
            else:
                anchor_result.commits_ok = True
                from veriseal import anchor as anchor_mod

                ots_bytes = base64.b64decode(anchor["ots_base64"])
                status, block_height = anchor_mod.verify_anchor(expected_digest, ots_bytes)
                anchor_result.status = status
                anchor_result.block_height = block_height
        except Exception as exc:
            anchor_result.error = str(exc)

    return VerificationResult(
        manifest=manifest,
        mcap_path=mcap_path,
        actual_sha256=actual_sha256,
        actual_size=actual_size,
        source_ok=source_ok,
        sig_ok=sig_ok,
        pubkey_ok=pubkey_ok,
        pubkey_pinned=pubkey_pinned,
        recomputed_root=recomputed_root,
        root_ok=root_ok,
        modifications=modifications,
        removals=removals,
        additions=additions,
        anchor=anchor_result,
    )


def verify_seal(
    mcap_path: Path,
    seal_path: Path,
    pubkey_path: Path | None = None,
    require_anchor: bool = False,
) -> int:
    """
    Verify *mcap_path* against *seal_path* and print a Rich report.

    Returns:
        0  — INTACT (signature valid AND Merkle root matches AND pubkey/anchor checks pass)
        1  — TAMPERED, key mismatch, or anchor required but absent/invalid
        2  — usage / parse error
    """
    try:
        manifest = json.loads(seal_path.read_bytes())
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] Cannot read manifest: {exc}")
        return 2

    try:
        result = run_verification(mcap_path, manifest, pubkey_path)
    except FileNotFoundError as exc:
        console.print(f"[bold red]ERROR:[/bold red] Cannot read MCAP: {exc}")
        return 2
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] {exc}")
        return 2

    # ── Rich output ───────────────────────────────────────────────────────────
    n = manifest["messages"]["count"]
    root_hex = manifest["merkle"]["root"]

    if result.ok:
        console.print(
            f"[bold green]INTACT[/bold green]: signature valid, "
            f"{n} messages, root {root_hex[:16]}..."
        )
        # Show the file-integrity check affirmatively too, so the source status
        # is ALWAYS reported (not only on failure) and INTACT visibly means the
        # bytes on disk match the sealed digest.
        console.print(
            f"  [green]Source file unchanged[/green] (SHA-256 {result.actual_sha256[:16]}...)"
        )
    else:
        console.print("[bold red]TAMPERED[/bold red]")
        if not result.pubkey_ok:
            console.print(
                "  [red]Signer key mismatch: manifest was not signed by the pinned key[/red]"
            )
        if not result.sig_ok:
            console.print("  [red]Signature INVALID: manifest may have been altered[/red]")
        if not result.source_ok:
            console.print(
                f"  [red]Source digest mismatch[/red]\n"
                f"    expected {manifest['source']['sha256'][:16]}...\n"
                f"    actual   {result.actual_sha256[:16]}..."
            )
        if not result.root_ok:
            console.print(
                f"  [red]Merkle root mismatch[/red]\n"
                f"    expected {manifest['merkle']['root'][:16]}...\n"
                f"    actual   {result.recomputed_root[:16]}..."
            )
        if result.modifications or result.removals or result.additions:
            if not result.sig_ok:
                console.print(
                    "  [dim](tamper localisation is untrusted: manifest signature invalid)[/dim]"
                )
            for topic, log_time in result.modifications:
                console.print(f"  [yellow]MODIFIED[/yellow]  topic={topic!r} log_time={log_time}")
            for topic, log_time in result.removals:
                console.print(f"  [yellow]REMOVED[/yellow]   topic={topic!r} log_time={log_time}")
            for topic, log_time in result.additions:
                console.print(f"  [yellow]ADDED[/yellow]     topic={topic!r} log_time={log_time}")

    # ── No-pubkey warning ─────────────────────────────────────────────────────
    if pubkey_path is None:
        console.print(
            "  [yellow]WARNING:[/yellow] no --pubkey: trusting the key embedded in the manifest; "
            "a tampered re-seal with a new key would still pass. "
            "Pin the signer's key for real assurance."
        )

    # ── Anchor report ─────────────────────────────────────────────────────────
    anchor_fail = False
    anchor = manifest.get("anchor")
    if require_anchor and (anchor is None or anchor.get("type") not in ("opentimestamps",)):
        console.print(
            "[bold red]Anchor: ABSENT[/bold red] "
            "(--require-anchor set but no valid anchor in manifest)"
        )
        anchor_fail = True
    elif result.anchor.present:
        a = result.anchor
        if a.error is not None:
            console.print(f"  [bold red]Anchor: ERROR[/bold red]: {a.error}")
            if require_anchor:
                anchor_fail = True
        elif a.commits_ok is False:
            console.print(
                "  [bold red]Anchor: INVALID[/bold red] (proof does not commit to this manifest)"
            )
            if require_anchor:
                anchor_fail = True
        elif a.status == "confirmed":
            console.print(
                f"  [bold green]Anchor: confirmed[/bold green] (Bitcoin block #{a.block_height})"
            )
        else:
            console.print("  [cyan]Anchor: pending[/cyan] (not yet Bitcoin-confirmed)")

    return 0 if (result.ok and not anchor_fail) else 1
