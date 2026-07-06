"""veriseal verify command — recompute and check a sealed MCAP."""

from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)
from rich.console import Console

from veriseal.canonical import canonical_json
from veriseal.mcap_io import file_digest, iter_messages
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


def verify_seal(
    mcap_path: Path,
    seal_path: Path,
    pubkey_path: Path | None = None,
    require_anchor: bool = False,
) -> int:
    """
    Verify *mcap_path* against *seal_path*.

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

    # ── Source file digest (gross check) ─────────────────────────────────────
    try:
        actual_sha256, actual_size = file_digest(mcap_path)
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] Cannot read MCAP: {exc}")
        return 2

    source_ok = (
        actual_sha256 == manifest["source"]["sha256"]
        and actual_size == manifest["source"]["size_bytes"]
    )

    # ── Signature check ───────────────────────────────────────────────────────
    try:
        payload_dict = {k: v for k, v in manifest.items() if k not in ("signature", "anchor")}
        signed_payload = canonical_json(payload_dict)
        pub_pem_str = manifest["signature"]["public_key"]
        sig_bytes = bytes.fromhex(manifest["signature"]["value"])
        sig_ok = ed25519_verify(pub_pem_str, signed_payload, sig_bytes)
    except Exception:
        sig_ok = False

    # ── Pubkey pin check ─────────────────────────────────────────────────────
    pubkey_ok = True
    if pubkey_path is not None:
        try:
            expected_key = load_pem_public_key(pubkey_path.read_bytes())
            manifest_key = load_pem_public_key(pub_pem_str.encode())
            raw_expected = expected_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            raw_manifest = manifest_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            pubkey_ok = raw_expected == raw_manifest
        except Exception as exc:
            console.print(f"[bold red]ERROR:[/bold red] Cannot load --pubkey: {exc}")
            return 2

    # ── Recompute leaves from MCAP ────────────────────────────────────────────
    try:
        raw_messages = list(iter_messages(mcap_path))
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] Cannot parse MCAP: {exc}")
        return 2

    recomputed_entries = [
        (topic, log_time, leaf_hash(topic, log_time, payload).hex())
        for topic, log_time, payload in raw_messages
    ]
    manifest_entries = [
        (leaf["topic"], leaf["log_time"], leaf["leaf_hash"])
        for leaf in manifest["leaves"]
    ]

    # ── Recompute Merkle root (same sort as seal) ─────────────────────────────
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

    intact = sig_ok and root_ok
    overall_ok = intact and pubkey_ok

    # ── Rich output ───────────────────────────────────────────────────────────
    n = manifest["messages"]["count"]
    root_hex = manifest["merkle"]["root"]

    if overall_ok:
        console.print(
            f"[bold green]INTACT[/bold green]: signature valid, "
            f"{n} messages, root {root_hex[:16]}..."
        )
    else:
        console.print("[bold red]TAMPERED[/bold red]")
        if not pubkey_ok:
            console.print(
                "  [red]Signer key mismatch: manifest was not signed by the pinned key[/red]"
            )
        if not sig_ok:
            console.print("  [red]Signature INVALID: manifest may have been altered[/red]")
        if not source_ok:
            console.print(
                f"  [red]Source digest mismatch[/red]\n"
                f"    expected {manifest['source']['sha256'][:16]}...\n"
                f"    actual   {actual_sha256[:16]}..."
            )
        if not root_ok:
            console.print(
                f"  [red]Merkle root mismatch[/red]\n"
                f"    expected {manifest['merkle']['root'][:16]}...\n"
                f"    actual   {recomputed_root[:16]}..."
            )
        if modifications or removals or additions:
            if not sig_ok:
                console.print(
                    "  [dim](tamper localisation is untrusted: manifest signature invalid)[/dim]"
                )
            for topic, log_time in modifications:
                console.print(f"  [yellow]MODIFIED[/yellow]  topic={topic!r} log_time={log_time}")
            for topic, log_time in removals:
                console.print(f"  [yellow]REMOVED[/yellow]   topic={topic!r} log_time={log_time}")
            for topic, log_time in additions:
                console.print(f"  [yellow]ADDED[/yellow]     topic={topic!r} log_time={log_time}")

    # ── No-pubkey warning ─────────────────────────────────────────────────────
    if pubkey_path is None:
        console.print(
            "  [yellow]WARNING:[/yellow] no --pubkey: trusting the key embedded in the manifest; "
            "a tampered re-seal with a new key would still pass. "
            "Pin the signer's key for real assurance."
        )

    # ── Anchor check ─────────────────────────────────────────────────────────
    anchor_fail = False
    anchor = manifest.get("anchor")
    if require_anchor and (anchor is None or anchor.get("type") not in ("opentimestamps",)):
        console.print(
            "[bold red]Anchor: ABSENT[/bold red] "
            "(--require-anchor set but no valid anchor in manifest)"
        )
        anchor_fail = True
    elif anchor and anchor.get("type") == "opentimestamps":
        anchor_valid = _check_anchor(manifest, anchor)
        if require_anchor and not anchor_valid:
            anchor_fail = True

    return 0 if (overall_ok and not anchor_fail) else 1


def _check_anchor(manifest: dict, anchor: dict) -> bool:
    """
    Verify the anchor and print status.

    Returns True if the anchor commits to the correct manifest digest and the OTS
    proof is parseable (pending or confirmed).  Returns False if commits mismatch
    or the proof cannot be verified.
    """
    try:
        payload_for_anchor = {k: v for k, v in manifest.items() if k != "anchor"}
        expected_digest = hashlib.sha256(canonical_json(payload_for_anchor)).digest()

        if expected_digest.hex() != anchor.get("commits", ""):
            console.print(
                "  [bold red]Anchor: INVALID[/bold red] (proof does not commit to this manifest)"
            )
            return False

        from veriseal import anchor as anchor_mod

        ots_bytes = base64.b64decode(anchor["ots_base64"])
        status, block_height = anchor_mod.verify_anchor(expected_digest, ots_bytes)

        if status == "confirmed":
            console.print(
                f"  [bold green]Anchor: confirmed[/bold green] (Bitcoin block #{block_height})"
            )
        else:
            console.print("  [cyan]Anchor: pending[/cyan] (not yet Bitcoin-confirmed)")

        return True

    except Exception as exc:
        console.print(f"  [bold red]Anchor: ERROR[/bold red]: {exc}")
        return False
