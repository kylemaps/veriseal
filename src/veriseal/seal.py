"""seal command implementation."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from veriseal.canonical import canonical_json
from veriseal.formats import detect_format, iter_messages
from veriseal.manifest import build_manifest
from veriseal.mcap_io import file_digest
from veriseal.signing import generate_key, load_private_pem, save_private_pem

console = Console()


# Extensions we recognise as the sealed-log container. Only the final one is
# stripped when deriving output names, so dotted stems are preserved.
_LOG_EXTENSIONS = (".mcap", ".bag")


def _derive_output(path: Path, new_ext: str) -> Path:
    """Return *path* with its final known log extension replaced by *new_ext*.

    Uses the full filename and strips ONLY the final recognised extension, so
    ``data.2026.mcap`` -> ``data.2026.seal.json`` (not ``data.seal.json``).
    ``Path.with_suffix`` would drop the ``.2026`` segment and let distinct inputs
    (``data.2026.mcap`` / ``data.2025.mcap``) collide onto one output.
    """
    name = path.name
    for ext in _LOG_EXTENSIONS:
        if name.lower().endswith(ext):
            name = name[: -len(ext)]
            break
    return path.parent / (name + new_ext)


def seal(
    path: Path,
    key_path: Path | None,
    out_path: Path | None,
    do_anchor: bool = True,
) -> None:
    """Read *path*, compute Merkle tree, sign, write manifest to *out_path*."""
    if out_path is None:
        out_path = _derive_output(path, ".seal.json")

    if key_path is None:
        key = generate_key()
        key_path = _derive_output(path, ".key.pem")
        save_private_pem(key, key_path)
        console.print(
            f"[bold yellow]WARNING:[/bold yellow] Generated new private key -> "
            f"[cyan]{key_path}[/cyan]\n"
            "Keep this file safe and secret. Without it you cannot re-seal this log."
        )
    else:
        key = load_private_pem(key_path)

    sha256_hex, size = file_digest(path)
    source_format = detect_format(path)
    messages = list(iter_messages(path))
    manifest = build_manifest(path, messages, sha256_hex, size, key, source_format=source_format)

    if do_anchor:
        # anchor_digest = SHA-256(canonical_json(manifest WITHOUT "anchor"))
        # This commits to the full signed manifest (signature INCLUDED).
        payload_for_anchor = {k: v for k, v in manifest.items() if k != "anchor"}
        anchor_digest = hashlib.sha256(canonical_json(payload_for_anchor)).digest()
        try:
            from veriseal import anchor as anchor_mod

            ots_bytes = anchor_mod.submit(anchor_digest)
            manifest["anchor"] = {
                "type": "opentimestamps",
                "commitment_alg": "SHA-256",
                "commits": anchor_digest.hex(),
                "ots_base64": base64.b64encode(ots_bytes).decode("ascii"),
                "status": "pending",
                "submitted_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        except Exception as exc:
            console.print(
                f"[bold yellow]WARNING:[/bold yellow] OpenTimestamps anchor failed "
                f"(network unavailable?): anchor stays null. {exc}"
            )
            # manifest["anchor"] already = None from build_manifest

    out_path.write_bytes(canonical_json(manifest))

    anchor_status = ""
    if manifest.get("anchor"):
        anchor_status = "\n[bold]Anchor:[/bold]      pending (OTS submitted)"

    console.print(
        Panel(
            f"[bold]Messages:[/bold]    {manifest['messages']['count']}\n"
            f"[bold]Merkle root:[/bold] {manifest['merkle']['root']}\n"
            f"[bold]Manifest:[/bold]    {out_path}" + anchor_status,
            title="[green]Seal complete[/green]",
            expand=False,
        )
    )
