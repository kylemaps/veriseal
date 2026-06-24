"""seal command implementation."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from veriseal.canonical import canonical_json
from veriseal.manifest import build_manifest
from veriseal.mcap_io import file_digest, iter_messages
from veriseal.signing import generate_key, load_private_pem, save_private_pem

console = Console()


def seal(path: Path, key_path: Path | None, out_path: Path | None) -> None:
    """Read *path*, compute Merkle tree, sign, write manifest to *out_path*."""
    if out_path is None:
        out_path = path.with_suffix("").with_suffix(".seal.json")
        if out_path == path:
            out_path = path.parent / (path.name + ".seal.json")

    if key_path is None:
        key = generate_key()
        key_path = path.with_suffix("").with_suffix(".key.pem")
        if key_path == path:
            key_path = path.parent / (path.name + ".key.pem")
        save_private_pem(key, key_path)
        console.print(
            f"[bold yellow]WARNING:[/bold yellow] Generated new private key -> "
            f"[cyan]{key_path}[/cyan]\n"
            "Keep this file safe and secret. Without it you cannot re-seal this log."
        )
    else:
        key = load_private_pem(key_path)

    sha256_hex, size = file_digest(path)
    messages = list(iter_messages(path))
    manifest = build_manifest(path, messages, sha256_hex, size, key)
    out_path.write_bytes(canonical_json(manifest))

    console.print(
        Panel(
            f"[bold]Messages:[/bold]    {manifest['messages']['count']}\n"
            f"[bold]Merkle root:[/bold] {manifest['merkle']['root']}\n"
            f"[bold]Manifest:[/bold]    {out_path}",
            title="[green]Seal complete[/green]",
            expand=False,
        )
    )
