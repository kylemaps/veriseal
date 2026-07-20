"""veriseal CLI."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

app = typer.Typer(
    name="veriseal",
    help="Tamper-evident incident packages for robot/autonomy logs.",
    no_args_is_help=True,
)
anchor_app = typer.Typer(
    help="Inspect and maintain a manifest's OpenTimestamps anchor.",
    no_args_is_help=True,
)
app.add_typer(anchor_app, name="anchor")
console = Console()

@app.command()
def seal(
    path: Path = typer.Argument(..., help="Path to the .mcap file to seal."),
    key: Path | None = typer.Option(None, "--key", help="Path to Ed25519 private key (PEM)."),
    out: Path | None = typer.Option(
        None, "--out", help="Output path for the .seal.json manifest."
    ),
    anchor: bool = typer.Option(
        True, "--anchor/--no-anchor", help="Submit Merkle root to OpenTimestamps calendars."
    ),
) -> None:
    """Hash every message, build a Merkle tree, sign, and write manifest."""
    from veriseal.seal import seal as do_seal

    do_seal(path, key, out, do_anchor=anchor)


@app.command()
def verify(
    path: Path = typer.Argument(..., help="Path to the .mcap file to verify."),
    seal_json: Path = typer.Argument(
        ..., help="Path to the .seal.json manifest.", metavar="PATH.seal.json"
    ),
    pubkey: Path | None = typer.Option(
        None,
        "--pubkey",
        help=(
            "Expected Ed25519 public key (PEM). "
            "If given, FAIL if the manifest was not signed by this exact key. "
            "Without this flag, the key embedded in the manifest is trusted unconditionally."
        ),
    ),
    require_anchor: bool = typer.Option(
        False,
        "--require-anchor",
        help=(
            "FAIL if the manifest has no anchor, if the anchor does not commit to "
            "the recomputed digest, or if the OTS proof cannot be verified."
        ),
    ),
) -> None:
    """Recompute hashes, validate signature, report INTACT or TAMPERED (with location)."""
    from veriseal.verify import verify_seal

    raise typer.Exit(
        code=verify_seal(path, seal_json, pubkey_path=pubkey, require_anchor=require_anchor)
    )


@app.command()
def pack(
    path: Path = typer.Argument(..., help="Path to the sealed .mcap file."),
    seal_json: Path = typer.Argument(
        ..., help="Path to the .seal.json manifest.", metavar="PATH.seal.json"
    ),
    out: Path = typer.Option(
        ...,
        "--out",
        "-o",
        help="Output path for the incident-evidence bundle (dir, or .zip with --zip).",
    ),
    zip_: bool = typer.Option(
        False, "--zip", help="Write a single .zip archive instead of a directory."
    ),
    pubkey: Path | None = typer.Option(
        None,
        "--pubkey",
        help="Pin the expected signer's Ed25519 public key (PEM) when building the report.",
    ),
) -> None:
    """Build a portable, independently re-verifiable incident-evidence bundle."""
    from veriseal.pack import build_pack

    result = build_pack(path, seal_json, out, pubkey_path=pubkey, as_zip=zip_)
    if result.ok:
        console.print(f"[bold green]Pack written[/bold green]: {result.out}  (INTACT)")
    else:
        console.print(
            f"[bold yellow]Pack written[/bold yellow]: {result.out}  "
            "([bold red]verification FAILED[/bold red] — see report.txt)"
        )
    raise typer.Exit(code=0 if result.ok else 1)


@app.command()
def inspect(
    path: Path = typer.Argument(..., help="Path to the .mcap file to inspect."),
    from_time: str = typer.Option(..., "--from", help="Window start: ns-since-epoch or ISO-8601."),
    to_time: str = typer.Option(..., "--to", help="Window end: ns-since-epoch or ISO-8601."),
    topic: str | None = typer.Option(None, "--topic", help="Filter to a single topic."),
    out: Path | None = typer.Option(None, "--out", help="Output path for the incident.mcap."),
) -> None:
    """Print chronological timeline for the window; export Foxglove-openable incident.mcap."""
    from veriseal.inspect import inspect_mcap, parse_time

    try:
        from_ns = parse_time(from_time)
        to_ns = parse_time(to_time)
    except ValueError as exc:
        console.print(f"[bold red]ERROR:[/bold red] {exc}")
        raise typer.Exit(code=2)
    raise typer.Exit(code=inspect_mcap(path, from_ns, to_ns, topic, out))


@anchor_app.command("upgrade")
def anchor_upgrade(
    seal_json: Path = typer.Argument(
        ..., help="Path to the .seal.json manifest to upgrade in place.", metavar="PATH.seal.json"
    ),
) -> None:
    """Check whether a pending OpenTimestamps anchor is now Bitcoin-confirmed.

    Asks the public calendars; if a Bitcoin block now includes the proof, the
    manifest's anchor block is updated in place (status -> confirmed, block height
    recorded). The anchor is excluded from the signed payload, so this never
    invalidates the signature.
    """
    import json

    from veriseal.anchor import upgrade_manifest
    from veriseal.canonical import canonical_json

    try:
        manifest = json.loads(seal_json.read_bytes())
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] cannot read manifest: {exc}")
        raise typer.Exit(code=2)

    try:
        status, height, changed = upgrade_manifest(manifest)
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] upgrade failed: {exc}")
        raise typer.Exit(code=2)

    if status == "none":
        console.print(
            "No OpenTimestamps anchor in this manifest (sealed with --no-anchor). "
            "Nothing to upgrade."
        )
        raise typer.Exit(code=0)
    if status == "mismatch":
        console.print(
            "[bold red]Anchor does not commit to this manifest[/bold red] "
            "(the manifest was altered, or this is the wrong proof). Not upgrading."
        )
        raise typer.Exit(code=1)

    if changed:
        seal_json.write_bytes(canonical_json(manifest))

    if status == "confirmed":
        console.print(
            f"[bold green]Anchor confirmed[/bold green] in Bitcoin block #{height}. "
            + ("Manifest updated." if changed else "Manifest already recorded this.")
        )
    else:
        suffix = " Proof refreshed." if changed else ""
        console.print(
            "[cyan]Anchor still pending[/cyan] (not yet in a Bitcoin block; "
            "confirmation typically takes a few hours). Try again later." + suffix
        )
    raise typer.Exit(code=0)
