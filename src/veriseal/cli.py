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
) -> None:
    """Recompute hashes, validate signature, report INTACT or TAMPERED (with location)."""
    from veriseal.verify import verify_seal

    raise typer.Exit(code=verify_seal(path, seal_json))


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
