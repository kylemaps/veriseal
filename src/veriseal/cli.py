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

_NOT_IMPLEMENTED = "[bold yellow]Not implemented in v0.1 scaffold.[/bold yellow]"


@app.command()
def seal(
    path: Path = typer.Argument(..., help="Path to the .mcap file to seal."),
    key: Path | None = typer.Option(None, "--key", help="Path to Ed25519 private key (PEM)."),
    out: Path | None = typer.Option(
        None, "--out", help="Output path for the .seal.json manifest."
    ),
) -> None:
    """Hash every message, build a Merkle tree, sign, and write manifest."""
    from veriseal.seal import seal as do_seal

    do_seal(path, key, out)


@app.command()
def verify(
    path: Path = typer.Argument(..., help="Path to the .mcap file to verify."),
    seal_json: Path = typer.Argument(
        ..., help="Path to the .seal.json manifest.", metavar="PATH.seal.json"
    ),
) -> None:
    """Recompute hashes, validate signature and OTS proof, report INTACT or TAMPERED."""
    console.print(_NOT_IMPLEMENTED)
    raise typer.Exit(code=2)


@app.command()
def inspect(
    path: Path = typer.Argument(..., help="Path to the .mcap file to inspect."),
    from_time: str = typer.Option(..., "--from", help="Start of window (ISO 8601 or ROS time)."),
    to_time: str = typer.Option(..., "--to", help="End of window (ISO 8601 or ROS time)."),
    topic: str | None = typer.Option(None, "--topic", help="Filter to a single topic."),
) -> None:
    """Print a chronological event timeline for the window; export sliced incident.mcap."""
    console.print(_NOT_IMPLEMENTED)
    raise typer.Exit(code=2)
