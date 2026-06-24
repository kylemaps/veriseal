"""veriseal inspect command — time-windowed incident slice."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from mcap.reader import make_reader
from mcap.writer import Writer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def parse_time(s: str) -> int:
    """
    Parse *s* as nanoseconds since epoch (integer string) or ISO-8601 UTC string.

    Returns an integer nanosecond timestamp.
    Raises ValueError on unrecognised format.
    """
    s = s.strip()
    try:
        return int(s)
    except ValueError:
        pass
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        raise ValueError(
            f"Cannot parse time {s!r} — use ns-since-epoch integer or ISO-8601 UTC "
            "(e.g. 2024-01-01T12:00:00Z)"
        ) from None
    if dt.tzinfo is None:
        raise ValueError(f"Timestamp {s!r} has no timezone — suffix with Z or +00:00")
    # Integer arithmetic to avoid float multiplication; preserves microsecond precision.
    delta = dt - _EPOCH
    return (
        delta.days * 86_400_000_000_000
        + delta.seconds * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _ns_to_iso(ns: int) -> str:
    dt = _EPOCH + timedelta(
        seconds=ns // 1_000_000_000,
        microseconds=(ns % 1_000_000_000) // 1_000,
    )
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def inspect_mcap(
    path: Path,
    from_ns: int,
    to_ns: int,
    topic_filter: str | None,
    out_path: Path | None,
) -> int:
    """
    Filter *path* to [from_ns, to_ns], display a timeline, write incident slice.

    Returns 0 on success, 2 on error.
    """
    if from_ns > to_ns:
        console.print(
            f"[bold red]ERROR:[/bold red] --from ({from_ns}) must be <= --to ({to_ns})"
        )
        return 2

    if out_path is None:
        out_path = path.with_name(path.stem + ".incident.mcap")

    # ── Read and filter ───────────────────────────────────────────────────────
    windowed: list[tuple] = []  # (schema | None, channel, message)
    try:
        with open(path, "rb") as f:
            reader = make_reader(f)
            for schema, channel, message in reader.iter_messages():
                if message.log_time < from_ns or message.log_time > to_ns:
                    continue
                if topic_filter is not None and channel.topic != topic_filter:
                    continue
                windowed.append((schema, channel, message))
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] Cannot read MCAP: {exc}")
        return 2

    # iter_messages delivers in log_time order; re-sort to be explicit.
    windowed.sort(key=lambda t: t[2].log_time)

    # ── Timeline table ────────────────────────────────────────────────────────
    table = Table(
        title=f"Window [{from_ns} ns, {to_ns} ns]  —  {len(windowed)} message(s)",
        show_lines=False,
    )
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("log_time (ns)", style="cyan", no_wrap=True)
    table.add_column("ISO-8601 UTC", style="cyan", no_wrap=True)
    table.add_column("topic", style="green")
    table.add_column("bytes", justify="right")
    table.add_column("preview (hex)", style="yellow")

    for i, (_schema, channel, msg) in enumerate(windowed):
        table.add_row(
            str(i),
            str(msg.log_time),
            _ns_to_iso(msg.log_time),
            channel.topic,
            str(len(msg.data)),
            msg.data[:16].hex(),
        )

    console.print(table)

    # ── Write incident MCAP ───────────────────────────────────────────────────
    try:
        with open(out_path, "wb") as f:
            writer = Writer(f)
            writer.start()

            # Map source schema_id → output schema_id (register each once)
            schema_id_map: dict[int, int] = {}
            # Map source channel_id → output channel_id (register each once)
            channel_id_map: dict[int, int] = {}

            for schema, channel, message in windowed:
                if channel.schema_id not in schema_id_map:
                    if schema is None or channel.schema_id == 0:
                        schema_id_map[channel.schema_id] = 0
                    else:
                        schema_id_map[channel.schema_id] = writer.register_schema(
                            name=schema.name,
                            encoding=schema.encoding,
                            data=schema.data,
                        )

                if channel.id not in channel_id_map:
                    channel_id_map[channel.id] = writer.register_channel(
                        topic=channel.topic,
                        message_encoding=channel.message_encoding,
                        schema_id=schema_id_map[channel.schema_id],
                        metadata=channel.metadata,
                    )

                writer.add_message(
                    channel_id=channel_id_map[channel.id],
                    log_time=message.log_time,
                    data=message.data,
                    publish_time=message.publish_time,
                    sequence=message.sequence,
                )

            writer.finish()
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] Cannot write incident MCAP: {exc}")
        return 2

    console.print(
        Panel(
            f"[bold]Messages in window:[/bold] {len(windowed)}\n"
            f"[bold]Output:[/bold] {out_path}",
            title="[green]Inspect complete[/green]",
            expand=False,
        )
    )
    return 0
