"""Tamper demo/sample.mcap by flipping byte 0 of the first /pose payload.

Usage: python demo/tamper.py [output_path]
"""

from __future__ import annotations

import sys
from pathlib import Path

from mcap.reader import make_reader
from mcap.writer import Writer

SRC = Path("demo/sample.mcap")
DST = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("demo/tampered.mcap")


def main() -> None:
    rows: list[tuple] = []
    with open(SRC, "rb") as f:
        reader = make_reader(f)
        for sc, ch, m in reader.iter_messages():
            rows.append((sc, ch, m))

    tampered_at: int | None = None

    with open(DST, "wb") as f:
        writer = Writer(f)
        writer.start()
        schema_map: dict[int, int] = {}
        channel_map: dict[int, int] = {}

        for sc, ch, m in rows:
            if ch.schema_id not in schema_map:
                if sc is None or ch.schema_id == 0:
                    schema_map[ch.schema_id] = 0
                else:
                    schema_map[ch.schema_id] = writer.register_schema(
                        name=sc.name, encoding=sc.encoding, data=sc.data
                    )
            if ch.id not in channel_map:
                channel_map[ch.id] = writer.register_channel(
                    topic=ch.topic,
                    message_encoding=ch.message_encoding,
                    schema_id=schema_map[ch.schema_id],
                    metadata=ch.metadata,
                )
            data = m.data
            if ch.topic == "/pose" and tampered_at is None:
                data = bytes([m.data[0] ^ 0xFF]) + m.data[1:]
                tampered_at = m.log_time
                print(f"Flipped byte 0 of /pose payload at log_time={m.log_time}")

            writer.add_message(
                channel_id=channel_map[ch.id],
                log_time=m.log_time,
                data=data,
                publish_time=m.publish_time,
                sequence=m.sequence,
            )
        writer.finish()

    print(f"Written: {DST}")


if __name__ == "__main__":
    main()
