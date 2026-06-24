"""Canonical JSON serialisation — deterministic bytes for signing."""

from __future__ import annotations

import json


def canonical_json(obj: object) -> bytes:
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
