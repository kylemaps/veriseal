"""Canonical JSON serialisation — deterministic bytes for signing.

The signed payload MUST NOT contain floating-point numbers. Python's `json`
formats floats differently from JavaScript's `JSON.stringify`/`String(x)` (e.g.
Python emits `1.0` where JS emits `1`, and the two disagree on precision and
exponent formatting for many values), so a float anywhere in the manifest would
make the canonical bytes — and therefore the Ed25519 signature — diverge between
the Python reference and the browser/panel verifiers, silently breaking
cross-verifier verification. veriseal's schema uses only integers (log_time in
ns, byte sizes, counts), so we reject floats outright rather than trust that no
one ever adds a float field later. See SPEC-manifest.md 1.
"""

from __future__ import annotations

import json


def reject_floats(obj: object, path: str = "$") -> None:
    """Raise ValueError if *obj* contains any float (at any depth).

    Note: `bool` is a subclass of `int` and is allowed; only real floats are
    rejected. `allow_nan=False` in json.dumps already blocks NaN/Infinity, but
    that permits finite floats like 1.0 — those are exactly the ones that would
    diverge between Python and JS, so they are caught here.
    """
    if isinstance(obj, float):
        raise ValueError(
            f"floating-point number at {path} is not allowed in the signed payload "
            f"(Python and JavaScript format floats differently, which would break "
            f"cross-verifier signature checks); use integers only"
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            reject_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            reject_floats(v, f"{path}[{i}]")


def canonical_json(obj: object) -> bytes:
    reject_floats(obj)
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
