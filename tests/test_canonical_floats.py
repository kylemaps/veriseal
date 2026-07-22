"""The signed payload must be float-free (Python/JS format floats differently)."""

from __future__ import annotations

import pytest

from veriseal.canonical import canonical_json, reject_floats


def test_finite_float_rejected() -> None:
    with pytest.raises(ValueError, match="floating-point"):
        canonical_json({"x": 1.0})


def test_nested_float_rejected_with_path() -> None:
    with pytest.raises(ValueError, match=r"\$\.a\[1\]\.b"):
        reject_floats({"a": [0, {"b": 2.5}]})


def test_nan_and_inf_rejected() -> None:
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})
    with pytest.raises(ValueError):
        canonical_json({"x": float("inf")})


def test_ints_and_bools_allowed() -> None:
    # bool is a subclass of int and must NOT be rejected.
    out = canonical_json({"a": 1, "b": True, "c": [1, 2, 3], "d": "s", "e": None})
    assert b'"b":true' in out
    assert b'"a":1' in out
