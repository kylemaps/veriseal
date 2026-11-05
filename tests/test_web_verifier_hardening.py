"""web/verify.html must not let a hostile file inject markup, and must parse like Python.

The page renders values read from the files being checked, so it builds its DOM with
text nodes only and ships a Content-Security-Policy that allows only its own inline
script and style (by hash). Its manifest parser must accept and reject the same inputs
as the Python reference, or the two verifiers could disagree about the same seal; the
parser tests run the page's own JavaScript under Node when it is available.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from veriseal.canonical import canonical_json

PAGE = Path(__file__).resolve().parents[1] / "web" / "verify.html"


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")  # universal newlines, as a browser normalises


def _csp_hash(body: str) -> str:
    return (
        "'sha256-" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode() + "'"
    )


def _csp() -> str:
    m = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', _page())
    assert m, "verify.html has no Content-Security-Policy meta tag"
    return m.group(1)


def _directive(name: str) -> list[str]:
    for part in _csp().split(";"):
        words = part.split()
        if words and words[0] == name:
            return words[1:]
    return []


# markup and policy


def test_charset_is_declared_first() -> None:
    """CSP hashes cover the decoded script text, so the page must always decode as UTF-8."""
    assert _page().startswith('<meta charset="utf-8">\n<meta http-equiv="Content-Security-Policy"')


def test_csp_allows_only_the_pages_own_inline_script_and_style() -> None:
    page = _page()
    scripts = {_csp_hash(b) for b in re.findall(r"<script>(.*?)</script>", page, re.S)}
    styles = {_csp_hash(b) for b in re.findall(r"<style>(.*?)</style>", page, re.S)}
    expected = (
        "default-src 'none'; script-src "
        + " ".join(sorted(scripts))
        + "; style-src "
        + " ".join(sorted(styles))
        + "; base-uri 'none'; form-action 'none'"
    )
    assert set(_directive("script-src")) == scripts, f"update the CSP meta tag to:\n{expected}"
    assert set(_directive("style-src")) == styles, f"update the CSP meta tag to:\n{expected}"
    assert _directive("default-src") == ["'none'"]
    assert "unsafe-inline" not in _csp() and "unsafe-eval" not in _csp()


def test_no_inline_handlers_or_style_attributes() -> None:
    """The CSP blocks both, so they would silently stop working."""
    markup = re.sub(r"<(script|style)>.*?</\1>", "", _page(), flags=re.S)
    assert not re.search(r"\son[a-z]+\s*=", markup)
    assert not re.search(r"\sstyle\s*=", markup)


def test_script_never_parses_strings_as_html() -> None:
    script = re.findall(r"<script>(.*?)</script>", _page(), re.S)[0]
    for sink in (r"\.innerHTML\s*=", r"\.outerHTML", r"insertAdjacentHTML", r"document\.write"):
        assert not re.search(sink, script), sink


# parser agreement with Python (needs Node)


def _js_function(name: str) -> str:
    page = _page()
    start = page.index(f"function {name}(")
    return page[start : page.index("\n}\n", start) + 2]


def _python_verdict(text: str) -> str | None:
    """Python's canonical bytes for *text*, or None if the reference rejects it."""
    try:
        return canonical_json(json.loads(text)).decode("utf-8")
    except (ValueError, UnicodeError):
        return None


CASES_FILE = PAGE.parents[1] / "conformance" / "parse-cases.json"
CASES = json.loads(CASES_FILE.read_text(encoding="utf-8"))["cases"]

_NODE_HARNESS = """
const cases = JSON.parse(require("fs").readFileSync(0, "utf8"));
const out = cases.map((text) => {
  try { return canonicalize(parseSeal(text)); } catch (e) { return null; }
});
process.stdout.write(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="needs Node.js")
def test_parser_accepts_and_rejects_exactly_what_python_does() -> None:
    """Runs the page's own parseSeal + canonicalize on every shared parse case."""
    program = _js_function("canonicalize") + _js_function("parseSeal") + _NODE_HARNESS
    proc = subprocess.run(
        ["node", "-e", program],
        input=json.dumps([case["text"] for case in CASES]),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    js = json.loads(proc.stdout)
    for case, got in zip(CASES, js, strict=True):
        assert got == case["canonical"], case["text"]


def test_shared_parse_cases_match_python() -> None:
    """conformance/parse-cases.json records what the Python reference does today."""
    for case in CASES:
        assert _python_verdict(case["text"]) == case["canonical"], case["text"]
    texts = {case["text"]: case["canonical"] for case in CASES}
    assert texts['{"log_time":1.7e18}'] is None  # the reason the strict parser exists
