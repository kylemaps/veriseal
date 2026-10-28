"""Run the README Quickstart block as written (offline) and check every documented output."""

from __future__ import annotations

import importlib.util
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from veriseal.cli import app

REPO = Path(__file__).resolve().parents[1]


def _quickstart_lines() -> list[str]:
    text = (REPO / "README.md").read_text(encoding="utf-8")
    section = text.split("## Quickstart", 1)[1]
    return section.split("```bash\n", 1)[1].split("\n```", 1)[0].splitlines()


def _steps() -> list[tuple[str, list[str]]]:
    """(command, documented output lines). Output lines are the '#' lines right after a command."""
    lines = _quickstart_lines()
    steps: list[tuple[str, list[str]]] = []
    after_command = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            after_command = False
        elif line.startswith("#"):
            if after_command:
                steps[-1][1].append(line.lstrip("#").strip())
        else:
            command = line
            if line == 'python -c "':
                while lines[i] != '"':
                    i += 1
                    command += "\n" + lines[i]
            while command.endswith("\\"):
                i += 1
                command = command[:-1] + " " + lines[i].strip()
            steps.append((command, []))
            after_command = True
        i += 1
    return steps


def _assert_documented(output: str, documented: list[str], command: str) -> None:
    flat = " ".join(output.split())
    pos = 0
    in_source_block = False
    for line in documented:
        if line.startswith("Source digest mismatch"):
            in_source_block = True
        elif not line.startswith(("expected", "actual")):
            in_source_block = False
        text = line[:-3] if line.endswith("...") else line
        pattern = re.escape(" ".join(text.split()))
        if in_source_block and line.startswith(("expected", "actual")):
            # Whole-file hashes depend on the MCAP writer/compressor versions; message hashes don't.
            pattern = re.sub(r"[0-9a-f]{8,}", "[0-9a-f]+", pattern)
        match = re.compile(pattern).search(flat, pos)
        assert match, f"documented output {line!r} missing after `{command}`:\n{output}"
        pos = match.end()


def test_quickstart_parses_into_the_documented_commands() -> None:
    commands = [c.split()[1] if c.startswith("veriseal") else c.split()[0] for c, _ in _steps()]
    assert commands[:4] == ["keygen", "seal", "seal", "verify"]
    assert "python" in commands and commands[-1] == "anchor"


def test_readme_quickstart_runs_as_documented(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    spec = importlib.util.spec_from_file_location("make_sample", REPO / "demo" / "make_sample.py")
    make_sample = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(make_sample)
    make_sample.write_sample(tmp_path / "log.mcap")
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    for command, documented in _steps():
        if command.startswith("python -c"):
            code = command.split('"', 1)[1].rsplit('"', 1)[0]
            subprocess.run([sys.executable, "-c", code], cwd=tmp_path, check=True)
            continue
        args = shlex.split(command, comments=True)
        assert args[0] == "veriseal", command
        args = args[1:]
        if args[0] == "seal" and "--no-anchor" not in args:
            args.append("--no-anchor")  # tests never contact public OpenTimestamps calendars
        result = runner.invoke(app, args)
        expected_exit = 1 if any(line.startswith("TAMPERED") for line in documented) else 0
        assert result.exit_code == expected_exit, (
            f"`{command}` -> {result.exit_code}\n{result.output}"
        )
        _assert_documented(result.output, documented, command)
