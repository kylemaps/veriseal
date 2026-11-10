"""`veriseal --version` reports the installed package version."""

from __future__ import annotations

import re

import pytest
from typer.testing import CliRunner

from veriseal import __version__
from veriseal.cli import app

runner = CliRunner()


@pytest.mark.parametrize("flag", ["--version", "-V", "-v"])
def test_version_flag_prints_the_version(flag):
    result = runner.invoke(app, [flag])
    assert result.exit_code == 0
    assert result.output.strip() == f"veriseal {__version__}"


def test_help_still_lists_the_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.output)  # colour codes can split an option
    assert "--version" in plain
    assert "seal" in plain


def test_bare_command_still_shows_help():
    result = runner.invoke(app, [])
    assert "Usage" in result.output
