from click.testing import CliRunner
import pytest
from endectools.cli import cli

@pytest.fixture
def runner():
    return CliRunner()

def test_version(runner):
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "EndecTools" in result.output

def test_help(runner):
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "encrypt" in result.output and "decrypt" in result.output