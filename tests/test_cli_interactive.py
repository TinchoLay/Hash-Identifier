from click.testing import CliRunner

from hashid.cli import main

_BCRYPT_EXAMPLE = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G"


def test_interactive_identifies_hash_then_exits_on_salir():
    runner = CliRunner()
    result = runner.invoke(main, ["interactive"], input=f"{_BCRYPT_EXAMPLE}\nsalir\n")
    assert result.exit_code == 0
    assert "bcrypt" in result.output


def test_interactive_ignores_empty_lines_and_exits_on_exit_keyword():
    runner = CliRunner()
    result = runner.invoke(main, ["interactive"], input="\n\nexit\n")
    assert result.exit_code == 0