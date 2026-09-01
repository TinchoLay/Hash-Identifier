import json

from click.testing import CliRunner

from hashid.cli import main

_BCRYPT_EXAMPLE = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G"


def test_identify_table_output_for_known_hash():
    runner = CliRunner()
    result = runner.invoke(main, ["identify", _BCRYPT_EXAMPLE])
    assert result.exit_code == 0
    assert "bcrypt" in result.output


def test_identify_json_output_is_valid_json():
    runner = CliRunner()
    result = runner.invoke(main, ["identify", _BCRYPT_EXAMPLE, "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data[0]["algorithm"] == "bcrypt"


def test_identify_csv_output_has_header():
    runner = CliRunner()
    result = runner.invoke(main, ["identify", _BCRYPT_EXAMPLE, "--format", "csv"])
    assert result.exit_code == 0
    assert result.output.startswith("algorithm,confidence,reason,detector_name")


def test_identify_no_match_exits_with_error_code():
    runner = CliRunner()
    result = runner.invoke(main, ["identify", "esto no es un hash"])
    assert result.exit_code == 1