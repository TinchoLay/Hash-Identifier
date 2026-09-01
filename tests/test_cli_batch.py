import json

import pytest
from click.testing import CliRunner

from hashid.cli import main

_BCRYPT_EXAMPLE = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G"
_SHA1_EXAMPLE = "a9993e364706816aba3e25717850c26c9cd0d89d"


@pytest.fixture
def sample_hash_file(tmp_path):
    content = "\n".join([
        "# comentario que debe ignorarse",
        _BCRYPT_EXAMPLE,
        "",
        _SHA1_EXAMPLE,
        "esto no es un hash reconocible",
    ])
    file_path = tmp_path / "hashes.txt"
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def test_batch_table_output_includes_both_hashes(sample_hash_file):
    runner = CliRunner()
    result = runner.invoke(main, ["batch", sample_hash_file])
    assert result.exit_code == 0
    assert "bcrypt" in result.output
    assert "SHA-1" in result.output


def test_batch_json_output_has_one_entry_per_hash(sample_hash_file):
    runner = CliRunner()
    result = runner.invoke(main, ["batch", sample_hash_file, "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data) == 3


def test_batch_csv_output_marks_no_match_rows(sample_hash_file):
    runner = CliRunner()
    result = runner.invoke(main, ["batch", sample_hash_file, "--format", "csv"])
    assert result.exit_code == 0
    assert "sin coincidencias" in result.output


def test_batch_output_file_writes_to_disk(sample_hash_file, tmp_path):
    output_path = tmp_path / "resultado.json"
    runner = CliRunner()
    result = runner.invoke(
        main, ["batch", sample_hash_file, "--format", "json", "--output", str(output_path)]
    )
    assert result.exit_code == 0
    assert output_path.exists()
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(data) == 3


def test_batch_table_format_rejects_output_option(sample_hash_file, tmp_path):
    output_path = tmp_path / "resultado.txt"
    runner = CliRunner()
    result = runner.invoke(main, ["batch", sample_hash_file, "--output", str(output_path)])
    assert result.exit_code == 2


def test_batch_empty_file_exits_with_error(tmp_path):
    empty_file = tmp_path / "vacio.txt"
    empty_file.write_text("# solo comentarios\n\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["batch", str(empty_file)])
    assert result.exit_code == 1