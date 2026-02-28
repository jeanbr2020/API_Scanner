import json
from pathlib import Path

import pytest

from src.interfaces.cli import CLI


class DummyResult:
    def __init__(self, data: dict, text: str):
        self._data = data
        self._text = text

    def to_dict(self):
        return self._data

    def __str__(self):
        return self._text


@pytest.fixture
def cli(tmp_path):
    return CLI()


def test_json_output_is_created_and_unique(tmp_path, cli, capsys):
    result = DummyResult({'hello': 'world'}, 'dummy text')
    path = tmp_path / 'scan.json'

    # first save should succeed
    cli._save_results(result, str(path))
    assert path.exists(), "File should have been created"
    assert json.loads(path.read_text(encoding='utf-8')) == {'hello': 'world'}
    captured = capsys.readouterr()
    assert 'Resultado salvo' in captured.out

    # try again with same path: should not overwrite and should print error
    path.write_text('bad', encoding='utf-8')  # ensure some content to detect overwrite
    cli._save_results(result, str(path))
    second_captured = capsys.readouterr()
    assert 'já existe' in second_captured.out
    # ensure contents unchanged
    assert path.read_text(encoding='utf-8') == 'bad'


def test_txt_output_can_overwrite(tmp_path, cli, capsys):
    result = DummyResult({}, 'first')
    path = tmp_path / 'scan.txt'

    cli._save_results(result, str(path))
    assert path.read_text(encoding='utf-8') == 'first'

    # overwrite with new content
    result2 = DummyResult({}, 'second')
    cli._save_results(result2, str(path))
    assert path.read_text(encoding='utf-8') == 'second'
