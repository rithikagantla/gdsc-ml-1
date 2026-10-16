import asyncio
import json
import sys
from pathlib import Path

import pytest

from mcpscan.connect import ConnectError, load_manifest, load_manifest_from_file, sha256_text

HELLO = Path(__file__).parent.parent / "corpus" / "servers" / "00_hello" / "server.py"


def write(tmp_path, data, name="demo.tools.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return path


def test_file_bare_list_and_name(tmp_path):
    m = load_manifest_from_file(write(tmp_path, [{"name": "a", "description": "d"}]))
    assert m.server == "demo"
    assert [t.name for t in m.tools] == ["a"]


def test_file_wrapped_object_and_explicit_name(tmp_path):
    m = load_manifest_from_file(write(tmp_path, {"tools": [{"name": "a"}]}), server_name="weather")
    assert m.server == "weather"


@pytest.mark.parametrize("key", ["input_schema", "inputSchema"])
def test_file_accepts_both_schema_keys(tmp_path, key):
    schema = {"type": "object"}
    m = load_manifest_from_file(write(tmp_path, [{"name": "a", key: schema}]))
    assert m.tools[0].input_schema == schema


def test_description_hash(tmp_path):
    m = load_manifest_from_file(write(tmp_path, [{"name": "a", "description": "hello"}]))
    assert m.tools[0].description_sha256 == sha256_text("hello")


def test_file_errors(tmp_path):
    with pytest.raises(ConnectError, match="file not found"):
        load_manifest_from_file(tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(ConnectError, match="not valid JSON"):
        load_manifest_from_file(bad)
    with pytest.raises(ConnectError, match="must be a list"):
        load_manifest_from_file(write(tmp_path, {"tools": "x"}, "w.json"))
    with pytest.raises(ConnectError, match="'name'"):
        load_manifest_from_file(write(tmp_path, [{"description": "x"}], "n.json"))


def test_stdio_hello_lists_two_tools():
    m = asyncio.run(load_manifest([sys.executable, str(HELLO)]))
    assert sorted(t.name for t in m.tools) == ["add", "get_weather"]
    assert len(m.raw["tools"]) == 2


def test_missing_command():
    with pytest.raises(ConnectError, match="command not found"):
        asyncio.run(load_manifest(["definitely-not-a-real-binary-xyz"]))


def test_silent_server_times_out():
    command = [sys.executable, "-c", "import time; time.sleep(30)"]
    with pytest.raises(ConnectError, match="did not respond within 1s"):
        asyncio.run(load_manifest(command, timeout=1))


def test_bad_url_and_empty_command():
    with pytest.raises(ConnectError, match="not an http"):
        asyncio.run(load_manifest("ftp://x"))
    with pytest.raises(ConnectError, match="no server command"):
        asyncio.run(load_manifest([]))
