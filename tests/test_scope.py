from mcpscan.models import ServerManifest, Tool
from mcpscan.rules.base import ScanContext
from mcpscan.rules.scope.over_permission import (
    OverPermissionRule,
    capability_sources,
    classify_purpose,
    load_purposes,
    requested_capabilities,
)


def schema(*params):
    return {"type": "object", "properties": {name: {"type": "string"} for name in params}}


def check(tool):
    manifest = ServerManifest(server="s", tools=[tool])
    return OverPermissionRule().check(tool, manifest, ScanContext(all_manifests=[manifest]))


def test_weather_tool_with_path_param_is_flagged():
    tool = Tool(name="get_forecast", description="Get a forecast.", input_schema=schema("path"))
    findings = check(tool)
    assert len(findings) == 1
    assert "purpose=weather" in findings[0].evidence and "filesystem" in findings[0].evidence


def test_files_tool_with_path_param_is_not_flagged():
    tool = Tool(name="read_file", description="Read a file.", input_schema=schema("path"))
    assert check(tool) == []


def test_unknown_purpose_is_skipped():
    tool = Tool(name="frobnicate", description="Does a thing.", input_schema=schema("path"))
    assert classify_purpose(tool, load_purposes()) is None
    assert check(tool) == []


def test_tied_purposes_are_skipped():
    purposes = {"a": {"keywords": ["alpha"]}, "b": {"keywords": ["beta"]}}
    assert classify_purpose(Tool(name="alpha_beta"), purposes) is None


def test_keyword_in_name_beats_keyword_in_description():
    purposes = {"a": {"keywords": ["alpha"]}, "b": {"keywords": ["beta"]}}
    assert classify_purpose(Tool(name="alpha", description="beta"), purposes) == "a"


def test_write_capability_from_wire_and_sdk_annotation_names():
    assert "write" in requested_capabilities(Tool(name="x", annotations={"destructiveHint": True}))
    assert "write" in requested_capabilities(Tool(name="x", annotations={"read_only_hint": False}))
    assert requested_capabilities(Tool(name="x", annotations={"readOnlyHint": True})) == set()


def test_query_param_is_not_a_database_capability():
    assert capability_sources(Tool(name="x", input_schema=schema("query"))) == {}


def test_add_as_a_verb_is_not_math():
    tool = Tool(name="add_observations", annotations={"readOnlyHint": False})
    assert classify_purpose(tool, load_purposes()) is None

