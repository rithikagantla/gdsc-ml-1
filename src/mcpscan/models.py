"""
Data models — the contract every other file depends on.

OWNER: Rithika (schema owner) · LOCKED Oct 20, 2026 (v1)
Changes need Rithika's review + a heads-up in #ml-1. tests/test_models.py pins the enum values,
so a change here fails CI until the test is updated on purpose.

WHAT THIS IS
    Everything downstream reads these models. Rules take a `Tool` + `ServerManifest` and return
    `Finding`s. Corpus `label.yaml` files parse into `ServerLabel`. The benchmark matches
    Findings to labels on the key (server, tool, vuln_class).

DECISIONS (v1)
    [x] VulnClass matches Arnav's top 6 in docs/threat-model.md, one class per attack type.
    [x] TOOL_SHADOWING and NAME_COLLISION stay separate: shadowing hides in a description and
        targets another server's tool; collision is about the name itself. Different rules,
        different false-positive traps, so they get separate precision/recall rows.
    [x] Rug pull and output injection are not classes: they are dynamic (stretch) and report as
        TOOL_POISONING with location BEHAVIOR.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class VulnClass(str, Enum):
    TOOL_POISONING = "tool_poisoning"
    TOOL_SHADOWING = "tool_shadowing"
    NAME_COLLISION = "name_collision"
    OVER_PERMISSION = "over_permission"
    HIDDEN_TEXT = "hidden_text"
    CREDENTIAL_HARVEST = "credential_harvest"


class Location(str, Enum):
    NAME = "name"
    DESCRIPTION = "description"
    SCHEMA = "schema"
    BEHAVIOR = "behavior"  # dynamic harness findings (stretch)


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["low", "medium", "high", "critical"].index(self.value)


class Tool(BaseModel):
    name: str
    description: str = ""
    input_schema: dict = {}
    annotations: dict = {}  # MCP hints like readOnlyHint, destructiveHint
    description_sha256: str = ""  # set by connect.py; enables rug-pull detection later


class ServerManifest(BaseModel):
    server: str
    tools: list[Tool]
    raw: dict = {}  # the untouched tools/list response, kept as evidence


class Finding(BaseModel):
    rule_id: str
    server: str
    tool: str
    vuln_class: VulnClass
    location: Location
    severity: Severity = Severity.LOW  # severity.py overwrites this after rules run
    evidence: str  # exact text that triggered the rule

    @property
    def key(self) -> tuple[str, str, VulnClass]:
        """Benchmark match key."""
        return (self.server, self.tool, self.vuln_class)


class LabeledVuln(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    tool: str
    vuln_class: VulnClass = Field(alias="class")
    location: Location
    note: str = ""


class ServerLabel(BaseModel):
    """Parsed form of corpus/servers/<name>/label.yaml."""

    server: str
    vulnerabilities: list[LabeledVuln] = []
