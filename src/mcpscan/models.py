"""
Data models — the contract every other file depends on.

OWNER: Rithika (schema owner) · WEEK 1–3 · Changes need Rithika's review + a heads-up in #ml-1.

WHAT THIS IS
    Everything downstream reads these models. Rules take a `Tool` + `ServerManifest` and return
    `Finding`s. Corpus `label.yaml` files parse into `ServerLabel`. The benchmark matches
    Findings to labels on the key (server, tool, vuln_class).

TODO (Rithika)
    [ ] Confirm the VulnClass list matches Arnav's top-6 in docs/threat-model.md.
    [ ] Agree whether TOOL_SHADOWING and NAME_COLLISION stay separate classes.
    [ ] Freeze this file by end of week 3 — after that, rules and labels depend on it.
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
