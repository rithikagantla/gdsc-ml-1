"""
SCOPE-001 · Over-permission  ->  VulnClass.OVER_PERMISSION

OWNER: Arnav · WEEK 4 (v1) / WEEK 5 (tuning purposes.yaml)

IDEA
    AWS IAM least privilege, in a new costume. A "weather" tool asking for a raw filesystem
    `path` is asking for more than its job needs.

TWO STEPS
    1. Stated purpose: map tool name + description -> purpose category using the keyword table
       in purposes.yaml (weather, math, time, files, web, shell, ...). Unknown -> skip, no finding.
    2. Requested capability: read from the schema + annotations:
         params named path/file/dir -> "filesystem"
         command/cmd/script         -> "shell"
         url/endpoint/webhook       -> "network"
         sql/query                  -> "database"
         annotations destructiveHint: true / readOnlyHint: false -> "write"
    If a capability is not in purposes.yaml[purpose].allowed -> Finding (location = SCHEMA).

WHY YAML
    Tuning in week 5 becomes a data change, not a code change. Document every edit in the report.

STEPS
    [ ] load_purposes() reads purposes.yaml next to this file (importlib.resources).
    [ ] classify_purpose(tool) -> str | None
    [ ] requested_capabilities(tool) -> set[str]   (also reused by severity.py for "network")
    [ ] evidence = "purpose=weather requests filesystem via param 'path'"
    [ ] Test with corpus 02_over_scoped (Arnav's over_scoped_filesystem server).
"""

from __future__ import annotations

from mcpscan.models import Finding, Location, ServerManifest, Tool, VulnClass
from mcpscan.rules.base import Rule, ScanContext


def load_purposes() -> dict:
    raise NotImplementedError("Arnav: week 4")


def classify_purpose(tool: Tool, purposes: dict) -> str | None:
    raise NotImplementedError("Arnav: week 4")


def requested_capabilities(tool: Tool) -> set[str]:
    raise NotImplementedError("Arnav: week 4")


class OverPermissionRule(Rule):
    id = "SCOPE-001"
    vuln_class = VulnClass.OVER_PERMISSION
    location = Location.SCHEMA
    description = "Tool requests capabilities beyond its stated purpose."

    def check(self, tool: Tool, manifest: ServerManifest, context: ScanContext) -> list[Finding]:
        raise NotImplementedError("Arnav: week 4")
