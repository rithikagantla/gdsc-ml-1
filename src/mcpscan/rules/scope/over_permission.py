"""
SCOPE-001 · Over-permission  ->  VulnClass.OVER_PERMISSION

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
"""

from __future__ import annotations

import re
from functools import lru_cache
from importlib.resources import files

import yaml

from mcpscan.models import Finding, Location, ServerManifest, Tool, VulnClass
from mcpscan.rules.base import Rule, ScanContext

NAME_WEIGHT = 3  # a keyword in the tool's name says more than one in its description
DESCRIPTION_WEIGHT = 1

PARAM_CAPABILITIES: dict[str, set[str]] = {
    "filesystem": {"path", "filepath", "file", "filename", "dir", "directory", "folder"},
    "shell": {"command", "cmd", "script", "shell"},
    "network": {"url", "uri", "endpoint", "webhook", "host"},
    "database": {"sql"},  # not `query`: most `query` params are search boxes
}


def _tokens(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {word[:-1] if len(word) > 3 and word.endswith("s") else word for word in words}


@lru_cache(maxsize=1)
def load_purposes() -> dict:
    text = files("mcpscan.rules.scope").joinpath("purposes.yaml").read_text("utf-8")
    return yaml.safe_load(text)


def classify_purpose(tool: Tool, purposes: dict) -> str | None:
    """Best-matching purpose, or None when nothing matches or two purposes tie."""
    name_tokens = _tokens(tool.name)
    description_tokens = _tokens(tool.description)
    scores: dict[str, int] = {}

    for purpose, config in purposes.items():
        score = 0
        for keyword in config["keywords"]:
            words = _tokens(keyword)
            if words <= name_tokens:
                score += NAME_WEIGHT
            elif words <= description_tokens:
                score += DESCRIPTION_WEIGHT
        if score:
            scores[purpose] = score

    if not scores:
        return None

    best = max(scores.values())
    leaders = [purpose for purpose, score in scores.items() if score == best]
    return leaders[0] if len(leaders) == 1 else None


def capability_sources(tool: Tool) -> dict[str, list[str]]:
    """Each capability the tool requests, with what in the schema or annotations requests it."""
    sources: dict[str, list[str]] = {}

    for param in (tool.input_schema or {}).get("properties", {}):
        for capability, names in PARAM_CAPABILITIES.items():
            if param.lower() in names:
                sources.setdefault(capability, []).append(f"param {param!r}")

    annotations = tool.annotations or {}

    # Saved JSON uses the wire names; a live SDK v2 client gives snake_case.
    if annotations.get("destructiveHint") or annotations.get("destructive_hint"):
        sources.setdefault("write", []).append("destructive hint")
    if annotations.get("readOnlyHint") is False or annotations.get("read_only_hint") is False:
        sources.setdefault("write", []).append("not read-only")

    return sources


def requested_capabilities(tool: Tool) -> set[str]:
    return set(capability_sources(tool))


class OverPermissionRule(Rule):
    id = "SCOPE-001"
    vuln_class = VulnClass.OVER_PERMISSION
    location = Location.SCHEMA
    description = "Tool requests capabilities beyond its stated purpose."

    def check(self, tool: Tool, manifest: ServerManifest, context: ScanContext) -> list[Finding]:
        purposes = load_purposes()
        purpose = classify_purpose(tool, purposes)

        if purpose is None:
            return []

        sources = capability_sources(tool)
        excess = sorted(set(sources) - set(purposes[purpose]["allowed"]))

        if not excess:
            return []

        detail = "; ".join(f"{cap} via {', '.join(sources[cap])}" for cap in excess)
        return [self.finding(tool, manifest, evidence=f"purpose={purpose} requests {detail}")]
