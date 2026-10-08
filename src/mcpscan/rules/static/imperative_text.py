"""
STATIC-001 · Imperative text aimed at the model  ->  VulnClass.TOOL_POISONING

OWNER: Raiyan · WEEK 3 (v1) / WEEK 5 (tuning)

HOW IT WORKS
    A *scored* phrase list for text addressed to the AI, not the user. Flag only when the total
    score passes THRESHOLD — never on a single word.
      high weight:  "ignore previous", "do not tell the user", "don't mention", "<IMPORTANT>",
                    "system:", "before using any tool", "you must first", "secretly"
      low weight:   "always", "must", "never", "before calling"

FALSE-POSITIVE TRAP
    Normal help text says "Use this tool when..." or "Always pass absolute paths". Keep an
    ALLOWLIST of benign patterns that subtract score. Test against samples/*.tools.json.

STEPS
    [ ] Lowercase + normalize whitespace before matching.
    [ ] Score = sum(weights of matched phrases) - allowlist credits.
    [ ] evidence = the matched sentence(s), verbatim.
    [ ] Tests: positive on corpus 01_hidden_instructions, negative on every samples/ description.
"""

from __future__ import annotations

from mcpscan.models import Finding, Location, ServerManifest, Tool, VulnClass
from mcpscan.rules.base import Rule, ScanContext

THRESHOLD = 3

PHRASES: dict[str, int] = {
    # TODO(Raiyan): fill in and tune
    "ignore previous": 3,
    "do not tell the user": 3,
    "<important>": 2,
}

ALLOWLIST: list[str] = [
    # TODO(Raiyan): benign patterns, e.g. r"use this tool when", r"always pass absolute paths"
]


class ImperativeTextRule(Rule):
    id = "STATIC-001"
    vuln_class = VulnClass.TOOL_POISONING
    location = Location.DESCRIPTION
    description = "Tool description contains instructions aimed at the model."

    def check(self, tool: Tool, manifest: ServerManifest, context: ScanContext) -> list[Finding]:
        raise NotImplementedError("Raiyan: week 3")
