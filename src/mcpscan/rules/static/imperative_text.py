"""
STATIC-001 · Imperative text aimed at the model -> VulnClass.TOOL_POISONING

OWNER: Raiyan · WEEK 3 (v1) / WEEK 5 (tuning)

HOW IT WORKS
    A *scored* phrase list for text addressed to the AI, not the user. Flag only when the total
    score passes THRESHOLD — never on a single word.
        high weight: "ignore previous", "do not tell the user", "don't mention", "<IMPORTANT>",
                     "system:", "before using any tool", "you must first", "secretly"
        low weight: "always", "must", "never", "before calling"

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
    "ignore previous": 3,
    "do not tell the user": 3,
    "don't tell the user": 3,
    "don't mention": 3,
    "<important>": 2,
    "system:": 2,
    "before using any tool": 3,
    "you must first": 2,
    "secretly": 3,
    "always": 1,
    "must": 1,
    "never": 1,
    "before calling": 1,
}

ALLOWLIST: list[str] = [
    "use this tool when",
    "always pass absolute paths",
]


class ImperativeTextRule(Rule):
    id = "STATIC-001"
    vuln_class = VulnClass.TOOL_POISONING
    location = Location.DESCRIPTION
    description = "Tool description contains instructions aimed at the model."

    def check(
        self,
        tool: Tool,
        manifest: ServerManifest,
        context: ScanContext,
    ) -> list[Finding]:
        original = tool.description

        if not original:
            return []

        normalized = " ".join(original.lower().split())

        score = 0
        matched_phrases: list[str] = []

        for phrase, weight in PHRASES.items():
            if phrase in normalized:
                score += weight
                matched_phrases.append(phrase)

        for phrase in ALLOWLIST:
            if phrase in normalized:
                score -= 2

        if score < THRESHOLD:
            return []

        evidence_sentences: list[str] = []

        for sentence in original.split("."):
            stripped = sentence.strip()

            if not stripped:
                continue

            lowered = stripped.lower()

            if any(phrase in lowered for phrase in matched_phrases):
                evidence_sentences.append(stripped)

        evidence = ". ".join(evidence_sentences)

        return [
            self.finding(
                tool,
                manifest,
                evidence=evidence,
            )
        ]
