"""
Severity scoring — turn raw findings into Low / Medium / High / Critical.

GOAL
    Rules don't decide severity; this module does, looking at ALL findings on the same tool.
    Keep it simple and write the reasoning down so it is defensible in the report.

TABLE (from the sprint guide; rows marked + are ours, because the guide left them open)
    | Condition                                                          | Severity |
    |--------------------------------------------------------------------|----------|
    | Hidden text AND tool poisoning on the same tool                    | Critical |
    | Tool poisoning with a strong phrase (weight >= 2 in STATIC-001)    | High     |
    | Credential harvesting on a tool that also has network access       | High     |
    | + Hidden text alone: nobody hides text for a good reason           | High     |
    | + Credential harvesting without network access                     | Medium   |
    | Over-permission, shadowing                                         | Medium   |
    | Name collision alone; poisoning match on weak words only           | Low      |
"""

from __future__ import annotations

from mcpscan.models import Finding, ServerManifest, Severity, VulnClass
from mcpscan.rules.scope.over_permission import requested_capabilities
from mcpscan.rules.static.imperative_text import PHRASES

STRONG_PHRASE_WEIGHT = 2

BASE_SEVERITY = {
    VulnClass.HIDDEN_TEXT: Severity.HIGH,
    VulnClass.CREDENTIAL_HARVEST: Severity.MEDIUM,
    VulnClass.OVER_PERMISSION: Severity.MEDIUM,
    VulnClass.TOOL_SHADOWING: Severity.MEDIUM,
    VulnClass.NAME_COLLISION: Severity.LOW,
}


def _has_strong_phrase(evidence: str) -> bool:
    text = " ".join(evidence.lower().split())
    return any(
        weight >= STRONG_PHRASE_WEIGHT and phrase in text for phrase, weight in PHRASES.items()
    )


def _severity(finding: Finding, classes_on_tool: set[VulnClass], has_network: bool) -> Severity:
    poisoned_and_hidden = {VulnClass.TOOL_POISONING, VulnClass.HIDDEN_TEXT} <= classes_on_tool

    if finding.vuln_class in (VulnClass.TOOL_POISONING, VulnClass.HIDDEN_TEXT):
        if poisoned_and_hidden:
            return Severity.CRITICAL

    if finding.vuln_class is VulnClass.TOOL_POISONING:
        return Severity.HIGH if _has_strong_phrase(finding.evidence) else Severity.LOW

    if finding.vuln_class is VulnClass.CREDENTIAL_HARVEST and has_network:
        return Severity.HIGH

    return BASE_SEVERITY[finding.vuln_class]


def assign_severities(
    findings: list[Finding], manifests: list[ServerManifest] | None = None
) -> list[Finding]:
    """Return copies of the findings, each scored using everything found on the same tool."""
    classes: dict[tuple[str, str], set[VulnClass]] = {}
    for finding in findings:
        classes.setdefault((finding.server, finding.tool), set()).add(finding.vuln_class)

    networked = {
        (manifest.server, tool.name)
        for manifest in manifests or []
        for tool in manifest.tools
        if "network" in requested_capabilities(tool)
    }

    scored = []
    for finding in findings:
        key = (finding.server, finding.tool)
        severity = _severity(finding, classes[key], key in networked)
        scored.append(finding.model_copy(update={"severity": severity}))
    return scored


def meets_threshold(finding: Finding, threshold: Severity) -> bool:
    return finding.severity.rank >= threshold.rank
