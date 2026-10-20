"""
SARIF 2.1.0 output, so findings show up in GitHub's Security tab.

Findings are about tools, not lines in a file, so every result carries a logicalLocation
(server/tool). GitHub code scanning also needs a physicalLocation, so when we know which file
the server came from (the --file JSON or the server script) results point at line 1 of it.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from mcpscan import __version__
from mcpscan.models import Finding, Severity
from mcpscan.rules.base import Rule

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/rithikagantla/gdsc-ml-1"

LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

# GitHub sorts code-scanning alerts by this 0.0-10.0 score.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
}


def _rule_descriptor(rule_id: str, rule: Rule | None) -> dict:
    text = (rule.description if rule else "") or rule_id
    descriptor = {
        "id": rule_id,
        "name": type(rule).__name__ if rule else rule_id,
        "shortDescription": {"text": text},
        "helpUri": INFO_URI,
        "properties": {"tags": ["security", "mcp"]},
    }
    if rule:
        descriptor["properties"]["vuln_class"] = rule.vuln_class.value
        descriptor["properties"]["location"] = rule.location.value
    return descriptor


def _fingerprint(f: Finding) -> str:
    key = "\0".join([f.rule_id, f.server, f.tool, f.vuln_class.value, f.evidence])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _message(f: Finding) -> str:
    evidence = f.evidence if len(f.evidence) <= 300 else f.evidence[:297] + "..."
    return (
        f"{f.vuln_class.value} in {f.location.value} of tool '{f.tool}' "
        f"on server '{f.server}': {evidence!r}"
    )


def to_sarif(
    findings: list[Finding],
    rules: list[Rule],
    artifact_uri: str | Path | None = None,
) -> dict:
    by_id = {r.id: r for r in rules}
    rule_ids = list(by_id)
    rule_ids += sorted({f.rule_id for f in findings} - set(by_id))  # e.g. LLM-001, probes
    index = {rule_id: i for i, rule_id in enumerate(rule_ids)}

    uri = Path(artifact_uri).as_posix() if artifact_uri else None

    results = []
    for f in findings:
        location: dict = {
            "logicalLocations": [
                {"name": f.tool, "fullyQualifiedName": f"{f.server}/{f.tool}", "kind": "function"}
            ]
        }
        if uri:
            location["physicalLocation"] = {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": 1},
            }
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": index[f.rule_id],
                "level": LEVELS[f.severity],
                "message": {"text": _message(f)},
                "locations": [location],
                "partialFingerprints": {"mcpscanFinding/v1": _fingerprint(f)},
                "properties": {
                    "server": f.server,
                    "tool": f.tool,
                    "vuln_class": f.vuln_class.value,
                    "location": f.location.value,
                    "severity": f.severity.value,
                    "security-severity": SECURITY_SEVERITY[f.severity],
                    "evidence": f.evidence,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpscan",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": [_rule_descriptor(i, by_id.get(i)) for i in rule_ids],
                    }
                },
                "results": results,
            }
        ],
    }
