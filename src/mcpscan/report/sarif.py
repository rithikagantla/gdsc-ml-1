"""
SARIF 2.1.0 output — lets findings show up in GitHub's Security tab.

OWNER: Daniel · WEEK 5–6 · Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

MAPPING
    - Every rule -> runs[0].tool.driver.rules[]  (id, shortDescription = rule.description)
    - Every finding -> runs[0].results[]:
        ruleId   = finding.rule_id
        level    = critical/high -> "error", medium -> "warning", low -> "note"
        message  = text quoting finding.evidence
        locations[0].logicalLocations = [{"name": tool, "fullyQualifiedName": "server/tool",
                                          "kind": "function"}]
      (Findings are not lines in a file, so use logicalLocations, not physicalLocation.)
    - Put severity + vuln_class in result.properties.

STEPS
    [ ] to_sarif(findings, rules) -> dict
    [ ] Validate output against the SARIF JSON schema in tests/test_sarif.py.
    [ ] Upload in CI via github/codeql-action/upload-sarif (see action.yml).
"""

from __future__ import annotations

from mcpscan.models import Finding, Severity
from mcpscan.rules.base import Rule

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def to_sarif(findings: list[Finding], rules: list[Rule]) -> dict:
    raise NotImplementedError("Daniel: week 5")
