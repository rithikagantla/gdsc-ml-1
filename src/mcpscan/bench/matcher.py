"""
Matcher — line up findings with ground-truth labels.

OWNER: Arnav · WEEK 4

RULES (from the sprint guide)
    Key = (server, tool, vuln_class). Several findings with the same key count ONCE.
      True positive : finding key is in the labels
      False positive: finding key is NOT in the labels (tools with no label must be clean)
      False negative: label with no matching finding

STEPS
    [ ] match(findings, labels) -> MatchResult with tp / fp / fn lists of keys
    [ ] Keep the original Finding objects for FPs so the report can quote evidence.
    [ ] tests/test_matcher.py: duplicates count once; unlabeled tool -> FP; missed label -> FN.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mcpscan.models import Finding, ServerLabel, VulnClass

Key = tuple[str, str, VulnClass]


@dataclass
class MatchResult:
    tp: set[Key] = field(default_factory=set)
    fp: set[Key] = field(default_factory=set)
    fn: set[Key] = field(default_factory=set)
    fp_findings: list[Finding] = field(default_factory=list)


def label_keys(labels: list[ServerLabel]) -> set[Key]:
    return {(lab.server, v.tool, v.vuln_class) for lab in labels for v in lab.vulnerabilities}



def match(findings: list[Finding], labels: list[ServerLabel]) -> MatchResult:
    # Get all known vulnerabilities from ground-truth labels.
    expected = label_keys(labels)

    # Track unique vulnerabilities reported by the scanner.
    found: set[Key] = set()

    # Keep original false-positive findings for the report.
    fp_findings: list[Finding] = []

    for finding in findings:
        key = finding.key

        # Ignore repeated findings with the same key.
        if key in found:
            continue

        found.add(key)

        # Save findings that are not in the ground truth.
        if key not in expected:
            fp_findings.append(finding)

    return MatchResult(
        tp=found & expected,
        fp=found - expected,
        fn=expected - found,
        fp_findings=fp_findings,
    )

