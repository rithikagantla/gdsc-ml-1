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
    raise NotImplementedError("Arnav: week 4 — see module docstring")
