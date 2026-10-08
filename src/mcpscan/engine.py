"""
Rule engine — runs every rule over every tool and collects findings.

OWNER: Raiyan · WEEK 3

GOAL
    findings = run_rules(manifests)   # one or many servers in a single scan

STEPS
    [ ] Loop every rule in rules.ALL_RULES over every tool of every manifest.
    [ ] Wrap each rule.check() in try/except: one broken rule must never kill a scan.
        Log the error (rule id + tool name) with `logging.warning` and keep going.
    [ ] Some rules need *all* servers in the scan (name_collision, shadowing). Pass the full list
        via `context` (see rules/base.py ScanContext).
    [ ] De-duplicate findings: same (rule_id, server, tool, evidence) counts once.
    [ ] After rules run, call severity.assign_severities(findings) (Arnav, week 4).
    [ ] Optional `rule_ids` filter so the CLI can run a subset (`--rule STATIC-001`).
    [ ] tests/test_engine.py: a rule that raises does not stop other rules; dedup works.

DONE WHEN
    Running it on a manifest from corpus/servers/01_hidden_instructions prints >= 1 finding.
"""

from __future__ import annotations

from mcpscan.models import Finding, ServerManifest
from mcpscan.rules.base import Rule


def run_rules(
    manifests: list[ServerManifest],
    rules: list[Rule] | None = None,
    rule_ids: set[str] | None = None,
) -> list[Finding]:
    raise NotImplementedError("Raiyan: week 3 — see module docstring")


def dedupe(findings: list[Finding]) -> list[Finding]:
    raise NotImplementedError("Raiyan: week 3")
