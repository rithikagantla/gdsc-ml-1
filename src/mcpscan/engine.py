"""
Rule engine — runs every rule over every tool and collects findings.

OWNER: Raiyan · WEEK 3

GOAL
    findings = run_rules(manifests)   # one or many servers in a single scan

STEPS
    [ ] Loop every rule in rules.ALL_RULES over every tool of every manifest.
    [ ] Wrap each rule.check() in try/except: one broken rule must never kill a scan.
        Log the error (rule id + tool name) with logging.warning() and keep going.
    [ ] Some rules need *all* servers in the scan (name_collision, shadowing). Pass the full list
        via context (see rules/base.py ScanContext).
    [ ] De-duplicate findings: same (rule_id, server, tool, evidence) counts once.
    [ ] After rules run, call severity.assign_severities(findings) (Arnav, week 4).
    [ ] Optional `rule_ids` filter so the CLI can run a subset (--rule STATIC-001).
    [ ] tests/test_engine.py: a rule that raises does not stop other rules; dedup works.

DONE WHEN
    Running it on a manifest from corpus/servers/01_hidden_instructions prints >= 1 finding.
"""

from __future__ import annotations

import logging

from mcpscan.models import Finding, ServerManifest
from mcpscan.rules import ALL_RULES
from mcpscan.rules.base import Rule, ScanContext
from mcpscan.severity import assign_severities


def run_rules(
    manifests: list[ServerManifest],
    rules: list[Rule] | None = None,
    rule_ids: set[str] | None = None,
) -> list[Finding]:
    active_rules = rules if rules is not None else ALL_RULES

    if rule_ids is not None:
        active_rules = [
            rule for rule in active_rules
            if rule.id in rule_ids
        ]

    context = ScanContext(all_manifests=manifests)

    findings: list[Finding] = []

    for manifest in manifests:
        for tool in manifest.tools:
            for rule in active_rules:
                try:
                    rule_findings = rule.check(
                        tool=tool,
                        manifest=manifest,
                        context=context,
                    )
                    findings.extend(rule_findings)

                except Exception as exc:
                    logging.warning(
                        "Rule %s failed on tool %s: %s",
                        rule.id,
                        tool.name,
                        exc,
                    )

    findings = dedupe(findings)

    try:
        findings = assign_severities(findings)
    except NotImplementedError:
        pass

    return findings


def dedupe(findings: list[Finding]) -> list[Finding]:
    unique: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()

    for finding in findings:
        key = (
            finding.rule_id,
            finding.server,
            finding.tool,
            finding.evidence,
        )

        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return unique
