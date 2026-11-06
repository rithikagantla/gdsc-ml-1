"""
Rule engine — runs every rule over every tool and collects findings.

GOAL
    findings = run_rules(manifests)   # one or many servers in a single scan
"""

from __future__ import annotations

import logging

from mcpscan.models import Finding, ServerManifest
from mcpscan.rules import ALL_RULES
from mcpscan.rules.base import Rule, ScanContext
from mcpscan.rules.static.name_collision import load_popular_names
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

    context = ScanContext(all_manifests=manifests, popular_names=set(load_popular_names()))

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

    return assign_severities(dedupe(findings), manifests)


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
