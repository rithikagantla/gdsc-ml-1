"""
Severity scoring — turn raw findings into Low / Medium / High / Critical.

OWNER: Arnav · WEEK 4

GOAL
    Rules don't decide severity; this module does, looking at ALL findings on the same tool.
    Keep it simple and write the reasoning down so it is defensible in the report.

STARTING TABLE (from the sprint guide — tune in week 5, document every change)
    | Condition                                                         | Severity |
    |-------------------------------------------------------------------|----------|
    | Hidden text AND imperative text on the same tool                  | Critical |
    | Tool poisoning; or credential harvesting on a tool w/ network access | High  |
    | Over-permission, shadowing                                        | Medium   |
    | Name collision alone, low-score imperative match                  | Low      |

STEPS
    [ ] Group findings by (server, tool).
    [ ] Apply the table; a tool's combination can upgrade individual findings.
    [ ] "Network access" = schema has a url/endpoint/webhook param (reuse scope helpers).
    [ ] meets_threshold(): used by `--fail-on high` in the CLI.
    [ ] Unit tests for each row of the table.
"""

from __future__ import annotations

from mcpscan.models import Finding, ServerManifest, Severity


def assign_severities(
    findings: list[Finding], manifests: list[ServerManifest] | None = None
) -> list[Finding]:
    raise NotImplementedError("Arnav: week 4 — see module docstring")


def meets_threshold(finding: Finding, threshold: Severity) -> bool:
    return finding.severity.rank >= threshold.rank
