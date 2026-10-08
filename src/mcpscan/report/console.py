"""
Console report — Rich table of findings.

OWNER: Daniel · WEEK 3

STEPS
    [ ] render(findings) -> prints a Rich table: Severity | Rule | Server | Tool | Class | Evidence
    [ ] Color severity: critical=bold red, high=red, medium=yellow, low=dim.
    [ ] Truncate evidence to ~80 chars; show repr() so hidden characters are visible.
    [ ] Summary line: "N findings (C critical, H high, M medium, L low)".
    [ ] "No findings" message when empty — green.
"""

from __future__ import annotations

from mcpscan.models import Finding


def render(findings: list[Finding]) -> None:
    raise NotImplementedError("Daniel: week 3")
