"""
Rule interface — every rule implements this, so people can write rules in parallel.

OWNER: Raiyan · WEEK 3

HOW TO WRITE A RULE
    1. New file in rules/static/ or rules/scope/.
    2. Subclass Rule, set id / vuln_class / location / description.
    3. Implement check(tool, manifest, context) -> list[Finding]. Use self.finding(...) helper.
    4. ALWAYS put the exact triggering text in `evidence` — week-5 FP analysis depends on it.
    5. Add one line to ALL_RULES in rules/__init__.py.
    6. Deterministic only: same input -> same output. No network, no randomness.

TODO (Raiyan)
    [ ] Review this interface with the team in week 3 before writing many rules.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from mcpscan.models import Finding, Location, ServerManifest, Tool, VulnClass


@dataclass
class ScanContext:
    """Everything a rule may need beyond its own server (e.g. other servers for collisions)."""

    all_manifests: list[ServerManifest] = field(default_factory=list)
    popular_names: set[str] = field(default_factory=set)  # built from samples/


class Rule(ABC):
    id: str  # e.g. "STATIC-001"
    vuln_class: VulnClass
    location: Location
    description: str = ""  # one line; also used in SARIF tool.driver.rules

    @abstractmethod
    def check(
        self, tool: Tool, manifest: ServerManifest, context: ScanContext
    ) -> list[Finding]: ...

    def finding(
        self, tool: Tool, manifest: ServerManifest, evidence: str, location: Location | None = None
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            server=manifest.server,
            tool=tool.name,
            vuln_class=self.vuln_class,
            location=location or self.location,
            evidence=evidence,
        )
