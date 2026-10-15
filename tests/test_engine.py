"""Owner: Raiyan. TODO: dedupe works; a rule that raises does not stop other rules."""

from mcpscan.engine import dedupe, run_rules
from mcpscan.models import (
    Finding,
    Location,
    ServerManifest,
    Tool,
    VulnClass,
)
from mcpscan.rules.base import Rule, ScanContext


class WorkingRule(Rule):
    id = "TEST-001"
    vuln_class = VulnClass.TOOL_POISONING
    location = Location.DESCRIPTION
    description = "Test rule that returns a finding."

    def check(
        self,
        tool: Tool,
        manifest: ServerManifest,
        context: ScanContext,
    ) -> list[Finding]:
        return [
            self.finding(
                tool,
                manifest,
                evidence="suspicious text",
            )
        ]


class BrokenRule(Rule):
    id = "TEST-BROKEN"
    vuln_class = VulnClass.TOOL_POISONING
    location = Location.DESCRIPTION
    description = "Test rule that deliberately crashes."

    def check(
        self,
        tool: Tool,
        manifest: ServerManifest,
        context: ScanContext,
    ) -> list[Finding]:
        raise RuntimeError("deliberate test failure")


def make_manifest() -> ServerManifest:
    return ServerManifest(
        server="test-server",
        tools=[
            Tool(
                name="hello",
                description="A normal test tool.",
            )
        ],
    )


def test_broken_rule_does_not_stop_other_rules():
    manifest = make_manifest()

    findings = run_rules(
        [manifest],
        rules=[BrokenRule(), WorkingRule()],
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "TEST-001"


def test_dedupe_removes_identical_findings():
    finding = Finding(
        rule_id="STATIC-001",
        server="test-server",
        tool="hello",
        vuln_class=VulnClass.TOOL_POISONING,
        location=Location.DESCRIPTION,
        evidence="ignore previous instructions",
    )

    findings = dedupe([finding, finding])

    assert len(findings) == 1


def test_rule_id_filter():
    manifest = make_manifest()

    findings = run_rules(
        [manifest],
        rules=[WorkingRule()],
        rule_ids={"OTHER-RULE"},
    )

    assert findings == []
