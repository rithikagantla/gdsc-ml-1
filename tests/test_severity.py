from mcpscan.models import (
    Finding,
    Location,
    ServerManifest,
    Severity,
    Tool,
    VulnClass,
)
from mcpscan.severity import assign_severities, meets_threshold


def finding(vuln_class, evidence="x", tool="t"):
    return Finding(
        rule_id="R",
        server="s",
        tool=tool,
        vuln_class=vuln_class,
        location=Location.DESCRIPTION,
        evidence=evidence,
    )


def score(*findings, manifests=None):
    return [f.severity for f in assign_severities(list(findings), manifests)]


def test_hidden_text_and_poisoning_on_one_tool_is_critical():
    scored = score(
        finding(VulnClass.HIDDEN_TEXT), finding(VulnClass.TOOL_POISONING, "ignore previous")
    )
    assert scored == [Severity.CRITICAL, Severity.CRITICAL]


def test_hidden_text_and_poisoning_on_different_tools_are_not_combined():
    scored = score(
        finding(VulnClass.HIDDEN_TEXT, tool="a"),
        finding(VulnClass.TOOL_POISONING, "ignore previous", tool="b"),
    )
    assert scored == [Severity.HIGH, Severity.HIGH]


def test_strong_poisoning_is_high_and_weak_is_low():
    assert score(finding(VulnClass.TOOL_POISONING, "<IMPORTANT> do it")) == [Severity.HIGH]
    assert score(finding(VulnClass.TOOL_POISONING, "always must never")) == [Severity.LOW]


def test_credentials_are_high_only_with_network_access():
    url_schema = {"properties": {"url": {"type": "string"}}}
    networked = ServerManifest(server="s", tools=[Tool(name="t", input_schema=url_schema)])
    local = ServerManifest(server="s", tools=[Tool(name="t")])
    harvest = finding(VulnClass.CREDENTIAL_HARVEST)
    assert score(harvest, manifests=[networked]) == [Severity.HIGH]
    assert score(harvest, manifests=[local]) == [Severity.MEDIUM]
    assert score(harvest) == [Severity.MEDIUM]


def test_over_permission_and_shadowing_are_medium():
    assert score(finding(VulnClass.OVER_PERMISSION)) == [Severity.MEDIUM]
    assert score(finding(VulnClass.TOOL_SHADOWING)) == [Severity.MEDIUM]


def test_name_collision_alone_is_low():
    assert score(finding(VulnClass.NAME_COLLISION)) == [Severity.LOW]


def test_input_findings_are_not_mutated():
    original = finding(VulnClass.OVER_PERMISSION)
    assign_severities([original])
    assert original.severity is Severity.LOW


def test_meets_threshold():
    high = finding(VulnClass.HIDDEN_TEXT).model_copy(update={"severity": Severity.HIGH})
    assert meets_threshold(high, Severity.HIGH) and meets_threshold(high, Severity.LOW)
    assert not meets_threshold(high, Severity.CRITICAL)
