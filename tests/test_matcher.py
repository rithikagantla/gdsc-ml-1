
"""Tests for the benchmark matcher."""

from mcpscan.bench.matcher import match
from mcpscan.models import Finding, LabeledVuln, Location, ServerLabel, VulnClass


def make_labels() -> list[ServerLabel]:
    """Create ground truth for our over-scoped test server."""
    return [
        ServerLabel(
            server="02_over_scoped",
            vulnerabilities=[
                LabeledVuln(
                    tool="get_forecast",
                    vuln_class=VulnClass.OVER_PERMISSION,
                    location=Location.SCHEMA,
                )
            ],
        )
    ]


def make_finding(tool: str, evidence: str = "Suspicious parameter") -> Finding:
    """Create a simulated scanner finding."""
    return Finding(
        rule_id="SCOPE-001",
        server="02_over_scoped",
        tool=tool,
        vuln_class=VulnClass.OVER_PERMISSION,
        location=Location.SCHEMA,
        evidence=evidence,
    )


def test_true_positive():
    """Correctly detecting a labeled vulnerability gives one TP."""
    finding = make_finding("get_forecast")

    result = match([finding], make_labels())

    assert len(result.tp) == 1
    assert len(result.fp) == 0
    assert len(result.fn) == 0


def test_duplicates_count_once():
    """Repeated findings for the same vulnerability count once."""
    first = make_finding("get_forecast", "Unrestricted path")
    second = make_finding("get_forecast", "Destructive hint")

    result = match([first, second], make_labels())

    assert len(result.tp) == 1
    assert len(result.fp) == 0
    assert len(result.fn) == 0


def test_unlabeled_tool_is_false_positive():
    """Flagging a clean decoy tool creates an FP."""
    finding = make_finding("convert_temperature")

    result = match([finding], make_labels())

    assert len(result.tp) == 0
    assert len(result.fp) == 1
    assert len(result.fn) == 1
    assert result.fp_findings == [finding]


def test_missed_label_is_false_negative():
    """A vulnerability with no matching finding becomes an FN."""
    result = match([], make_labels())

    assert len(result.tp) == 0
    assert len(result.fp) == 0
    assert len(result.fn) == 1


def test_duplicate_false_positives_preserve_first_finding():
    """Duplicate false alarms count once and retain original evidence."""
    first = make_finding("convert_temperature", "First evidence")
    second = make_finding("convert_temperature", "Second evidence")

    result = match([first, second], make_labels())

    assert len(result.fp) == 1
    assert len(result.fp_findings) == 1
    assert result.fp_findings[0] is first
