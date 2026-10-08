"""Owner: Rithika. Guards the Finding/label contract."""

from pathlib import Path

import yaml

from mcpscan.models import Finding, Location, ServerLabel, Severity, VulnClass

CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "servers"


def test_every_corpus_label_parses():
    labels = sorted(CORPUS.glob("*/label.yaml"))
    assert labels, "no label.yaml files found"
    for path in labels:
        label = ServerLabel.model_validate(yaml.safe_load(path.read_text()))
        assert label.server == path.parent.name, f"{path}: server must equal folder name"


def test_finding_key_matches_label_key():
    f = Finding(
        rule_id="STATIC-001",
        server="01_hidden_instructions",
        tool="get_weather",
        vuln_class=VulnClass.TOOL_POISONING,
        location=Location.DESCRIPTION,
        evidence="<IMPORTANT>",
    )
    assert f.key == ("01_hidden_instructions", "get_weather", VulnClass.TOOL_POISONING)


def test_severity_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank
