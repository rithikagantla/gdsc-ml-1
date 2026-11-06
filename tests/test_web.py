import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from build_web import build_data, highlight_spans, render, visible_text  # noqa: E402

from mcpscan.models import Finding, Location, VulnClass  # noqa: E402


def finding(rule_id, evidence):
    return Finding(
        rule_id=rule_id,
        server="s",
        tool="t",
        vuln_class=VulnClass.HIDDEN_TEXT,
        location=Location.DESCRIPTION,
        evidence=evidence,
    )


def test_invisible_characters_become_a_visible_marker():
    assert visible_text("Hi.\u200b\u200b\u200b") == "Hi.[3 invisible characters]"


def test_highlight_spans_merge_and_cover_the_comment():
    text = visible_text("Hi.\u200b\u200b<!-- x -->")
    spans = highlight_spans(text, [finding("STATIC-003", "x")])
    assert spans == [[3, len(text)]]


def test_page_data_matches_the_committed_benchmark():
    data = asyncio.run(build_data())
    results = json.loads((ROOT / "results" / "results.json").read_text())
    assert data["overall"] == results["overall"]
    assert data["per_class"] == results["per_class"]
    assert data["combined"] == results["combined_scan"]["overall"]
    assert sum(server["tp"] for server in data["servers"]) == data["overall"]["tp"]
    assert sum(server["fp"] for server in data["servers"]) == data["overall"]["fp"]


def test_rendered_page_embeds_data_without_breaking_the_script():
    page = render(asyncio.run(build_data()))
    assert "/*__DATA__*/" not in page
    assert page.count("</script>") == 1
    assert "\\u003cIMPORTANT>" in page
