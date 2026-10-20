import io
import json
import sys
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from mcpscan import cli
from mcpscan.cli import app
from mcpscan.models import Finding, Location, ServerManifest, Severity, Tool, VulnClass
from mcpscan.report.console import render, short_evidence, summary_line

HELLO = Path(__file__).parent.parent / "corpus" / "servers" / "00_hello" / "server.py"
runner = CliRunner()


def finding(severity=Severity.LOW, tool="t0", evidence="bad"):
    return Finding(
        rule_id="STATIC-001",
        server="s",
        tool=tool,
        vuln_class=VulnClass.TOOL_POISONING,
        location=Location.DESCRIPTION,
        severity=severity,
        evidence=evidence,
    )


def sample_file(tmp_path):
    path = tmp_path / "x.tools.json"
    path.write_text(json.dumps({"tools": [{"name": "a", "inputSchema": {}}]}))
    return str(path)


def test_summary_line():
    findings = [finding(Severity.HIGH), finding(Severity.HIGH, "t1"), finding(Severity.LOW)]
    assert summary_line(findings) == "3 findings (0 critical, 2 high, 0 medium, 1 low)"


def test_evidence_shows_hidden_chars_and_is_truncated():
    assert "\\u200b" in short_evidence("a​b")
    assert len(short_evidence("x" * 500)) == 80


def test_render_sorts_worst_first_and_escapes_markup():
    out = io.StringIO()
    findings = [finding(evidence="[bold]low"), finding(Severity.CRITICAL, "t1", "<IMPORTANT>")]
    manifest = ServerManifest(server="s", tools=[Tool(name="t0"), Tool(name="t1")])
    render(findings, [manifest], Console(file=out, width=140, color_system=None))
    text = out.getvalue()
    assert text.index("CRITICAL") < text.index("LOW")
    assert "<IMPORTANT>" in text and "[bold]low" in text and "s: 2 tools" in text


def test_render_no_findings():
    out = io.StringIO()
    render([], None, Console(file=out, color_system=None))
    assert "No findings" in out.getvalue()


def test_scan_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run_rules", lambda manifests: [])
    result = runner.invoke(app, ["scan", "--file", sample_file(tmp_path)])
    assert result.exit_code == 0
    assert "1 tool" in result.output and "No findings" in result.output


def test_scan_live_hello_server(monkeypatch):
    monkeypatch.setattr(cli, "run_rules", lambda manifests: [])
    result = runner.invoke(app, ["scan", "--", sys.executable, str(HELLO)])
    assert result.exit_code == 0
    assert "2 tools" in result.output and "No findings" in result.output


def test_scan_works_before_engine_exists(tmp_path):
    assert runner.invoke(app, ["scan", "--file", sample_file(tmp_path)]).exit_code == 0


def test_bad_server_is_one_friendly_line():
    result = runner.invoke(app, ["scan", "--", "definitely-not-a-real-binary-xyz"])
    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert len([line for line in result.output.splitlines() if line.strip()]) == 1


def test_needs_exactly_one_source(tmp_path):
    assert runner.invoke(app, ["scan"]).exit_code == 2
    both = ["scan", "--file", sample_file(tmp_path), "--", "python", "x.py"]
    assert runner.invoke(app, both).exit_code == 2


def test_scan_json_output(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run_rules", lambda manifests: [finding(Severity.HIGH)])
    out = tmp_path / "out" / "r.json"
    args = ["scan", "--file", sample_file(tmp_path), "-f", "json", "-o", str(out)]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["server"] == "x" and data["tools"] == ["a"]
    assert data["findings"][0]["severity"] == "high"


def test_scan_sarif_to_stdout_points_at_source_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run_rules", lambda manifests: [finding()])
    path = sample_file(tmp_path)
    result = runner.invoke(app, ["scan", "--file", path, "--format", "sarif"])
    assert result.exit_code == 0
    sarif = json.loads(result.output)
    location = sarif["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"].endswith("x.tools.json")


def test_fail_on_threshold(tmp_path, monkeypatch):
    path = sample_file(tmp_path)
    monkeypatch.setattr(cli, "run_rules", lambda manifests: [finding(Severity.MEDIUM)])
    assert runner.invoke(app, ["scan", "--file", path, "--fail-on", "high"]).exit_code == 0
    assert runner.invoke(app, ["scan", "--file", path, "--fail-on", "medium"]).exit_code == 1


def test_console_output_to_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run_rules", lambda manifests: [])
    out = tmp_path / "report.txt"
    args = ["scan", "--file", sample_file(tmp_path), "-o", str(out)]
    assert runner.invoke(app, args).exit_code == 0
    assert "No findings" in out.read_text()


def test_bench_before_runner_exists_is_friendly(tmp_path):
    (tmp_path / "servers").mkdir()
    result = runner.invoke(app, ["bench", str(tmp_path)])
    assert result.exit_code == 2 and "Traceback" not in result.output


def test_bench_prints_metrics(tmp_path, monkeypatch):
    (tmp_path / "servers").mkdir()

    async def fake_run(corpus, out):
        return {"overall": {"precision": 0.75, "recall": 0.5}}

    monkeypatch.setattr(cli, "run_benchmark", fake_run)
    result = runner.invoke(app, ["bench", str(tmp_path), "--out", str(tmp_path / "r")])
    assert result.exit_code == 0
    assert "0.75" in result.output and "0.50" in result.output
