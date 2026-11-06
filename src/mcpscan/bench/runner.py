"""
Benchmark runner: scan every corpus server, score against the labels, write the results.

Each corpus server is scored on its own, because they are independent test cases that are never
installed together. Scanning them as one set would make shared decoy names (`get_weather` in 00
and 01) look like collisions, so that run is reported separately as `combined_scan`.

`results/report.md` keeps its hand-written analysis: only the text between the GENERATED markers
is replaced on each run.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import yaml

from mcpscan.bench.matcher import MatchResult, match
from mcpscan.bench.metrics import compute, to_markdown
from mcpscan.connect import load_manifest, load_manifest_from_file
from mcpscan.engine import run_rules
from mcpscan.models import Finding, ServerLabel, ServerManifest

BEGIN = "<!-- BEGIN GENERATED: mcpscan bench -->"
END = "<!-- END GENERATED -->"


def _server_dirs(corpus_dir: Path) -> list[Path]:
    return [
        path.parent
        for path in sorted((corpus_dir / "servers").glob("*/label.yaml"))
        if (path.parent / "server.py").is_file()
    ]


def load_labels(corpus_dir: Path) -> list[ServerLabel]:
    return [
        ServerLabel.model_validate(yaml.safe_load((path / "label.yaml").read_text("utf-8")))
        for path in _server_dirs(corpus_dir)
    ]


def _finding_row(finding: Finding) -> dict:
    return {
        "server": finding.server,
        "tool": finding.tool,
        "class": finding.vuln_class.value,
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "evidence": finding.evidence,
    }


def _key_rows(keys: set) -> list[dict]:
    rows = [{"server": s, "tool": t, "class": c.value} for s, t, c in keys]
    return sorted(rows, key=lambda row: (row["server"], row["tool"], row["class"]))


def _score(findings: list[Finding], labels: list[ServerLabel]) -> tuple[MatchResult, dict]:
    result = match(findings, labels)
    return result, compute(result)


def _real_world(samples_dir: Path) -> dict | None:
    """Static findings on saved public tools/list JSON. There are no labels to score these."""
    paths = sorted(samples_dir.glob("*.tools.json"))
    if not paths:
        return None
    findings: list[Finding] = []
    tools = 0
    for path in paths:
        manifest = load_manifest_from_file(path)
        tools += len(manifest.tools)
        findings += run_rules([manifest])
    return {
        "servers": len(paths),
        "tools": tools,
        "findings": [_finding_row(finding) for finding in findings],
    }


def _generated_section(results: dict) -> str:
    corpus = results["corpus"]
    combined = results["combined_scan"]["overall"]
    lines = [
        f"Corpus: {corpus['servers']} servers, {corpus['tools']} tools, "
        f"{corpus['labeled_vulnerabilities']} labeled vulnerabilities.",
        "",
        to_markdown(results),
        "",
        f"All servers scanned as one set instead: precision {combined['precision']:.2f}, "
        f"recall {combined['recall']:.2f} ({combined['fp']} false positives).",
        "",
        "### False positives",
        "",
        "| Server | Tool | Class | Rule | Severity | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for row in results["false_positives"]:
        evidence = " ".join(row["evidence"].split()).replace("|", "\\|")[:100]
        lines.append(
            f"| {row['server']} | {row['tool']} | {row['class']} | {row['rule_id']} "
            f"| {row['severity']} | {evidence} |"
        )
    lines += ["", "### False negatives", ""]
    missed = results["false_negatives"]
    lines += [f"- {r['server']} / {r['tool']} / {r['class']}" for r in missed] or ["None."]
    if results["real_world"]:
        world = results["real_world"]
        lines += [
            "",
            "### Public samples (unlabeled)",
            "",
            f"{len(world['findings'])} findings across {world['tools']} tools "
            f"on {world['servers']} servers.",
        ]
    return "\n".join(lines)


def _write_report(path: Path, section: str) -> None:
    block = f"{BEGIN}\n{section}\n{END}"
    if path.is_file():
        text = path.read_text("utf-8")
        before, _, rest = text.partition(BEGIN)
        _, _, after = rest.partition(END)
        path.write_text(f"{before}{block}{after}", "utf-8")
    else:
        path.write_text(f"# Benchmark results\n\n{block}\n", "utf-8")


async def run_benchmark(corpus_dir: Path, out_dir: Path) -> dict:
    labels = load_labels(corpus_dir)
    manifests: list[ServerManifest] = []
    for server_dir in _server_dirs(corpus_dir):
        command = [sys.executable, str(server_dir / "server.py")]
        manifests.append(await load_manifest(command, server_name=server_dir.name))

    findings = [finding for manifest in manifests for finding in run_rules([manifest])]
    result, metrics = _score(findings, labels)
    _, combined = _score(run_rules(manifests), labels)

    results = {
        **metrics,
        "corpus": {
            "servers": len(manifests),
            "tools": sum(len(manifest.tools) for manifest in manifests),
            "labeled_vulnerabilities": sum(len(label.vulnerabilities) for label in labels),
        },
        "severity_counts": dict(sorted(Counter(f.severity.value for f in findings).items())),
        "false_positives": [_finding_row(finding) for finding in result.fp_findings],
        "false_negatives": _key_rows(result.fn),
        "combined_scan": combined,
        "real_world": _real_world(corpus_dir.resolve().parent / "samples"),
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n", "utf-8")
    _write_report(out_dir / "report.md", _generated_section(results))
    return results
