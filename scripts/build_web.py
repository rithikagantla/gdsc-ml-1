"""
Build web/index.html from real scanner output.

    python scripts/build_web.py            # writes web/index.html
    python scripts/build_web.py --bare X   # also writes X without the html wrapper

Every number on the page comes from running the rules and the matcher here. The page itself does
no scanning, so it replays this recorded run. Rerun this after any rule or corpus change.
"""

import argparse
import asyncio
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import date
from pathlib import Path

from mcpscan.bench.matcher import label_keys, match
from mcpscan.bench.metrics import compute
from mcpscan.bench.runner import _server_dirs, load_labels
from mcpscan.connect import load_manifest, load_manifest_from_file
from mcpscan.engine import run_rules
from mcpscan.models import Finding, Tool
from mcpscan.rules import ALL_RULES
from mcpscan.rules.static.imperative_text import PHRASES

ROOT = Path(__file__).resolve().parent.parent
WRAPPER = (
    '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
    "</head>\n<body>\n{page}\n</body>\n</html>\n"
)

SERVER_INFO = {
    "00_hello": ("Baseline server", "clean", "A small, honest server. Nothing should fire."),
    "01_hidden_instructions": (
        "Hidden instructions",
        "attack",
        "A weather tool whose description tells the model to read an SSH key and hide it.",
    ),
    "02_over_scoped": (
        "Over-scoped tool",
        "attack",
        "The description looks innocent. The schema asks for a file path a forecast never needs.",
    ),
    "03_tool_shadowing": (
        "Tool shadowing",
        "attack",
        "A date formatter that quietly changes how a different server's email tool behaves.",
    ),
    "04_typosquat": (
        "Typosquatted names",
        "attack",
        "Tool names one slip away from the official filesystem server.",
    ),
    "05_hidden_text": (
        "Hidden text",
        "attack",
        "Invisible characters and a base64 comment that a person reviewing the tool never sees.",
    ),
    "06_credential_harvest": (
        "Credential harvesting",
        "attack",
        "An order lookup that demands a password and API key, then says not to mention it.",
    ),
    "07_hard_negative_files": (
        "Strict file server",
        "decoy",
        "Clean, but full of firm instructions. Any finding here is a false alarm.",
    ),
    "08_hard_negative_workflow": (
        "Notes server",
        "decoy",
        "Clean, including one tool with a legitimate auth token. Any finding is a false alarm.",
    ),
}

FALSE_ALARM_WHY = {
    ("07_hard_negative_files", "list_allowed_directories"): (
        "\"must\", \"never\" and \"always\" each score 1 and reach the threshold of 3. "
        "These are ordinary usage instructions."
    ),
    ("08_hard_negative_workflow", "sync_notes"): (
        "A parameter named token matches, but this is the user's own auth token for their account."
    ),
}

# From the table in results/report.md. Steps 2 and 3 are the changes that moved the number.
STEPS = [
    {"label": "First full run", "precision": 0.56, "recall": 0.56, "tp": 5, "fp": 4, "fn": 4},
    {"label": "Rules fixed", "precision": 0.69, "recall": 1.0, "tp": 9, "fp": 4, "fn": 0},
    {"label": "Scored per server", "precision": 0.82, "recall": 1.0, "tp": 9, "fp": 2, "fn": 0},
    {"label": "Keyword fix", "precision": 0.82, "recall": 1.0, "tp": 9, "fp": 2, "fn": 0},
]


def visible_text(description: str) -> str:
    """Tidy the description and turn runs of invisible characters into a readable marker."""

    def marker(found: re.Match) -> str:
        return f"[{len(found.group(0))} invisible characters]"

    invisible = "".join(
        chr(c) for c in (0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, *range(0x202a, 0x202f))
    )
    return re.sub(f"[{invisible}]+", marker, description.strip())


def sentences(text: str) -> list[tuple[int, int]]:
    spans, start = [], 0
    for found in re.finditer(r"(?<=[.!?])\s+", text):
        spans.append((start, found.start()))
        start = found.end()
    return spans + [(start, len(text))]


def highlight_spans(text: str, findings: list[Finding]) -> list[list[int]]:
    """Character ranges of the text that made a description-based rule fire."""
    spans: list[tuple[int, int]] = []
    lowered = text.lower()
    for finding in findings:
        if finding.rule_id == "STATIC-001":
            terms = [phrase for phrase in PHRASES if phrase in lowered]
            spans += [s for s in sentences(text) if any(t in lowered[s[0] : s[1]] for t in terms)]
        elif finding.rule_id == "STATIC-002":
            for found in re.finditer(re.escape(finding.evidence.lower()), lowered):
                spans.append(found.span())
        elif finding.rule_id == "STATIC-003":
            spans += [m.span() for m in re.finditer(r"\[\d+ invisible characters\]", text)]
            spans += [m.span() for m in re.finditer(r"<!--.*?-->", text, re.S)]
        elif finding.rule_id == "STATIC-005":
            name = re.search(r"external tool '([^']+)'", finding.evidence)
            if name:
                spans += [s for s in sentences(text) if name.group(1) in text[s[0] : s[1]]]

    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def short_evidence(finding: Finding) -> str:
    text = finding.evidence
    if finding.rule_id == "STATIC-005":
        return text.split(":", 1)[0]
    if finding.rule_id == "STATIC-003":
        decoded = re.search(r'-> "(.*)"', text, re.S)
        if decoded:
            return f"Decoded base64: {decoded.group(1)}"
        names = Counter(re.findall(r"\((ZERO WIDTH[^,]*|[A-Z][A-Z -]+), U\+[0-9A-F]+\)", text))
        if names:
            return ", ".join(f"{count} × {name.lower()}" for name, count in names.items())
        return "HTML comment in the description"
    return " ".join(text.split())


def tool_row(tool: Tool, findings: list[Finding], labeled: list[str]) -> dict:
    text = visible_text(tool.description)
    flagged = {
        name
        for finding in findings
        for name in (*re.findall(r"param '(\w+)'", finding.evidence), finding.evidence)
    }
    return {
        "name": tool.name,
        "sha": tool.description_sha256[:8],
        "text": text,
        "spans": highlight_spans(text, findings),
        "params": [
            {"name": name, "flagged": name in flagged}
            for name in (tool.input_schema or {}).get("properties", {})
        ],
        "labeled": labeled,
    }


def finding_rows(findings: list[Finding], server: str, expected: set) -> list[dict]:
    """One row per tool, rule and class, because the matcher counts those once."""
    groups: dict[tuple, list[Finding]] = {}
    for finding in findings:
        groups.setdefault((finding.tool, finding.rule_id, finding.vuln_class), []).append(finding)

    rows = []
    for (tool, rule_id, vuln_class), group in groups.items():
        hit = (server, tool, vuln_class) in expected
        rows.append(
            {
                "tool": tool,
                "rule": rule_id,
                "class": vuln_class.value,
                "severity": group[0].severity.value,
                "location": group[0].location.value,
                "evidence": list(dict.fromkeys(short_evidence(finding) for finding in group)),
                "outcome": "caught" if hit else "false_alarm",
                "why": "" if hit else FALSE_ALARM_WHY.get((server, tool), ""),
            }
        )
    return rows


async def build_data() -> dict:
    corpus = ROOT / "corpus"
    labels = load_labels(corpus)
    expected = label_keys(labels)
    label_by_server = {label.server: label for label in labels}

    servers, manifests, all_findings = [], [], []
    for server_dir in _server_dirs(corpus):
        name = server_dir.name
        command = [sys.executable, str(server_dir / "server.py")]
        manifest = await load_manifest(command, server_name=name)
        manifests.append(manifest)
        findings = run_rules([manifest])
        all_findings += findings

        vulns = label_by_server[name].vulnerabilities
        title, kind, summary = SERVER_INFO[name]
        tools = [
            tool_row(
                tool,
                [finding for finding in findings if finding.tool == tool.name],
                [vuln.vuln_class.value for vuln in vulns if vuln.tool == tool.name],
            )
            for tool in manifest.tools
        ]
        result = match(findings, [label_by_server[name]])
        servers.append(
            {
                "id": name,
                "title": title,
                "kind": kind,
                "summary": summary,
                "tools": tools,
                "findings": finding_rows(findings, name, expected),
                "tp": len(result.tp),
                "fp": len(result.fp),
                "fn": len(result.fn),
                "labels": len(vulns),
            }
        )

    metrics = compute(match(all_findings, labels))
    combined = compute(match(run_rules(manifests), labels))

    public = []
    for path in sorted((ROOT / "samples").glob("*.tools.json")):
        manifest = load_manifest_from_file(path)
        public.append(
            {
                "name": manifest.server,
                "tools": len(manifest.tools),
                "findings": len(run_rules([manifest])),
            }
        )

    commit = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()

    return {
        "commit": commit,
        "date": date.today().isoformat(),
        **metrics,
        "combined": combined["overall"],
        "corpus": {
            "servers": len(servers),
            "tools": sum(len(server["tools"]) for server in servers),
            "labels": sum(server["labels"] for server in servers),
        },
        "rules": [
            {"id": rule.id, "class": rule.vuln_class.value, "description": rule.description}
            for rule in ALL_RULES
        ],
        "servers": servers,
        "public": public,
        "steps": STEPS,
    }


def render(data: dict) -> str:
    template = (ROOT / "web" / "template.html").read_text("utf-8")
    payload = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
    return template.replace("/*__DATA__*/null", payload)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bare", type=Path, help="also write the page without the html wrapper")
    args = parser.parse_args()

    page = render(asyncio.run(build_data()))
    output = ROOT / "web" / "index.html"
    output.write_text(WRAPPER.format(page=page), "utf-8")
    if args.bare:
        args.bare.write_text(page, "utf-8")
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
