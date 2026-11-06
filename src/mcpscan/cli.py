from __future__ import annotations

import asyncio
import json
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from mcpscan import __version__
from mcpscan.bench.runner import run_benchmark
from mcpscan.connect import ConnectError, load_manifest, load_manifest_from_file
from mcpscan.engine import run_rules
from mcpscan.models import Finding, ServerManifest, Severity
from mcpscan.report.console import render
from mcpscan.report.sarif import to_sarif
from mcpscan.rules import ALL_RULES
from mcpscan.severity import meets_threshold

app = typer.Typer(help="Security scanner for MCP servers.", no_args_is_help=True)


class OutputFormat(str, Enum):
    console = "console"
    json = "json"
    sarif = "sarif"


def fail(message: str) -> typer.Exit:
    Console(stderr=True).print(f"[red]error:[/red] {escape(message)}", soft_wrap=True)
    return typer.Exit(2)


def source_file(file: Path | None, command: list[str]) -> Path | None:
    """The file a finding should point at in SARIF: the JSON we read, or the server script."""
    if file:
        return file
    for arg in command[1:]:
        if Path(arg).is_file():
            return Path(arg)
    return None


def to_json(findings: list[Finding], manifest: ServerManifest) -> dict:
    return {
        "mcpscan_version": __version__,
        "server": manifest.server,
        "tools": [t.name for t in manifest.tools],
        "findings": [f.model_dump(mode="json") for f in findings],
    }


def write(text: str, output: Path | None) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    else:
        typer.echo(text)


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def scan(
    ctx: typer.Context,
    url: str = typer.Option(None, help="HTTP(S) URL of a running MCP server."),
    file: Path = typer.Option(None, help="Saved tools/list JSON (e.g. from samples/)."),
    format: OutputFormat = typer.Option(OutputFormat.console, "--format", "-f"),
    output: Path = typer.Option(None, "--output", "-o", help="Write the report to this file."),
    fail_on: Severity = typer.Option(
        None, "--fail-on", help="Exit 1 if any finding is at or above this severity."
    ),
) -> None:
    """Scan one MCP server. Pass a stdio command after `--`."""
    command = ctx.args
    if sum(bool(x) for x in (command, url, file)) != 1:
        raise fail("give exactly one of: a server command after `--`, --url, or --file")

    try:
        if file:
            manifest = load_manifest_from_file(file)
        else:
            manifest = asyncio.run(load_manifest(url or command))
    except ConnectError as exc:
        raise fail(str(exc)) from None

    try:
        findings = run_rules([manifest])
    except NotImplementedError:
        findings = []

    if format == OutputFormat.json:
        write(json.dumps(to_json(findings, manifest), indent=2), output)
    elif format == OutputFormat.sarif:
        sarif = to_sarif(findings, ALL_RULES, source_file(file, command))
        write(json.dumps(sarif, indent=2), output)
    elif output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as fh:
            render(findings, [manifest], Console(file=fh, width=160, color_system=None))
    else:
        render(findings, [manifest])

    if fail_on and any(meets_threshold(f, fail_on) for f in findings):
        raise typer.Exit(1)


@app.command()
def bench(
    corpus: Path = typer.Argument(Path("corpus"), help="Corpus folder with servers/*/label.yaml"),
    out: Path = typer.Option(Path("results"), help="Where to write report.md / results.json"),
) -> None:
    """Scan every corpus server and score the findings against the labels."""
    if not (corpus / "servers").is_dir():
        raise fail(f"no servers/ folder in {corpus}")
    try:
        metrics = asyncio.run(run_benchmark(corpus, out))
    except NotImplementedError:
        raise fail("the benchmark runner is not implemented yet (bench/runner.py)") from None

    console = Console()
    overall = (metrics or {}).get("overall", {})
    if overall:
        console.print(
            f"[bold]precision[/bold] {overall.get('precision', 0):.2f}   "
            f"[bold]recall[/bold] {overall.get('recall', 0):.2f}"
        )
    console.print(f"Report written to {escape(str(out))}/")


if __name__ == "__main__":
    app()
