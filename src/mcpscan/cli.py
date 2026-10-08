"""
CLI — `mcpscan scan` and `mcpscan bench`.

OWNER: Daniel · WEEK 3 (scan) / WEEK 4 (bench) / WEEK 6 (polish)

TARGET USAGE
    mcpscan scan -- python server.py
    mcpscan scan --url http://localhost:8000/mcp
    mcpscan scan --file samples/filesystem.tools.json
    mcpscan scan ... --format console|json|sarif --output out.sarif --fail-on high
    mcpscan bench corpus/ --out results/

STEPS
    [ ] scan: build the manifest (connect.load_manifest / load_manifest_from_file),
        run engine.run_rules, print via report.console / report.sarif / JSON.
    [ ] --fail-on: exit code 1 if any finding meets the threshold (this is what lets CI block a PR).
    [ ] Catch connect.ConnectError and print a one-line red error, exit code 2.
    [ ] bench: call mcpscan.bench.runner.run_benchmark and print the metrics table.
    [ ] tests: use typer.testing.CliRunner with --file on a sample JSON.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import typer

app = typer.Typer(help="Security scanner for MCP servers.", no_args_is_help=True)


class OutputFormat(str, Enum):
    console = "console"
    json = "json"
    sarif = "sarif"


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def scan(
    ctx: typer.Context,
    url: str = typer.Option(None, help="HTTP(S) URL of a running MCP server."),
    file: Path = typer.Option(None, help="Saved tools/list JSON (e.g. from samples/)."),
    format: OutputFormat = typer.Option(OutputFormat.console, "--format", "-f"),
    output: Path = typer.Option(None, "--output", "-o", help="Write report to this file."),
    fail_on: str = typer.Option(None, help="Exit 1 if any finding is >= this severity."),
) -> None:
    """Scan one MCP server. Pass a stdio command after `--`."""
    _command = ctx.args  # e.g. ["python", "server.py"]
    raise NotImplementedError("Daniel: week 3 — see module docstring")


@app.command()
def bench(
    corpus: Path = typer.Argument(Path("corpus"), help="Corpus folder with servers/*/label.yaml"),
    out: Path = typer.Option(Path("results"), help="Where to write report.md / results.json"),
) -> None:
    """Run the benchmark: scan every corpus server and score findings against labels."""
    raise NotImplementedError("Daniel + Arnav: week 4")


if __name__ == "__main__":
    app()
