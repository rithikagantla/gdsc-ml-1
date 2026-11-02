from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from mcpscan.connect import ConnectError, load_manifest, load_manifest_from_file
from mcpscan.engine import run_rules
from mcpscan.report.console import render

app = typer.Typer(help="Security scanner for MCP servers.", no_args_is_help=True)


def fail(message: str) -> typer.Exit:
    Console(stderr=True).print(f"[red]error:[/red] {escape(message)}", soft_wrap=True)
    return typer.Exit(2)


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def scan(
    ctx: typer.Context,
    url: str = typer.Option(None, help="HTTP(S) URL of a running MCP server."),
    file: Path = typer.Option(None, help="Saved tools/list JSON (e.g. from samples/)."),
) -> None:
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
    render(findings, [manifest])


@app.command()
def bench(
    corpus: Path = typer.Argument(Path("corpus"), help="Corpus folder with servers/*/label.yaml"),
    out: Path = typer.Option(Path("results"), help="Where to write report.md / results.json"),
) -> None:
    raise NotImplementedError("Daniel + Arnav: week 4")


if __name__ == "__main__":
    app()
