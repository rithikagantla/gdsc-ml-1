from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from mcpscan.models import Finding, ServerManifest, Severity

STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}


def short_evidence(evidence: str, width: int = 80) -> str:
    text = repr(evidence)
    return text if len(text) <= width else text[: width - 3] + "..."


def summary_line(findings: list[Finding]) -> str:
    count = {s: sum(f.severity == s for f in findings) for s in Severity}
    n = len(findings)
    return (
        f"{n} {'finding' if n == 1 else 'findings'} "
        f"({count[Severity.CRITICAL]} critical, {count[Severity.HIGH]} high, "
        f"{count[Severity.MEDIUM]} medium, {count[Severity.LOW]} low)"
    )


def render(
    findings: list[Finding],
    manifests: list[ServerManifest] | None = None,
    console: Console | None = None,
) -> None:
    console = console or Console()

    for m in manifests or []:
        n = len(m.tools)
        console.print(f"[bold]{escape(m.server)}[/bold]: {n} {'tool' if n == 1 else 'tools'}")
        console.print(f"  {escape(', '.join(t.name for t in m.tools))}", style="dim")

    if not findings:
        console.print("[green]No findings.[/green]")
        return

    table = Table(header_style="bold")
    for column in ("Severity", "Rule", "Server", "Tool", "Class", "Evidence"):
        table.add_column(column, overflow="fold")
    for f in sorted(findings, key=lambda f: (-f.severity.rank, f.server, f.tool, f.rule_id)):
        table.add_row(
            f"[{STYLES[f.severity]}]{f.severity.value.upper()}[/]",
            escape(f.rule_id),
            escape(f.server),
            escape(f.tool),
            f.vuln_class.value,
            escape(short_evidence(f.evidence)),
        )
    console.print(table)
    console.print(f"[bold]{summary_line(findings)}[/bold]")
