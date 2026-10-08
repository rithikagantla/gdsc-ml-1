"""
Dynamic harness — STRETCH GOAL. Only start if the benchmark table exists by week 5.

OWNER: Rithika + pair (whoever finishes their core work first) · WEEK 5–6

HARD RULE
    Runs ONLY against our own corpus servers, inside Docker with networking turned off
    (`network_mode: none`). Never against public servers.

CHECKS (what static rules cannot see)
    1. Rug pull: list tools, call one tool, list tools again; compare description_sha256.
       A changed description -> Finding(location=BEHAVIOR, vuln_class=TOOL_POISONING).
    2. Output injection: call each tool with harmless inputs (probes/), then run the
       imperative_text and hidden_text rules on the *results*.

Findings use Location.BEHAVIOR so they flow into the same benchmark.
"""

from __future__ import annotations

from mcpscan.models import Finding


async def run_dynamic(server_command: list[str]) -> list[Finding]:
    raise NotImplementedError("Stretch: week 5+")
