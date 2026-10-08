"""
Benchmark runner — scan every corpus server and score the results.

OWNER: Arnav · WEEK 4

STEPS
    [ ] Find corpus/servers/*/ that contain both server.py and label.yaml.
    [ ] For each: load ServerLabel from label.yaml; load_manifest(["python", server.py]).
    [ ] Run engine.run_rules over ALL manifests together (collision rules need the full set).
    [ ] matcher.match(findings, labels) -> MatchResult
    [ ] metrics.compute(match_result) -> overall + per-class precision/recall
    [ ] Write results/results.json (machine-readable, so CI can compare to baseline.json)
        and results/report.md (tables + FP list).
    [ ] One command regenerates everything: `mcpscan bench corpus/`.
"""

from __future__ import annotations

from pathlib import Path

from mcpscan.models import ServerLabel


def load_labels(corpus_dir: Path) -> list[ServerLabel]:
    raise NotImplementedError("Arnav: week 4")


async def run_benchmark(corpus_dir: Path, out_dir: Path) -> dict:
    raise NotImplementedError("Arnav: week 4 — see module docstring")
