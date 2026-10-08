"""
Metrics — precision and recall, overall and per vulnerability class.

OWNER: Arnav · WEEK 4

    precision = TP / (TP + FP)     "when it flags something, is it right?"  <- headline number
    recall    = TP / (TP + FN)     "does it catch what is there?"

STEPS
    [ ] precision()/recall() return 0.0 (not crash) when the denominator is 0.
    [ ] compute(match_result) -> {"overall": {...}, "per_class": {class: {...}}}
    [ ] to_markdown(metrics) -> table for results/report.md
    [ ] CI regression gate (week 6): compare to results/baseline.json; fail if either drops.
"""

from __future__ import annotations

from mcpscan.bench.matcher import MatchResult


def precision(tp: int, fp: int) -> float:
    return tp / (tp + fp) if (tp + fp) else 0.0


def recall(tp: int, fn: int) -> float:
    return tp / (tp + fn) if (tp + fn) else 0.0


def compute(result: MatchResult) -> dict:
    raise NotImplementedError("Arnav: week 4")


def to_markdown(metrics: dict) -> str:
    raise NotImplementedError("Arnav: week 4")
