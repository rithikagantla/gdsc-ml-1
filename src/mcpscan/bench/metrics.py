"""
Metrics — precision and recall, overall and per vulnerability class.

OWNER: Arnav · WEEK 4

    precision = TP / (TP + FP)     "when it flags something, is it right?"  <- headline number
    recall    = TP / (TP + FN)     "does it catch what is there?"
"""

from __future__ import annotations

from mcpscan.bench.matcher import MatchResult
from mcpscan.models import VulnClass


def precision(tp: int, fp: int) -> float:
    return tp / (tp + fp) if (tp + fp) else 0.0


def recall(tp: int, fn: int) -> float:
    return tp / (tp + fn) if (tp + fn) else 0.0


def _row(tp: int, fp: int, fn: int) -> dict:
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision(tp, fp), 3),
        "recall": round(recall(tp, fn), 3),
    }


def compute(result: MatchResult) -> dict:
    per_class = {
        vuln_class.value: _row(
            sum(key[2] is vuln_class for key in result.tp),
            sum(key[2] is vuln_class for key in result.fp),
            sum(key[2] is vuln_class for key in result.fn),
        )
        for vuln_class in VulnClass
    }
    overall = _row(len(result.tp), len(result.fp), len(result.fn))
    return {"overall": overall, "per_class": per_class}


def to_markdown(metrics: dict) -> str:
    rows = [("**Overall**", metrics["overall"]), *metrics["per_class"].items()]
    lines = ["| Class | TP | FP | FN | Precision | Recall |", "|---|---|---|---|---|---|"]
    for name, row in rows:
        lines.append(
            f"| {name} | {row['tp']} | {row['fp']} | {row['fn']} "
            f"| {row['precision']:.2f} | {row['recall']:.2f} |"
        )
    return "\n".join(lines)
