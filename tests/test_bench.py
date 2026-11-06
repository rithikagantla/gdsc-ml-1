import asyncio
import json
from pathlib import Path

from mcpscan.bench.matcher import MatchResult
from mcpscan.bench.metrics import compute, precision, recall, to_markdown
from mcpscan.bench.runner import BEGIN, END, _write_report, load_labels, run_benchmark
from mcpscan.models import VulnClass

ROOT = Path(__file__).resolve().parent.parent


def test_zero_denominators_do_not_crash():
    assert precision(0, 0) == 0.0 and recall(0, 0) == 0.0


def test_compute_overall_and_per_class():
    poisoning, hidden = VulnClass.TOOL_POISONING, VulnClass.HIDDEN_TEXT
    result = MatchResult(
        tp={("s", "a", poisoning), ("s", "b", poisoning)},
        fp={("s", "c", poisoning)},
        fn={("s", "d", hidden)},
    )
    metrics = compute(result)
    assert metrics["overall"] == {"tp": 2, "fp": 1, "fn": 1, "precision": 0.667, "recall": 0.667}
    assert metrics["per_class"]["tool_poisoning"]["recall"] == 1.0
    assert metrics["per_class"]["hidden_text"]["recall"] == 0.0
    assert set(metrics["per_class"]) == {vuln_class.value for vuln_class in VulnClass}


def test_to_markdown_has_one_row_per_class_plus_overall():
    table = to_markdown(compute(MatchResult()))
    assert "**Overall**" in table
    assert len(table.splitlines()) == 2 + 1 + len(VulnClass)


def test_report_keeps_hand_written_text(tmp_path):
    path = tmp_path / "report.md"
    path.write_text(f"intro\n{BEGIN}\nold\n{END}\nanalysis\n")
    _write_report(path, "new")
    text = path.read_text()
    assert "intro" in text and "analysis" in text and "new" in text and "old" not in text


def test_report_is_created_when_missing(tmp_path):
    path = tmp_path / "report.md"
    _write_report(path, "new")
    assert BEGIN in path.read_text() and "new" in path.read_text()


def test_labels_cover_every_corpus_server():
    assert len(load_labels(ROOT / "corpus")) == 9


def test_benchmark_runs_and_does_not_fall_below_baseline(tmp_path):
    results = asyncio.run(run_benchmark(ROOT / "corpus", tmp_path))
    assert (tmp_path / "report.md").is_file()
    written = json.loads((tmp_path / "results.json").read_text())
    assert written["overall"] == results["overall"]

    baseline = json.loads((ROOT / "results" / "baseline.json").read_text())["overall"]
    assert results["overall"]["precision"] >= baseline["precision"]
    assert results["overall"]["recall"] >= baseline["recall"]
