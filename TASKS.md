# ML-1 project status

Sprint Sep 24 to **Nov 12 (Showcase)**. Lead and mentor: Rithika.

| Deliverable | Status |
|---|---|
| Installable CLI with console, JSON and SARIF output | Done |
| Labeled corpus: 9 servers, 23 tools, 9 labeled vulnerabilities | Done |
| Six rules, severity scoring, benchmark | Done |
| Results report with error analysis | Done: [`results/report.md`](results/report.md) |
| Project website | Done: <https://rithikagantla.github.io/mcp-scanner/> |
| CI: lint, tests, baseline check | Done: `tests/test_bench.py` fails if precision or recall drop |
| Five-minute demo | Done: [`docs/demo.md`](docs/demo.md) |

## Who built what

| Person | Area |
|---|---|
| Ankitha | Corpus and ground truth |
| Raiyan | Static rules, rule engine, public samples |
| Arnav | Threat model, over-scoped server, matcher |
| Daniel | Connector, scan CLI, console report |
| Rithika | Schemas, SARIF and JSON output, scope and severity, benchmark, report, website, reviews |

## Decisions

- **Stretch goals cut:** the LLM classifier and the dynamic harness. The benchmark came first.
- **Rules frozen:** the two remaining false positives stay in the score and are explained in the
  report. Tuning them away this close to the showcase would only fit the rules to our own corpus.

## Hard rule

Adversarial probes run **only** against servers we wrote (`corpus/`). Public servers get static,
read-only analysis: list tools, never call them.
