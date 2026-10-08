# ML-1 Task Division — MCP Security Scanner

Sprint: Sep 24 → **Nov 12 (Showcase)** · Mentor/Lead: @Rithika · Channel: #ml-1

Every file in this repo starts with a header that says **who owns it, which week it is due,
what to build, and when it counts as done**. Open the file, read the header, delete the
`NotImplementedError`, ship it through a PR.

> Roles are a starting point, not a cage. You will touch code outside your area. The owner is
> the person accountable for that piece shipping. Swap roles in #ml-1 if something fits better.

---

## Who owns what

| Person | Role | Owns (files) |
|---|---|---|
| **Ankitha** | Corpus & ground truth | `corpus/` (all servers + `label.yaml` files), `corpus/docker-compose.yml`, `corpus/Dockerfile` |
| **Raiyan** | Static rules + rule engine | `src/mcpscan/engine.py`, `src/mcpscan/rules/base.py`, `src/mcpscan/rules/__init__.py`, `src/mcpscan/rules/static/*`, `samples/`, `tests/test_static_rules.py`, `tests/test_engine.py` |
| **Arnav** | Scope, severity & benchmark | `src/mcpscan/rules/scope/*`, `src/mcpscan/severity.py`, `src/mcpscan/bench/*`, `bench/triage.yaml`, `docs/threat-model.md`, `results/`, `tests/test_scope.py`, `tests/test_matcher.py` |
| **Daniel** | Connector, CLI & shipping | `src/mcpscan/connect.py`, `src/mcpscan/cli.py`, `src/mcpscan/report/*`, `scripts/list_tools.py`, `pyproject.toml`, `.github/workflows/ci.yml`, `action.yml`, `tests/test_connect.py`, `tests/test_sarif.py` |
| **Rithika** (lead) | Schemas, reviews, stretch | `src/mcpscan/models.py` (schema owner — changes need her approval), `README.md`, `docs/architecture.md`, `src/mcpscan/llm/*` (stretch), pairs on `src/mcpscan/dynamic/*` (stretch) |

Why this split:
- **Ankitha** built `00_hello`, the baseline every corpus server copies from.
- **Raiyan** collected the public `samples/` and already wrote a credential-seeking server — he has the best feel for real vs. suspicious descriptions, which is exactly what static rules need.
- **Arnav** wrote the threat model and the over-scoped filesystem server — scope analysis and measuring results follow directly.
- **Daniel** wrote the connect-and-list script, which becomes `connect.py`; CLI, SARIF and CI are small pieces that sit on top of it.
- With four people, packaging folds into the connector/CLI role (guide: "If we end up with four people, packaging folds into …").

---

## Week-by-week checklist

### Week 3 — Oct 8 · *Static rules v1, finish corpus*
**Done when:** the first rule set prints findings and the corpus is at 6 servers.

- [ ] **Ankitha** — Move Raiyan's and Arnav's branch servers into `corpus/servers/06_credential_harvest/` and `02_over_scoped/` (fix their label files to the agreed schema). Finish `01`, `03`, `04`, `05`. Every server has 1–2 clean decoy tools.
- [ ] **Raiyan** — `rules/base.py` + `engine.py` working. `imperative_text.py` and `credential_terms.py` v1 with tests.
- [ ] **Arnav** — `docs/threat-model.md` finalized. Start `rules/scope/purposes.yaml`.
- [ ] **Daniel** — `connect.py` (`load_manifest`, `load_manifest_from_file`), `mcpscan scan` prints findings via `report/console.py`.
- [ ] **Rithika** — Lock `models.py`; merge open PRs; close stale branches.

### Week 4 — Oct 15 · *Scope, severity, benchmark harness*
**Done when:** over-scoped tools are detected, findings carry a severity, and `mcpscan bench` prints a first precision/recall table.

- [ ] **Ankitha** — Two hard-negative servers (`07`, `08`). `docker compose up` runs everything.
- [ ] **Raiyan** — `hidden_text.py`, `name_collision.py`, `shadowing.py`.
- [ ] **Arnav** — `over_permission.py`, `severity.py`, `bench/matcher.py`, `bench/metrics.py`, `bench/runner.py`.
- [ ] **Daniel** — `mcpscan bench` command; JSON output format.
- [ ] **Rithika** — Decide on cuts (LLM / dynamic) by end of week.

### Week 5 — Oct 22 · *Rule tuning + real-world false positives*
**Done when:** rules are rerun on corpus + `samples/`, and every false positive has a written explanation.

- [ ] **Raiyan** — Tune rules against `samples/`; add allowlists. Every rule has ≥1 positive and ≥1 negative test.
- [ ] **Arnav** — Fill `bench/triage.yaml`; draft error-analysis section of `results/report.md`. (If on track: Snyk agent-scan comparison.)
- [ ] **Ankitha** — Review every FP on the corpus: is the label wrong or the rule wrong? Fix labels.
- [ ] **Daniel** — `report/sarif.py` (SARIF 2.1.0), validate against the schema.
- [ ] **Rithika** — Stretch: start `llm/classifier.py` *only if* the benchmark table exists.

### Week 6 — Oct 29 · *Packaging, CI, report draft, buffer*
**Done when:** `pip install` works, SARIF + CI are green, the results report is drafted.

- [ ] **Daniel** — Move `docs/ci.yml` → `.github/workflows/ci.yml` (needs a GitHub token with `workflow` scope), then `ci.yml` (ruff + pytest + benchmark regression gate), `action.yml`, test `pip install .` in a clean venv.
- [ ] **Arnav** — Commit `results/baseline.json` so CI can fail on regressions. Finish `results/report.md`.
- [ ] **Everyone** — Midterm buffer. Catch up on anything that slipped.

### Week 7 — Nov 5 · *Demo prep and polish*
**Done when:** README with architecture diagram is done, and **every** member can run the 5-minute demo alone.

- [ ] **Rithika** — README + architecture diagram, demo script in `docs/demo.md`.
- [ ] **Everyone** — Run the demo end-to-end on your own machine at least once.

---

## Cut order if we fall behind (decided by week 4)
1. LLM classifier goes first.
2. Dynamic harness goes second (only starts in week 5 if the benchmark table exists).
3. **The benchmark never gets cut.**

## Hard rule
Adversarial probes run **only** against servers we wrote (`corpus/`). Public servers get static,
read-only analysis — list tools, never call them.
