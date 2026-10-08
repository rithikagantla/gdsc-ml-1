# Contributing

1. Pick up your issue / task from [`TASKS.md`](TASKS.md).
2. `git checkout main && git pull`
3. `git checkout -b <your-name>/<topic>`
4. Write code + tests. Run `ruff check . && pytest` before pushing.
5. Open a PR, request 1 reviewer (any teammate). Link the task.
6. Merge after approval + green CI. Delete your branch.

## Adding a rule (no merge conflicts)
1. Create one file in `src/mcpscan/rules/static/` or `rules/scope/`.
2. Subclass `Rule` from `rules/base.py`; give it a unique `id` (e.g. `STATIC-005`).
3. Add one line to `ALL_RULES` in `src/mcpscan/rules/__init__.py`.
4. Add at least one positive and one negative test in `tests/`.

## Changing `models.py`
`models.py` is the contract between rules, the corpus labels and the benchmark. Changes need
Rithika's review and a heads-up in #ml-1.
