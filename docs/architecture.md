# Architecture

**OWNER: Rithika** · WEEK 7 — polish into the README diagram for the showcase.

Pipeline: **connect → ServerManifest → rule engine → findings (+severity) → console / SARIF / benchmark**.

## The two contracts
1. **Finding** (`models.Finding`): `rule_id, server, tool, vuln_class, location, severity, evidence`
2. **Label** (`corpus/servers/*/label.yaml` → `models.ServerLabel`): `server, vulnerabilities[tool, class, location, note]`

The benchmark matches them on `(server, tool, vuln_class)`.

## Dependency layers (nobody waits on work that has not started)
| Layer | Components | Weeks | Owners |
|---|---|---|---|
| Core | models, connector, rule engine | 1–3 | Rithika, Daniel, Raiyan |
| Detection | static rules, scope, severity | 3–4 | Raiyan, Arnav |
| Measurement | corpus, matcher, metrics, triage | 2–5 | Ankitha, Arnav |
| Shipping | CLI, SARIF, CI, Action | 3–7 | Daniel |

## TODO (Rithika)
- [ ] `docs/demo.md`: the 5-minute demo script every member can run alone.
