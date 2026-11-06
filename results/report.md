# MCP Security Scanner: benchmark results

**mcpscan finds all 9 labeled vulnerabilities in our corpus (recall 1.00), and 9 of its 11 flags on
that corpus are correct (precision 0.82).** On 36 tools from 3 public servers it raises no findings.
These numbers measure our own 9-server corpus, not MCP servers in general. See
[What these numbers do not show](#what-these-numbers-do-not-show).

Regenerate the tables with `mcpscan bench corpus/`. Only the section between the GENERATED markers
changes; the analysis around it is written by hand.

## Results

<!-- BEGIN GENERATED: mcpscan bench -->
Corpus: 9 servers, 23 tools, 9 labeled vulnerabilities.

| Class | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| **Overall** | 9 | 2 | 0 | 0.82 | 1.00 |
| tool_poisoning | 2 | 1 | 0 | 0.67 | 1.00 |
| tool_shadowing | 1 | 0 | 0 | 1.00 | 1.00 |
| name_collision | 2 | 0 | 0 | 1.00 | 1.00 |
| over_permission | 1 | 0 | 0 | 1.00 | 1.00 |
| hidden_text | 1 | 0 | 0 | 1.00 | 1.00 |
| credential_harvest | 2 | 1 | 0 | 0.67 | 1.00 |

All servers scanned as one set instead: precision 0.69, recall 1.00 (4 false positives).

### False positives

| Server | Tool | Class | Rule | Severity | Evidence |
|---|---|---|---|---|---|
| 07_hard_negative_files | list_allowed_directories | tool_poisoning | STATIC-001 | low | You must call this before read_text_file or write_file if you are unsure which directories are acces |
| 08_hard_negative_workflow | sync_notes | credential_harvest | STATIC-002 | medium | token |

### False negatives

None.

### Public samples (unlabeled)

0 findings across 36 tools on 3 servers.
<!-- END GENERATED -->

## How the number moved

Every step is listed so the tuning can be checked. Steps 2 to 4 were made after looking at
corpus results, which is why the final numbers are not an independent test.

| Step | Change | Precision | Recall | TP / FP / FN |
|---|---|---|---|---|
| 1 | First full run: five static rules, no scope rule | 0.56 | 0.56 | 5 / 4 / 4 |
| 2 | Engine loads the popular-name list; `send_email` added to it; SCOPE-001 added | 0.69 | 1.00 | 9 / 4 / 0 |
| 3 | Score each server on its own instead of as one set | 0.82 | 1.00 | 9 / 2 / 0 |
| 4 | Removed `add` from the math keywords (public samples only: 2 findings to 0) | 0.82 | 1.00 | 9 / 2 / 0 |

Why each change was made:

- **Step 2, popular names.** The rule that catches typosquats was written, but the engine never
  gave it the list of names to compare against, so it could not fire. This fixed `read_flie` and
  `list_directroy`.
- **Step 2, `send_email`.** Shadowing only recognises tools it knows about. `send_email` was added
  to a list of common action tools *after* `03_tool_shadowing` was missed, so that detection is not
  independent evidence. A real attacker naming a tool outside the list would still get through.
- **Step 3, scoring per server.** This is a choice about method, and it improves the number, so it
  is shown openly: scanned as one set, precision is 0.69. Corpus servers are separate test cases
  and are never installed together, so a decoy `get_weather` shared by `00` and `01` is not a real
  collision. The cost is that the benchmark no longer exercises exact cross-server collisions;
  only unit tests cover them.

## False positives

Both labels were reviewed and are correct: these tools are clean, so the rules are wrong. Neither
was tuned away, because the fix should be general rather than fitted to these two tools. Tracked
in #18.

| Finding | Why the rule fired | Rule change to consider |
|---|---|---|
| `07` `list_allowed_directories`, tool_poisoning (low) | "must", "never" and "always" each score 1, reaching the threshold of 3. All three are ordinary usage instructions | Stop weak words reaching the threshold alone; require one strong phrase. Severity already rates this low |
| `08` `sync_notes`, credential_harvest (medium) | A parameter named `token` matches, and the rule cannot tell that this is the user's own auth token | Have the scope check decide whether a token fits the purpose, as the sprint guide proposed |

## Corpus review

All 9 labels (on 7 tools) were checked against the tools they describe, and all 16 unlabeled tools were reviewed
as clean. No label changed. Two earlier decisions affect the count: `01` is labeled for both
tool_poisoning and credential_harvest because the same hidden block does both, and `06` is labeled
for both because its description also pressures the model to collect the password.

## Public servers

The first SCOPE-001 run flagged 2 of 36 tools, both on `memory` and both false positives
(`bench/triage.yaml`). The keyword `add` had classified tools that add graph data as math. After
removing it there are no findings. No real vulnerability was found in a public server.

Zero findings is a good sign for false alarms, but a weak one: all three servers come from the same
official reference project and are written to be well behaved.

## What these numbers do not show

- **The corpus is small and ours.** Nine labels and 23 tools, written by the same team that wrote
  the rules. One wrong call changes precision by about 8 points.
- **Rules were tuned on this corpus.** There is no held-out test set. Recall of 1.00 means "catches
  the attacks we thought of", not "catches attacks".
- **No external comparison yet.** Snyk agent-scan and mcp-guardbench were not run. We make no claim
  of beating other scanners, and the 33-server audit (6 of 27 detections genuine) used different
  servers, so its figure cannot be compared with ours.
- **Static only.** Rug pulls and output injection need the dynamic harness, which is not built.
- **Not everything fires.** No corpus finding reaches Critical, because `05` hides its instruction
  in base64 and STATIC-001 does not read the decoded text. That is a real detection gap.
