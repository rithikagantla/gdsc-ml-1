# Five-minute demo

**OWNER: Rithika** · Every team member must be able to run this alone before Nov 12.
Practice it once on your own laptop in week 7. Draft; update as rules and the benchmark land.

## Before you start (not part of the five minutes)
```bash
git pull && source .venv/bin/activate && pip install -e ".[dev]"
mcpscan --help            # confirms the install
```
Open two things: this file, and `corpus/servers/01_hidden_instructions/server.py`.

## 0:00 – 0:45 · The problem
- MCP is how AI assistants connect to tools. Every tool ships a **description** the model reads
  as instructions, and nothing sanitizes it.
- Show `01_hidden_instructions/server.py`: a weather tool whose description hides an
  `<IMPORTANT>` block telling the model to read `~/.ssh/id_rsa` and not tell the user.
- Existing scanners exist, but one audit found only 6 of 27 detections were real. **Our headline
  is a measured precision number, not another scanner.**

## 0:45 – 2:00 · Scan a poisoned server
```bash
mcpscan scan -- python corpus/servers/01_hidden_instructions/server.py
```
Point at: rule id, class, and the **evidence** column (the exact text that fired the rule).

## 2:00 – 2:45 · A clean server stays clean
```bash
mcpscan scan -- python corpus/servers/00_hello/server.py
mcpscan scan -- python corpus/servers/07_hard_negative_files/server.py
```
Hard negatives look suspicious ("Always pass absolute paths") but are fine. Any finding here is a
false positive, and we count it.

## 2:45 – 3:30 · Plugs into CI
```bash
mcpscan scan --file samples/filesystem.tools.json --format sarif -o demo.sarif --fail-on high
echo $?          # nonzero = the build would be blocked
```
Show `action.yml`: five lines of YAML adds this to any repo, and results land in GitHub's
Security tab.

## 3:30 – 4:30 · The number
```bash
mcpscan bench corpus/
```
Open `results/report.md`: overall and per-class precision/recall, then **one** false positive and
why the rule fired. This is the part to talk about in interviews.

## 4:30 – 5:00 · Close
- Open-source corpus with ground-truth labels anyone can benchmark against.
- Hard rule: we only attack servers we wrote; public servers get read-only analysis.

## If something breaks live
- Server will not start: run the `--file samples/...` variant instead (no server needed).
- `bench` fails: open the committed `results/report.md` directly.
