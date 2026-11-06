# Five-minute demo

**OWNER: Rithika** · Every team member must be able to run this alone before Nov 12. Every command
here was run against `main`. Use a terminal at least 120 columns wide so the tables stay readable.

## Before you start (not part of the five minutes)
```bash
git pull && source .venv/bin/activate && pip install -e ".[dev]"
mcpscan --help            # confirms the install
```
Open two things: this file, and `corpus/servers/01_hidden_instructions/server.py`.

## 0:00 – 0:45 · The problem
- MCP is how AI assistants connect to tools. Every tool ships a **description** the model reads as
  instructions, and nothing sanitizes it.
- Show `01_hidden_instructions/server.py`: a weather tool whose description hides an `<IMPORTANT>`
  block telling the model to read `~/.ssh/id_rsa` and not tell the user.
- Scanners already exist, but one audit found only 6 of 27 detections were genuine. **Our headline
  is a measured precision number, not another scanner.**

## 0:45 – 1:45 · Catch the attack
```bash
mcpscan scan -- python corpus/servers/01_hidden_instructions/server.py
```
Point at three columns: severity (HIGH), class, and **evidence**, the exact text that fired the
rule. Then show it is more than text matching: this next server has an innocent description, and
the problem is in its parameters. A weather tool should not need a file path.
```bash
mcpscan scan -- python corpus/servers/02_over_scoped/server.py
```

## 1:45 – 2:30 · Clean stays clean, and we admit our mistakes
```bash
mcpscan scan -- python corpus/servers/00_hello/server.py
mcpscan scan -- python corpus/servers/07_hard_negative_files/server.py
```
`00_hello` is clean: no findings. `07` is clean too but is written to look suspicious, and our
scanner **wrongly** flags it. Do not hide this. This is the false positive we count in the number,
and the severity is only LOW.

## 2:30 – 3:15 · It blocks bad code in CI
```bash
mcpscan scan --format sarif -o demo.sarif --fail-on high -- python corpus/servers/01_hidden_instructions/server.py
echo $?          # 1 = the build is blocked
```
Show `action.yml`: a few lines of YAML add this to any repo, and SARIF is the standard format
GitHub's Security tab reads.

## 3:15 – 4:30 · The number
```bash
mcpscan bench corpus/
```
Say the result out loud: **precision 0.82, recall 1.00** on 9 labeled vulnerabilities in 9 servers.
Open `results/report.md` and show the "How the number moved" table, then one false positive and
why the rule fired.

## 4:30 – 5:00 · Close
- Be honest about the limit: this is our own small corpus, so the numbers show our method works,
  not that every attack is caught.
- The corpus and labels are open source, so anyone can benchmark a scanner against them.
- Hard rule: we only attack servers we wrote; public servers get read-only analysis.

## If something breaks live
- A server will not start: scan saved JSON instead, which needs no server:
  `mcpscan scan --file samples/filesystem.tools.json`
- `bench` fails: open the committed `results/report.md` directly.
