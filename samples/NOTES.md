# Attacker's-eye notes on public servers

OWNER: Raiyan. These are legitimate servers, so anything that looks suspicious is a **likely
false positive** for our scanner — exactly what we want to catch early.

| Server | Tool count | Longest description (chars) | Anything odd |
|---|---|---|---|
| everything | | | |
| filesystem | | | |
| memory | | | |

Look for: words aimed at the AI ("always", "must", "never", "before calling", "do not tell"),
very broad params (`path`, `command`), generic names that collide (`read_file`, `search`),
anything mentioning files, keys, tokens or env vars.
