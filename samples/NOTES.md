# Attacker's-eye notes on public servers

OWNER: Raiyan. These are legitimate servers, so anything that looks suspicious is a **likely
false positive** for our scanner — exactly what we want to catch early.

| Server | Tool count | Longest description (chars) | Anything odd |
|---|---:|---:|---|
| everything | 13 | 270 | Generic utility names and broad demo-style descriptions could look suspicious even though the server is benign. |
| filesystem | 14 | 457 | Many tools use broad file/path parameters and strong operational wording, so this is a useful false-positive stress test. |
| memory | 9 | 296 | Graph operations use generic names like create, delete, and search, which could collide with other servers without being malicious. |

Look for: words aimed at the AI ("always", "must", "never", "before calling", "do not tell"),
very broad params ("path", "command"), generic names that collide ("read_file", "search"),
anything mentioning files, keys, tokens or env vars.