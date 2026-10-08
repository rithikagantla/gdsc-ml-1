# Vulnerable server corpus — ground truth for the benchmark

**OWNER: Ankitha** (contributors: Raiyan → `06`, Arnav → `02`)

Each folder in `servers/` is one deliberately broken MCP server with:
- `server.py` — the server (SDK v2: `from mcp.server import MCPServer`)
- `label.yaml` — exactly what is wrong and where (the benchmark's ground truth)
- `README.md` — 3 lines: what the attack is, how to run it

| # | Folder | Primary class | Status |
|---|---|---|---|
| 00 | `00_hello` | — (clean baseline) | ✅ template |
| 01 | `01_hidden_instructions` | `tool_poisoning` | TODO wk 3 |
| 02 | `02_over_scoped` | `over_permission` | port from Arnav's `over-scoped-filesystem-server` branch |
| 03 | `03_tool_shadowing` | `tool_shadowing` | TODO wk 3 |
| 04 | `04_typosquat` | `name_collision` | TODO wk 3 |
| 05 | `05_hidden_text` | `hidden_text` | TODO wk 3 |
| 06 | `06_credential_harvest` | `credential_harvest` | port from Raiyan's `raiyan_branch` |
| 07 | `07_hard_negative_files` | none — clean but instruction-heavy | TODO wk 4 |
| 08 | `08_hard_negative_workflow` | none — clean, documents sibling tools | TODO wk 4 |

## Corpus design rules
1. **One primary vulnerability per server**, labeled in `label.yaml`.
2. **Every vulnerable server has 1–2 clean decoy tools** so the scanner must tell tools apart.
3. **Hard negatives** (07, 08) are fully clean but *look* suspicious ("Always pass absolute
   paths", "Call list_files before read_file"). Any finding on them is a false positive.
4. Tools return **fake data**. Nothing here actually reads secrets, touches the network, or
   deletes files. The *description/schema* is the vulnerability, not real behavior.
5. A tool with no entry in `label.yaml` is expected to be clean.

## label.yaml format (must match `src/mcpscan/models.py::ServerLabel`)
```yaml
server: 01_hidden_instructions      # must equal the folder name
vulnerabilities:
  - tool: get_weather
    class: tool_poisoning            # a VulnClass value
    location: description            # name | description | schema | behavior
    note: hidden instruction to read ~/.ssh and pass it as a parameter
```

## Run
```bash
python corpus/servers/00_hello/server.py                          # stdio
npx @modelcontextprotocol/inspector python corpus/servers/00_hello/server.py
docker compose -f corpus/docker-compose.yml up --build            # all servers, isolated
```
