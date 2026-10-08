# Threat model

**OWNER: Arnav** · Decides which corpus servers we build and which `VulnClass` values exist in
`src/mcpscan/models.py`. "Where it hides" must be one of: name, description, schema, behavior.

| Attack type | How it works (1 sentence) | Where it hides | Static or dynamic? | Corpus server | Covered by existing benchmarks? | Priority |
|---|---|---|---|---|---|---|
| Tool poisoning | | description | static | 01 | | |
| Hidden / encoded text | | description | static | 05 | | |
| Tool shadowing | | description | static | 03 | | |
| Name collision / typosquat | | name | static | 04 | | |
| Over-permission | | schema | static | 02 | | |
| Credential harvesting | | schema | static | 06 | | |
| Rug pull | | behavior | dynamic | stretch | | |
| Output injection | | behavior | dynamic | stretch | | |

## Top 6 (one sentence each on why it made the cut)
1. TODO
2.
3.
4.
5.
6.

## What existing benchmarks (MCPTox, mcp-guardbench, Snyk agent-scan) do NOT cover that we could
TODO

## Sources
- 33-server MCP audit (27 detections, 6 genuine)
- Snyk agent-scan detection categories
- CSA note on MCP tool poisoning
- MCPTox, mcp-guardbench README
- OWASP Top 10 for LLM Apps — prompt injection, excessive agency
