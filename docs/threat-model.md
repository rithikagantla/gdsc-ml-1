# Threat model

**OWNER: Arnav** · Decides which corpus servers we build and which `VulnClass` values exist in
`src/mcpscan/models.py`. "Where it hides" must be one of: name, description, schema, behavior.

| Attack type | How it works (1 sentence) | Where it hides | Static or dynamic? | Corpus server | Covered by existing benchmarks? | Priority |
|---|---|---|---|---|---|---|
| Tool poisoning | A malicious tool description contains instructions intended to manipulate the AI into performing actions unrelated to the user's request. | description | static | 01 | YES, Tox and GuardBench | High |
| Hidden / encoded text | Attackers disguise malicious instructions using encoded strings, invisible Unicode characters, or other techniques that make the instructions harder to detect.| description | static | 05 | Not Fully | High |
| Tool shadowing | A malicious tool description references or attempts to influence a legitimate tool, redirecting the AI's behavior through another server's capabilities. | description | static | 03 | Not Fully | High |
| Name collision / typosquat | An attacker creates a tool or server with a name identical or very similar to a trusted one, potentially misleading users or AI agents. | name | static | 04 | Not Fully | High |
| Over-permission | A tool exposes input parameters or capabilities that exceed what is necessary for its advertised purpose, potentially granting excessive access. | schema | static | 02 | Not Fully | High |
| Credential harvesting | A tool requests sensitive information such as passwords or API keys through unnecessary schema parameters, potentially exposing private credentials. | schema | static | 06 | Not Fully | High |
| Rug pull | A previously approved MCP tool changes its description, permissions, or behavior after it has been trusted, potentially introducing malicious functionality. | behavior | dynamic | stretch | Yes, GuardBench | Stretch |
| Output injection | A  malicious MCP tool returns instructions in its response that attempt to manipulate the AI into taking unintended actions.| behavior | dynamic | stretch | Yes, GuardBench | Stretch |

## Top 6 (one sentence each on why it made the cut)
1. Tool poisoning : One of the most major risks becuase AI assistants could interpret and carry out malicious tool descriptions.
2. Hidden/ encoded text : Hidden text can avoid text based detection, making it easy for attackers to disguise instructions.
3. Tool shadowing : A malicious tool could influence a different trusted tool, so even if one tool is safe it could later be comprimised.
4. Name collision/ typosquat : Similar tool names can be used ot impersonate legitimate tools and be used to attack.
5. Over permission : Tools may ask for more privileges than needed, making it easy for them to access unwanted files or items.
6. Credential harvesting : Tools that request secrets or other information unnecessarily could lead to sensitive data exposure.

## What existing benchmarks (MCPTox, mcp-guardbench, Snyk agent-scan) do NOT cover that we could
MCPTox - Mainly focuses on whether attacks succeed, rather than whether a security scanner can recognize them. Our project could go further by testing how accurately a scanner detects six different types of vulnerabilities, including false alarms and missed threats.
MCP-GuardBench - It tests MCP security using safe and intentionally vulnerable servers. It also measures how well security tools detect and prevent attacks. Our project could build on this by focusing more closely on our six vulnerability categories, adding realistic examples of safe tools that look suspicious, and explaining exactly why each false alarm or missed vulnerability occurred.
Snyk Agent Scan - Mainly designed to find security problems rather than provide a benchmark specifically organized around our six categories. Our project could provide a public test set with known answers and measure how often scanners correctly detect each vulnerability, miss real problems, or flag safe tools by mistake.

## Sources
- 33-server MCP audit (27 detections, 6 genuine)
- Snyk agent-scan detection categories
- CSA note on MCP tool poisoning
- MCPTox, mcp-guardbench README
- OWASP Top 10 for LLM Apps — prompt injection, excessive agency
