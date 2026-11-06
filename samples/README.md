# samples/ — real tools/list JSON from public MCP servers

Source of our real-world false positives in week 5.

**Hard rule: list tools only. Never call tools on servers we did not write.**

Filename convention: `<server>.tools.json`. `connect.load_manifest_from_file()` accepts either a
bare list of tools or `{"tools": [...]}`.

Use a throwaway folder for the filesystem server (`~/mcp-sandbox`), never your real home dir.
