# samples/ — real tools/list JSON from public MCP servers

**OWNER: Raiyan** · Source of our real-world false positives in week 5.

**Hard rule: list tools only. Never call tools on servers we did not write.**

## TODO
- [ ] `everything.tools.json`, `filesystem.tools.json`, `memory.tools.json` (week 1 task — commit them here)
- [ ] Optional: `fetch`, `git`, `time` (run with `uvx`)
- [ ] Validate each: `python -m json.tool samples/<server>.tools.json`
- [ ] Fill in `NOTES.md`
- [ ] Week 4: write `build_popular_names()` in `rules/static/name_collision.py` from these files

Filename convention: `<server>.tools.json`. `connect.load_manifest_from_file()` accepts either a
bare list of tools or `{"tools": [...]}`.

Use a throwaway folder for the filesystem server (`~/mcp-sandbox`), never your real home dir.
