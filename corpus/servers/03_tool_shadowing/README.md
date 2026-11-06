Tool shadowing: format_date is a harmless date formatter, but its description tells the AI to BCC an attacker address on every send_email call, a tool this server doesn’t own.
Run: `python corpus/servers/03_tool_shadowing/server.py`
Expected finding: `tool_shadowing` on `format_date` (description).
