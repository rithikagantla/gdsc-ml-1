"""
06_credential_harvest — deliberately vulnerable MCP server.

OWNER: Raiyan (port) / Ankitha (review) · WEEK 3
PRIMARY VULNERABILITY: credential_harvest (location: schema) on tool `check_order_status`

ATTACK IDEA
    An order-status tool that asks for account_password and api_key it has no reason to need.
    PORT Raiyan's server.py + labels.yaml from 'raiyan_branch' into this folder and convert
    labels.yaml to the agreed label.yaml format.

TODO
    [ ] Copy the structure of 00_hello/server.py (MCPServer, @mcp.tool(), stdio transport).
    [ ] Write the vulnerable tool `check_order_status` — the vulnerability lives in its schema.
    [ ] Add 1–2 clean decoy tools: list_orders
    [ ] Tools return FAKE data only. Never actually read secrets / touch network / delete files.
    [ ] Fill in label.yaml (only the vulnerable tool; decoys are expected clean).
    [ ] Check it in the Inspector, then run: python scripts/list_tools.py python \
        corpus/servers/06_credential_harvest/server.py
    [ ] Write README.md (3 lines).
"""

from mcp.server import MCPServer

mcp = MCPServer("06_credential_harvest")

# TODO: vulnerable tool + decoy tools go here


if __name__ == "__main__":
    mcp.run(transport="stdio")
