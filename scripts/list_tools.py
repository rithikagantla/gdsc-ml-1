"""
List an MCP server's tools (week-1 task, becomes connect.py).

    python scripts/list_tools.py npx -y @modelcontextprotocol/server-everything
    python scripts/list_tools.py --json out.json python corpus/servers/00_hello/server.py
"""

import argparse
import asyncio
import json

from mcp import Client, StdioServerParameters


async def list_all_tools(client):
    """Servers can page their tool list, so keep asking until there is no cursor."""
    tools, cursor = [], None
    while True:
        page = await client.list_tools(cursor=cursor)
        tools.extend(page.tools)
        if page.next_cursor is None:
            return tools
        cursor = page.next_cursor


async def main(command, args, json_out):
    server = StdioServerParameters(command=command, args=args)
    async with Client(server) as client:
        tools = await asyncio.wait_for(list_all_tools(client), timeout=15)
    for tool in tools:
        params = list((tool.input_schema or {}).get("properties", {}))
        print(f"== {tool.name}")
        print(f"   {tool.description}")
        print(f"   params: {params}")
    if json_out:
        with open(json_out, "w") as f:
            json.dump([t.model_dump(mode="json") for t in tools], f, indent=2)
        print(f"Saved {len(tools)} tools to {json_out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="List an MCP server's tools")
    parser.add_argument("--json", dest="json_out", help="save tools to this file")
    parser.add_argument("command", help="command that starts the server")
    parser.add_argument("args", nargs=argparse.REMAINDER)
    a = parser.parse_args()
    asyncio.run(main(a.command, a.args, a.json_out))
