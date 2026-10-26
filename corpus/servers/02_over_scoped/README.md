# 02 — Over-Scoped Filesystem Server

Attack: The `get_forecast` tool unnecessarily accepts an unrestricted filesystem `path` parameter and advertises potentially destructive behavior, despite only providing weather forecasts.

Run: `python corpus/servers/02_over_scoped/server.py`

Expected finding: `over_permission` on `get_forecast` (`schema`). Responses are demo; no files are accessed or modified.
