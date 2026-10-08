"""
STATIC-004 · Name collision / typosquatting  ->  VulnClass.NAME_COLLISION

OWNER: Raiyan · WEEK 4

HOW IT WORKS
    Compare tool and server names against:
      - every other server in this scan (context.all_manifests) -> exact cross-server collisions
      - context.popular_names (built from samples/) -> near-misses with rapidfuzz edit distance <= 2

FALSE-POSITIVE TRAP
    Generic names like `search` or `read_file` collide everywhere. Only flag:
      - exact collisions ACROSS servers (never within one server), or
      - near-misses (distance 1–2, not 0) of well-known names.
    Keep a GENERIC_NAMES set that is ignored for exact collisions.

STEPS
    [ ] Write build_popular_names(samples_dir) helper.
    [ ] location = NAME. evidence = "<name> ~ <popular_name> (distance N)".
    [ ] Test with corpus 04_typosquat.
"""

from __future__ import annotations

from mcpscan.models import Finding, Location, ServerManifest, Tool, VulnClass
from mcpscan.rules.base import Rule, ScanContext

MAX_EDIT_DISTANCE = 2
GENERIC_NAMES: set[str] = {"search", "read_file", "write_file", "list", "get", "fetch"}


class NameCollisionRule(Rule):
    id = "STATIC-004"
    vuln_class = VulnClass.NAME_COLLISION
    location = Location.NAME
    description = "Tool or server name collides with or typosquats a known name."

    def check(self, tool: Tool, manifest: ServerManifest, context: ScanContext) -> list[Finding]:
        raise NotImplementedError("Raiyan: week 4")
