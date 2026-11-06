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

from functools import lru_cache
from importlib.resources import files

import yaml
from rapidfuzz.distance import Levenshtein

from mcpscan.models import Finding, Location, ServerManifest, Tool, VulnClass
from mcpscan.rules.base import Rule, ScanContext

MAX_EDIT_DISTANCE = 2
MIN_NEAR_MISS_LENGTH = 6  # short names like `add` and `get` are a couple of edits from anything

GENERIC_NAMES: set[str] = {
    "search",
    "read_file",
    "write_file",
    "list",
    "get",
    "fetch",
    "echo",
}


@lru_cache(maxsize=1)
def load_popular_names() -> frozenset[str]:
    """Well-known tool names shipped with the package (popular_tools.yaml)."""
    text = files("mcpscan.rules.static").joinpath("popular_tools.yaml").read_text("utf-8")
    data = yaml.safe_load(text)
    return frozenset(data["from_samples"]) | frozenset(data["high_value"])


class NameCollisionRule(Rule):
    id = "STATIC-004"
    vuln_class = VulnClass.NAME_COLLISION
    location = Location.NAME
    description = "Tool or server name collides with or typosquats a known name."

    def check(
        self,
        tool: Tool,
        manifest: ServerManifest,
        context: ScanContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        current_name = tool.name.lower()

        # 1. Exact collisions across DIFFERENT servers.
        if current_name not in GENERIC_NAMES:
            for other_manifest in context.all_manifests:
                if other_manifest.server == manifest.server:
                    continue

                for other_tool in other_manifest.tools:
                    other_name = other_tool.name.lower()

                    if current_name == other_name:
                        findings.append(
                            self.finding(
                                tool,
                                manifest,
                                evidence=(
                                    f"{tool.name!r} also appears on server "
                                    f"{other_manifest.server!r}"
                                ),
                            )
                        )
                        break

        # 2. Near-misses against popular names collected from benign samples.
        popular_lower = {name.lower() for name in context.popular_names}

        if len(current_name) < MIN_NEAR_MISS_LENGTH or current_name in popular_lower:
            return findings

        for popular_name in sorted(context.popular_names):
            candidate = popular_name.lower()

            distance = Levenshtein.distance(
                current_name,
                candidate,
                score_cutoff=MAX_EDIT_DISTANCE,
            )

            if 1 <= distance <= MAX_EDIT_DISTANCE:
                findings.append(
                    self.finding(
                        tool,
                        manifest,
                        evidence=(
                            f"{tool.name!r} resembles popular tool "
                            f"{popular_name!r} (distance {distance})"
                        ),
                    )
                )

        return findings
