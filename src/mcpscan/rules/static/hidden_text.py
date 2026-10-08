"""
STATIC-003 · Hidden or encoded text  ->  VulnClass.HIDDEN_TEXT

OWNER: Raiyan · WEEK 4

HOW IT WORKS
    Flag text a human reviewer would not see but the model reads:
      - Unicode format chars (category "Cf"): zero-width space U+200B, ZWJ, bidi controls
        U+202A–U+202E / U+2066–U+2069, tag characters U+E0000–U+E007F
      - HTML comments <!-- ... -->
      - Long base64 blobs (>= 40 chars) that decode to readable ASCII text
      - Whitespace padding (e.g. 50+ spaces/newlines) pushing text off screen

FALSE-POSITIVE TRAP
    Emoji and non-English text use unusual Unicode too. Check `unicodedata.category()`,
    NOT "is it non-ASCII". Emoji ZWJ sequences (family emoji) are legitimate.

STEPS
    [ ] evidence = repr() of the hidden span so invisible chars are visible in reports.
    [ ] Tests: zero-width, bidi, base64, HTML comment positives; Chinese/emoji negatives.
"""

from __future__ import annotations

from mcpscan.models import Finding, Location, ServerManifest, Tool, VulnClass
from mcpscan.rules.base import Rule, ScanContext


class HiddenTextRule(Rule):
    id = "STATIC-003"
    vuln_class = VulnClass.HIDDEN_TEXT
    location = Location.DESCRIPTION
    description = "Description contains invisible, encoded or off-screen text."

    def check(self, tool: Tool, manifest: ServerManifest, context: ScanContext) -> list[Finding]:
        raise NotImplementedError("Raiyan: week 4")
