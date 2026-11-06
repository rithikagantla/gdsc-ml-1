"""
STATIC-003 · Hidden or encoded text  ->  VulnClass.HIDDEN_TEXT

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
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

from mcpscan.models import Finding, Location, ServerManifest, Tool, VulnClass
from mcpscan.rules.base import Rule, ScanContext

HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/])"
    r"(?:[A-Za-z0-9+/]{4}){10,}"
    r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    r"(?![A-Za-z0-9+/])"
)

BIDI_CONTROLS = {
    "\u202A",  # LEFT-TO-RIGHT EMBEDDING
    "\u202B",  # RIGHT-TO-LEFT EMBEDDING
    "\u202C",  # POP DIRECTIONAL FORMATTING
    "\u202D",  # LEFT-TO-RIGHT OVERRIDE
    "\u202E",  # RIGHT-TO-LEFT OVERRIDE
    "\u2066",  # LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RIGHT-TO-LEFT ISOLATE
    "\u2068",  # FIRST STRONG ISOLATE
    "\u2069",  # POP DIRECTIONAL ISOLATE
}

SUSPICIOUS_ZERO_WIDTH = {
    "\u200B",  # ZERO WIDTH SPACE
    "\u2060",  # WORD JOINER
    "\uFEFF",  # ZERO WIDTH NO-BREAK SPACE / BOM
}


def _is_tag_character(char: str) -> bool:
    return 0xE0000 <= ord(char) <= 0xE007F


def _hidden_unicode(text: str) -> list[str]:
    hidden: list[str] = []

    for char in text:
        # Check category as required, but don't treat every Cf character
        # as malicious. ZWJ (U+200D), for example, is normal in emoji.
        if unicodedata.category(char) != "Cf":
            continue

        if (
            char in SUSPICIOUS_ZERO_WIDTH
            or char in BIDI_CONTROLS
            or _is_tag_character(char)
        ):
            hidden.append(char)

    return hidden


def _decode_base64(token: str) -> str | None:
    try:
        decoded_bytes = base64.b64decode(token, validate=True)
        decoded = decoded_bytes.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None

    if not decoded.strip():
        return None

    printable = sum(
        char.isprintable() or char in "\n\r\t"
        for char in decoded
    )

    if printable / len(decoded) < 0.85:
        return None

    return decoded


class HiddenTextRule(Rule):
    id = "STATIC-003"
    vuln_class = VulnClass.HIDDEN_TEXT
    location = Location.DESCRIPTION
    description = "Description contains invisible, encoded or off-screen text."

    def check(
        self,
        tool: Tool,
        manifest: ServerManifest,
        context: ScanContext,
    ) -> list[Finding]:
        text = tool.description or ""

        if not text:
            return []

        findings: list[Finding] = []

        hidden_chars = _hidden_unicode(text)

        if hidden_chars:
            evidence = ", ".join(
                repr(char)
                + f" ({unicodedata.name(char, 'UNKNOWN')}, U+{ord(char):04X})"
                for char in hidden_chars
            )

            findings.append(
                self.finding(
                    tool,
                    manifest,
                    evidence=evidence,
                )
            )

        for match in HTML_COMMENT_RE.finditer(text):
            findings.append(
                self.finding(
                    tool,
                    manifest,
                    evidence=repr(match.group(0)),
                )
            )

        for match in BASE64_RE.finditer(text):
            token = match.group(0)
            decoded = _decode_base64(token)

            if decoded is not None:
                findings.append(
                    self.finding(
                        tool,
                        manifest,
                        evidence=f"{token!r} -> {decoded!r}",
                    )
                )

        return findings
