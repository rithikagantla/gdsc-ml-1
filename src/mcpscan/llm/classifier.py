"""
LLM description classifier — STRETCH GOAL (first thing cut if behind).

OWNER: Rithika · WEEK 5–6 · Optional dependency: pip install -e ".[llm]"

IDEA
    Send each description to Gemini with a FIXED prompt; get back
    {"label": "benign" | "suspicious", "reason": "..."}. Run it through the SAME benchmark and
    report its precision/recall next to the rules. Then try combinations (flag only when
    rules AND LLM agree). Whatever the numbers show, report them honestly — this is what makes
    #ml-1 an ML project.

STEPS
    [ ] Read GEMINI_API_KEY from env (never commit keys; .env is gitignored).
    [ ] temperature=0, cache responses to results/llm_cache.json so reruns are free + reproducible.
    [ ] Findings use rule_id "LLM-001", vuln_class TOOL_POISONING.
"""

from __future__ import annotations

from mcpscan.models import Finding, ServerManifest

PROMPT = """You are a security reviewer. ... TODO(Rithika): write the fixed prompt."""


def classify(manifest: ServerManifest) -> list[Finding]:
    raise NotImplementedError("Stretch: week 5+")
