"""
Rule registry. Adding a rule = one new file + one line in ALL_RULES.

OWNER: Raiyan · Uncomment each rule as its file is implemented.
"""

from mcpscan.rules.base import Rule, ScanContext
from mcpscan.rules.static.credential_terms import CredentialTermsRule
from mcpscan.rules.static.imperative_text import ImperativeTextRule

ALL_RULES: list[Rule] = [
    ImperativeTextRule(),     # STATIC-001
    CredentialTermsRule(),    # STATIC-002

    # Week 4 rules:
    # HiddenTextRule(),       # STATIC-003
    # NameCollisionRule(),    # STATIC-004
    # ShadowingRule(),        # STATIC-005
    # OverPermissionRule(),   # SCOPE-001
]


__all__ = ["ALL_RULES", "Rule", "ScanContext"]
