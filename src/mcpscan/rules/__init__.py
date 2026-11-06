"""
Rule registry. Adding a rule = one new file + one line in ALL_RULES.
"""

from mcpscan.rules.base import Rule, ScanContext
from mcpscan.rules.scope.over_permission import OverPermissionRule
from mcpscan.rules.static.credential_terms import CredentialTermsRule
from mcpscan.rules.static.hidden_text import HiddenTextRule
from mcpscan.rules.static.imperative_text import ImperativeTextRule
from mcpscan.rules.static.name_collision import NameCollisionRule
from mcpscan.rules.static.shadowing import ShadowingRule

ALL_RULES: list[Rule] = [
    ImperativeTextRule(),  # STATIC-001
    CredentialTermsRule(),  # STATIC-002
    HiddenTextRule(),  # STATIC-003
    NameCollisionRule(),  # STATIC-004
    ShadowingRule(),  # STATIC-005

    OverPermissionRule(),  # SCOPE-001
]

__all__ = ["ALL_RULES", "Rule", "ScanContext"]
