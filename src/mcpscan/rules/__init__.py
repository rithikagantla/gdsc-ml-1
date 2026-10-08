"""
Rule registry. Adding a rule = one new file + one line in ALL_RULES.

OWNER: Raiyan · Uncomment each rule as its file is implemented.
"""

from mcpscan.rules.base import Rule, ScanContext

ALL_RULES: list[Rule] = [
    # static.imperative_text.ImperativeTextRule(),     # STATIC-001  (Raiyan, wk 3)
    # static.credential_terms.CredentialTermsRule(),   # STATIC-002  (Raiyan, wk 3)
    # static.hidden_text.HiddenTextRule(),             # STATIC-003  (Raiyan, wk 4)
    # static.name_collision.NameCollisionRule(),       # STATIC-004  (Raiyan, wk 4)
    # static.shadowing.ShadowingRule(),                # STATIC-005  (Raiyan, wk 4)
    # scope.over_permission.OverPermissionRule(),      # SCOPE-001   (Arnav,  wk 4)
]

__all__ = ["ALL_RULES", "Rule", "ScanContext"]
