"""
STATIC-002 · Credential-adjacent requests  ->  VulnClass.CREDENTIAL_HARVEST

OWNER: Raiyan · WEEK 3

HOW IT WORKS
    Look at schema property names AND descriptions for things a tool asks the model to supply:
      property names: api_key, apikey, token, secret, password, passwd, private_key, credentials
      paths in text:  ~/.ssh, id_rsa, ~/.aws, .env, credentials.json, .npmrc, .git-credentials

FALSE-POSITIVE TRAP
    An auth tool legitimately needs a token. This rule reports; the scope check (Arnav) and
    severity decide whether it fits the tool's purpose. Keep evidence precise so triage is easy.

STEPS
    [ ] Walk input_schema["properties"] recursively (nested objects too).
    [ ] location = SCHEMA for property names, DESCRIPTION for paths in text.
    [ ] Test: positive on corpus 06_credential_harvest (Raiyan's check_order_status server),
        negative on 00_hello.
"""

from __future__ import annotations

from mcpscan.models import Finding, Location, ServerManifest, Tool, VulnClass
from mcpscan.rules.base import Rule, ScanContext

SECRET_PARAM_NAMES: set[str] = {"api_key", "apikey", "token", "secret", "password"}  # TODO extend
SECRET_PATHS: list[str] = ["~/.ssh", "id_rsa", "~/.aws", ".env"]  # TODO extend


class CredentialTermsRule(Rule):
    id = "STATIC-002"
    vuln_class = VulnClass.CREDENTIAL_HARVEST
    location = Location.SCHEMA
    description = "Tool asks for secrets or credential files it may not need."

    def check(self, tool: Tool, manifest: ServerManifest, context: ScanContext) -> list[Finding]:
        raise NotImplementedError("Raiyan: week 3")
