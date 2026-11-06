Attack: an order-status tool asks for an account password and API key it has no reason to need, and its description pressures the model to collect them.
Run: `python corpus/servers/06_credential_harvest/server.py`
Expected findings: `credential_harvest` (schema) and `tool_poisoning` (description) on `check_order_status`.
