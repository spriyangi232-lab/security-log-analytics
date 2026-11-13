"""Compatibility shim. Rule metadata now lives in `sla/rules.py` (the single rules file)."""
from .rules import ITIL_PRIORITY, RESPONSE_TARGET, RULES, SEVERITY_ORDER  # noqa: F401
