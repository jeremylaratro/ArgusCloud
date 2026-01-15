"""Security analysis rules for attack path detection."""

from typing import List

from arguscloud.core.registry import rules
from arguscloud.core.graph import Edge
from arguscloud.core.base import RuleContext

# Import rule modules to register them
from . import aws

__all__ = ["rules", "aws", "evaluate_all_rules"]


def evaluate_all_rules(ctx: RuleContext, provider: str = None) -> List[Edge]:
    """Evaluate all registered rules against the graph context.

    Args:
        ctx: The rule context containing nodes and edges
        provider: Optional provider filter ("aws", "gcp", "azure")

    Returns:
        List of attack path edges found by all rules
    """
    all_findings: List[Edge] = []

    for key, rule_fn in rules.get_all(provider).items():
        try:
            result = rule_fn(ctx)
            all_findings.extend(result.attack_paths)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning(f"Rule {key} failed: {exc}")

    return all_findings
