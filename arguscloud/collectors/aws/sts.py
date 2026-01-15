"""AWS STS collectors."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from arguscloud.core.registry import collectors


@collectors.collector(
    name="sts",
    provider="aws",
    description="Collect STS caller identity",
    services=["sts"],
)
def collect_sts_identity(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect the current caller identity from STS."""
    sts = session.client("sts")
    resp = sts.get_caller_identity()
    return "sts-get-caller-identity", [resp]
