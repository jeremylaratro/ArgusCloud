import json
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .modes import RunMode


@dataclass
class ServiceResult:
    name: str
    status: str
    detail: Optional[str] = None
    collected_resources: int = 0
    errors: List[str] = field(default_factory=list)


@dataclass
class Manifest:
    run_id: str
    mode: RunMode
    caller_arn: str
    account_id: str
    partition: str
    region: Optional[str]
    profile: str
    services: List[ServiceResult] = field(default_factory=list)
    schema_version: str = "0.1.0"
    notes: Optional[str] = None

    @classmethod
    def new(
        cls,
        mode: RunMode,
        caller_arn: str,
        account_id: str,
        partition: str,
        region: Optional[str],
        profile: str,
    ) -> "Manifest":
        return cls(
            run_id=str(uuid.uuid4()),
            mode=mode,
            caller_arn=caller_arn,
            account_id=account_id,
            partition=partition,
            region=region,
            profile=profile,
        )

    def add_service(self, name: str, status: str, detail: Optional[str] = None, collected_resources: int = 0, errors: Optional[List[str]] = None) -> None:
        self.services.append(
            ServiceResult(
                name=name,
                status=status,
                detail=detail,
                collected_resources=collected_resources,
                errors=errors or [],
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
