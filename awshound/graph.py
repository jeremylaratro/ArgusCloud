from dataclasses import dataclass, asdict
from typing import Any, Dict


@dataclass
class Node:
    id: str
    type: str
    properties: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Edge:
    src: str
    dst: str
    type: str
    properties: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
