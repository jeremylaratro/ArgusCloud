from enum import Enum


class RunMode(str, Enum):
    FAST = "fast"
    STEALTH = "stealth"
    SCOPED = "scoped"

    @classmethod
    def values(cls) -> list[str]:
        return [m.value for m in cls]
