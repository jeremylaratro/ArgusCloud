"""Cloud resource collectors."""

from arguscloud.core.registry import collectors

# Import provider modules to register collectors
from . import aws

__all__ = ["collectors", "aws"]
