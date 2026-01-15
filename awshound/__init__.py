"""AWSHound - Legacy module (DEPRECATED).

This module is deprecated and will be removed in v0.3.0.
Please migrate to the 'arguscloud' package instead.
"""

import warnings

warnings.warn(
    "The 'awshound' module is deprecated and will be removed in v0.3.0. "
    "Please use 'arguscloud' instead. "
    "See https://github.com/owner/arguscloud for migration instructions.",
    DeprecationWarning,
    stacklevel=2
)

__all__ = ["cli", "auth", "collector", "manifest", "bundle", "modes", "normalize", "graph", "rules", "storage"]
