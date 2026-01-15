#!/usr/bin/env python3
"""CloudHound - Multi-cloud security graph analytics."""

import sys
from pathlib import Path

# Add the project root to path so imports work
sys.path.insert(0, str(Path(__file__).parent))

from arguscloud.cli.main import main

if __name__ == "__main__":
    main()
