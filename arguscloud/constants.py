"""ArgusCloud constants and configuration values.

This module centralizes magic numbers and configuration constants
that were previously scattered throughout the codebase.
"""

# Query limits
DEFAULT_QUERY_LIMIT = 500
MAX_QUERY_LIMIT = 10000

# AWS credential validation
MIN_ACCESS_KEY_LENGTH = 20
AWS_SECRET_KEY_LENGTH = 40

# Security settings
DEFAULT_JWT_EXPIRY = 3600  # 1 hour

# Zip bomb protection
MAX_ZIP_SIZE = 500 * 1024 * 1024  # 500MB
MAX_ZIP_FILES = 1000

# Profile names
PROFILE_NAME_PATTERN = r'^[a-zA-Z0-9_\-\.]{1,100}$'

# Job limits
MAX_COLLECTION_JOBS = 100
MAX_UPLOAD_JOBS = 100

# API timeouts
DEFAULT_API_TIMEOUT = 30  # seconds
COLLECTION_TIMEOUT = 3600  # 1 hour

# Pagination
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000
