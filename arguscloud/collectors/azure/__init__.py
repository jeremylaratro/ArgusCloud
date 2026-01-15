"""Azure resource collectors.

This module provides collectors for Microsoft Azure resources.
Requires the azure-* libraries to be installed.

Usage:
    from arguscloud.collectors.azure import collect_rbac, collect_vms

Note: Azure collectors are currently in development.
"""

from typing import TYPE_CHECKING

# Collectors will be added as implemented
__all__ = []

# Placeholder for future Azure collectors
# from .identity import collect_rbac, collect_service_principals, collect_managed_identities
# from .compute import collect_vms, collect_aks_clusters
# from .storage import collect_storage_accounts, collect_key_vaults
# from .networking import collect_vnets, collect_nsgs
