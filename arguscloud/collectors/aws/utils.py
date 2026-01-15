"""Common utilities for AWS collectors.

This module provides reusable functions to reduce code duplication
across AWS collectors, including pagination helpers, error handling,
and resource detail collection patterns.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

T = TypeVar("T")


def paginate_collect(
    client: Any,
    method: str,
    results_key: str,
    **paginate_kwargs: Any,
) -> List[Dict[str, Any]]:
    """Generic paginated AWS API collection.

    Handles pagination automatically using boto3 paginators,
    with standardized error handling.

    Args:
        client: boto3 service client
        method: Name of the paginator method (e.g., 'list_roles')
        results_key: Key in the response containing results (e.g., 'Roles')
        **paginate_kwargs: Additional arguments passed to paginator

    Returns:
        List of collected items, or empty list on error

    Example:
        >>> iam = session.client('iam')
        >>> roles = paginate_collect(iam, 'list_roles', 'Roles')
    """
    try:
        paginator = client.get_paginator(method)
        results: List[Dict[str, Any]] = []
        for page in paginator.paginate(**paginate_kwargs):
            results.extend(page.get(results_key, []))
        return results
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        logger.warning(f"Pagination failed for {method}: {error_code}")
        return []
    except Exception as e:
        logger.warning(f"Unexpected error in {method}: {type(e).__name__}")
        return []


def safe_api_call(
    client: Any,
    method: str,
    result_key: Optional[str] = None,
    default: T = None,  # type: ignore
    log_level: str = "debug",
    **kwargs: Any,
) -> T:
    """Safely call an AWS API with standardized error handling.

    Args:
        client: boto3 service client
        method: Name of the API method to call
        result_key: Optional key to extract from response
        default: Default value to return on error
        log_level: Logging level for errors ('debug' or 'warning')
        **kwargs: Arguments passed to the API method

    Returns:
        API response (or extracted key), or default on error

    Example:
        >>> iam = session.client('iam')
        >>> policy = safe_api_call(
        ...     iam, 'get_role_policy',
        ...     result_key='PolicyDocument',
        ...     RoleName='MyRole',
        ...     PolicyName='MyPolicy'
        ... )
    """
    try:
        operation = getattr(client, method)
        result = operation(**kwargs)
        if result_key:
            return result.get(result_key, default)
        return result
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        msg = f"{method} failed: {error_code}"
        if log_level == "warning":
            logger.warning(msg)
        else:
            logger.debug(msg)
        return default
    except Exception as e:
        msg = f"Unexpected error in {method}: {type(e).__name__}"
        if log_level == "warning":
            logger.warning(msg)
        else:
            logger.debug(msg)
        return default


def collect_resource_details(
    resource: Dict[str, Any],
    resource_id_key: str,
    detail_collectors: List[Tuple[str, Callable[[str], Any]]],
) -> Dict[str, Any]:
    """Collect optional details for a resource with error handling.

    This pattern is common across collectors where the primary resource
    is listed, then additional API calls fetch related details.

    Args:
        resource: The primary resource dictionary
        resource_id_key: Key in resource dict containing the identifier
        detail_collectors: List of (property_name, collector_function) tuples

    Returns:
        Dictionary with resource and collected details

    Example:
        >>> def get_attached_policies(role_name):
        ...     return iam.list_attached_role_policies(RoleName=role_name)
        ...
        >>> record = collect_resource_details(
        ...     role,
        ...     'RoleName',
        ...     [('AttachedPolicies', get_attached_policies)]
        ... )
    """
    record: Dict[str, Any] = {"Resource": resource}
    resource_id = resource.get(resource_id_key)

    if not resource_id:
        logger.debug(f"Missing resource ID key: {resource_id_key}")
        return record

    for prop_name, collector_fn in detail_collectors:
        try:
            result = collector_fn(resource_id)
            record[prop_name] = result
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.debug(f"Failed to collect {prop_name} for {resource_id}: {error_code}")
            record[prop_name] = None
        except Exception as e:
            logger.debug(f"Error collecting {prop_name}: {type(e).__name__}")
            record[prop_name] = None

    return record


def parse_policy_document(
    policy_response: Dict[str, Any],
    policy_key: str = "PolicyDocument",
    default: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Safely parse a JSON policy document from AWS response.

    Many AWS APIs return policy documents as JSON strings that need
    to be parsed. This function handles that safely.

    Args:
        policy_response: API response containing the policy
        policy_key: Key in response containing the policy string
        default: Default value if parsing fails

    Returns:
        Parsed policy dictionary, or default on error

    Example:
        >>> response = iam.get_role_policy(RoleName='MyRole', PolicyName='MyPolicy')
        >>> policy = parse_policy_document(response)
    """
    if default is None:
        default = {}

    try:
        policy_str = policy_response.get(policy_key)
        if policy_str is None:
            return default
        if isinstance(policy_str, dict):
            return policy_str
        return json.loads(policy_str)
    except (json.JSONDecodeError, TypeError, AttributeError) as e:
        logger.debug(f"Failed to parse policy document: {type(e).__name__}")
        return default


def batch_process(
    items: List[T],
    processor: Callable[[List[T]], List[Dict[str, Any]]],
    batch_size: int = 100,
) -> List[Dict[str, Any]]:
    """Process items in batches with a processor function.

    Some AWS APIs have batch operations that accept multiple items
    at once (e.g., batch_get_projects in CodeBuild).

    Args:
        items: List of items to process
        processor: Function that takes a batch and returns results
        batch_size: Maximum items per batch

    Returns:
        Combined results from all batches

    Example:
        >>> def get_project_details(project_names):
        ...     return cb.batch_get_projects(names=project_names)['projects']
        ...
        >>> all_details = batch_process(project_names, get_project_details)
    """
    results: List[Dict[str, Any]] = []
    for i in range(0, len(items), batch_size):
        batch = items[i : i + batch_size]
        try:
            batch_results = processor(batch)
            results.extend(batch_results)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(f"Batch processing failed: {error_code}")
        except Exception as e:
            logger.warning(f"Batch processing error: {type(e).__name__}")
    return results


def extract_arn_account_id(arn: str) -> Optional[str]:
    """Extract AWS account ID from an ARN.

    Args:
        arn: AWS ARN string

    Returns:
        Account ID if found, None otherwise

    Example:
        >>> extract_arn_account_id('arn:aws:iam::123456789012:role/MyRole')
        '123456789012'
    """
    try:
        parts = arn.split(":")
        if len(parts) >= 5:
            return parts[4] if parts[4] else None
        return None
    except (AttributeError, IndexError):
        return None


def extract_arn_region(arn: str) -> Optional[str]:
    """Extract AWS region from an ARN.

    Args:
        arn: AWS ARN string

    Returns:
        Region if found, None otherwise (some ARNs like IAM are global)

    Example:
        >>> extract_arn_region('arn:aws:s3:us-east-1:123456789012:bucket/mybucket')
        'us-east-1'
    """
    try:
        parts = arn.split(":")
        if len(parts) >= 4:
            return parts[3] if parts[3] else None
        return None
    except (AttributeError, IndexError):
        return None


def get_tags_dict(tags_list: Optional[List[Dict[str, str]]]) -> Dict[str, str]:
    """Convert AWS tags list format to dictionary.

    AWS returns tags as [{"Key": "k", "Value": "v"}], this converts
    to {"k": "v"} for easier use.

    Args:
        tags_list: List of tag dictionaries with Key/Value pairs

    Returns:
        Dictionary mapping tag keys to values

    Example:
        >>> tags = [{"Key": "Environment", "Value": "prod"}]
        >>> get_tags_dict(tags)
        {'Environment': 'prod'}
    """
    if not tags_list:
        return {}
    return {tag.get("Key", ""): tag.get("Value", "") for tag in tags_list if tag.get("Key")}


class CollectionContext:
    """Context manager for safe AWS collection with standardized error handling.

    Provides a consistent pattern for wrapping collection logic with
    proper error handling and logging.

    Example:
        >>> with CollectionContext("iam-roles") as ctx:
        ...     roles = paginate_collect(iam, 'list_roles', 'Roles')
        ...     ctx.set_result(roles)
        >>> # Returns (True, roles) on success, (False, []) on error
    """

    def __init__(self, service_name: str):
        """Initialize collection context.

        Args:
            service_name: Name of the service being collected
        """
        self.service_name = service_name
        self.result: List[Dict[str, Any]] = []
        self.error: Optional[Exception] = None

    def __enter__(self) -> "CollectionContext":
        """Enter the context."""
        logger.debug(f"Starting collection: {self.service_name}")
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[Exception],
        exc_tb: Any,
    ) -> bool:
        """Exit the context, handling any exceptions.

        Returns:
            True to suppress exception, False to propagate
        """
        if exc_val is not None:
            self.error = exc_val
            if isinstance(exc_val, ClientError):
                error_code = exc_val.response.get("Error", {}).get("Code", "Unknown")
                logger.warning(f"Collection failed for {self.service_name}: {error_code}")
            else:
                logger.warning(
                    f"Collection error for {self.service_name}: {type(exc_val).__name__}"
                )
            return True  # Suppress exception
        logger.debug(f"Completed collection: {self.service_name}")
        return False

    def set_result(self, result: List[Dict[str, Any]]) -> None:
        """Set the collection result.

        Args:
            result: Collected data
        """
        self.result = result

    def get_result(self) -> Tuple[bool, List[Dict[str, Any]]]:
        """Get the collection result.

        Returns:
            Tuple of (success, result_data)
        """
        return (self.error is None, self.result)
