"""AWS Messaging service collectors (SNS, SQS)."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Tuple

import botocore.exceptions

from arguscloud.core.registry import collectors

log = logging.getLogger(__name__)


@collectors.collector(
    name="sns",
    provider="aws",
    description="Collect SNS topics and policies",
    services=["sns"],
)
def collect_sns(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect SNS topics with their policies and subscriptions."""
    sns = session.client("sns")
    data: List[Dict[str, Any]] = []

    try:
        topics = sns.list_topics().get("Topics", [])
        for topic in topics:
            arn = topic.get("TopicArn")
            if not arn:
                continue

            record: Dict[str, Any] = {"Topic": topic}

            # Topic attributes including policy
            try:
                attrs = sns.get_topic_attributes(TopicArn=arn)
                record["Attributes"] = attrs.get("Attributes", {})
            except botocore.exceptions.ClientError:
                pass

            # Subscriptions
            try:
                subs = sns.list_subscriptions_by_topic(TopicArn=arn)
                record["Subscriptions"] = subs.get("Subscriptions", [])
            except botocore.exceptions.ClientError:
                pass

            data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.warning(f"SNS collection failed: {exc}")

    return "sns", data


@collectors.collector(
    name="sqs",
    provider="aws",
    description="Collect SQS queues and policies",
    services=["sqs"],
)
def collect_sqs(session) -> Tuple[str, List[Dict[str, Any]]]:
    """Collect SQS queues with their policies and configuration."""
    sqs = session.client("sqs")
    data: List[Dict[str, Any]] = []

    try:
        queues = sqs.list_queues().get("QueueUrls", []) or []
        for queue_url in queues:
            record: Dict[str, Any] = {"QueueUrl": queue_url}

            # Queue attributes
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=["All"]
                )
                record["Attributes"] = attrs.get("Attributes", {})
            except botocore.exceptions.ClientError:
                pass

            data.append(record)
    except botocore.exceptions.ClientError as exc:
        log.warning(f"SQS collection failed: {exc}")

    return "sqs", data
