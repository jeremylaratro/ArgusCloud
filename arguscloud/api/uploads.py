"""Bulk file upload handling for ArgusCloud."""

from __future__ import annotations

import io
import json
import logging
import re
import threading
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class UploadStatus(Enum):
    """Upload job status."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class UploadProgress:
    """Progress tracking for an upload job."""
    total_files: int = 0
    processed_files: int = 0
    current_file: str = ""
    profiles_created: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


@dataclass
class UploadJob:
    """Represents a bulk upload job."""
    id: str
    status: UploadStatus
    progress: UploadProgress
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "id": self.id,
            "status": self.status.value,
            "created_at": self.created_at,
            "progress": {
                "total_files": self.progress.total_files,
                "processed_files": self.progress.processed_files,
                "current_file": self.progress.current_file,
                "profiles_created": self.progress.profiles_created,
                "errors": self.progress.errors,
                "started_at": self.progress.started_at,
                "completed_at": self.progress.completed_at,
            }
        }


class UploadManager:
    """Manages bulk upload jobs."""

    def __init__(self, max_jobs: int = 50):
        self._jobs: Dict[str, UploadJob] = {}
        self._lock = threading.Lock()
        self._max_jobs = max_jobs

    def create_job(self, total_files: int) -> UploadJob:
        """Create a new upload job."""
        with self._lock:
            if len(self._jobs) >= self._max_jobs:
                self._cleanup_old_jobs()

            job = UploadJob(
                id=str(uuid.uuid4()),
                status=UploadStatus.PENDING,
                progress=UploadProgress(total_files=total_files),
            )
            self._jobs[job.id] = job
            return job

    def get_job(self, job_id: str) -> Optional[UploadJob]:
        """Get a job by ID."""
        return self._jobs.get(job_id)

    def list_jobs(self, limit: int = 20) -> List[UploadJob]:
        """List recent jobs."""
        jobs = list(self._jobs.values())
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]

    def _cleanup_old_jobs(self):
        """Remove old completed/failed jobs."""
        completed = [
            j for j in self._jobs.values()
            if j.status in (UploadStatus.COMPLETED, UploadStatus.FAILED)
        ]
        completed.sort(key=lambda j: j.created_at)
        for job in completed[:len(completed) // 2]:
            del self._jobs[job.id]


# Global upload manager
_upload_manager: Optional[UploadManager] = None


def get_upload_manager() -> UploadManager:
    """Get the global upload manager instance."""
    global _upload_manager
    if _upload_manager is None:
        _upload_manager = UploadManager()
    return _upload_manager


def parse_jsonl(content: str) -> List[Dict]:
    """Parse JSONL content into a list of dicts."""
    lines = content.strip().split('\n')
    result = []
    for line in lines:
        line = line.strip()
        if line:
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return result


def extract_account_id(nodes: List[Dict]) -> Optional[str]:
    """Extract AWS account ID from node data."""
    for node in nodes:
        node_id = node.get("id", "")
        match = re.search(r'arn:aws:[^:]*:[^:]*:(\d{12})', node_id)
        if match:
            return match.group(1)

        props = node.get("properties", {})
        account = props.get("account")
        if account and re.match(r'^\d{12}$', str(account)):
            return str(account)

    return None


def process_upload_files(
    job: UploadJob,
    files: Dict[str, bytes],
    driver,
) -> None:
    """Process uploaded files and save to Neo4j.

    Args:
        job: The upload job
        files: Dict of filename -> file content bytes
        driver: Neo4j driver
    """
    job.status = UploadStatus.PROCESSING
    job.progress.started_at = datetime.utcnow().isoformat()

    try:
        # Group files by potential profile (based on directory structure or naming)
        file_groups = group_files_by_profile(files)

        for group_name, group_files in file_groups.items():
            job.progress.current_file = group_name

            try:
                # Parse nodes and edges
                nodes_content = group_files.get("nodes.jsonl", b"")
                edges_content = group_files.get("edges.jsonl", b"")
                attack_paths_content = group_files.get("attack_paths.jsonl", b"")

                if not nodes_content and not edges_content:
                    job.progress.errors.append(f"{group_name}: Missing nodes.jsonl and edges.jsonl")
                    continue

                nodes = parse_jsonl(nodes_content.decode("utf-8")) if nodes_content else []
                edges = parse_jsonl(edges_content.decode("utf-8")) if edges_content else []

                # Merge attack paths into edges
                if attack_paths_content:
                    attack_paths = parse_jsonl(attack_paths_content.decode("utf-8"))
                    edges.extend(attack_paths)

                if not nodes and not edges:
                    job.progress.errors.append(f"{group_name}: No data found in files")
                    continue

                # Generate profile name
                account_id = extract_account_id(nodes)
                if account_id:
                    profile_name = f"AWS-{account_id}"
                elif group_name and group_name != "default":
                    profile_name = group_name
                else:
                    profile_name = f"Upload-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

                # Save to Neo4j
                save_profile_data(driver, profile_name, nodes, edges)
                job.progress.profiles_created.append(profile_name)

            except Exception as e:
                logger.error(f"Error processing {group_name}: {e}")
                job.progress.errors.append(f"{group_name}: {str(e)}")

            job.progress.processed_files += 1

        job.status = UploadStatus.COMPLETED
        job.progress.completed_at = datetime.utcnow().isoformat()
        job.progress.current_file = ""

    except Exception as e:
        logger.exception(f"Upload job failed: {e}")
        job.status = UploadStatus.FAILED
        job.progress.errors.append(str(e))


def group_files_by_profile(files: Dict[str, bytes]) -> Dict[str, Dict[str, bytes]]:
    """Group files by profile based on directory structure.

    Files can be organized as:
    - Flat: nodes.jsonl, edges.jsonl (single profile)
    - By directory: account1/nodes.jsonl, account1/edges.jsonl, account2/nodes.jsonl, ...

    Returns:
        Dict of profile_name -> {filename: content}
    """
    groups: Dict[str, Dict[str, bytes]] = {}

    for filename, content in files.items():
        # Normalize path
        filename = filename.replace("\\", "/")
        parts = filename.split("/")

        if len(parts) > 1:
            # Has directory structure - use first directory as profile
            profile = parts[0]
            base_name = parts[-1].lower()
        else:
            # Flat structure
            profile = "default"
            base_name = filename.lower()

        if profile not in groups:
            groups[profile] = {}

        # Only include relevant files
        if base_name in ("nodes.jsonl", "edges.jsonl", "attack_paths.jsonl"):
            groups[profile][base_name] = content

    return groups


def save_profile_data(driver, profile_name: str, nodes: List[Dict], edges: List[Dict]) -> None:
    """Save nodes and edges to Neo4j under a profile."""
    import json
    from datetime import datetime

    def flatten_props(props):
        """Flatten nested objects to JSON strings."""
        result = {}
        for key, value in props.items():
            if value is None:
                continue
            elif isinstance(value, (dict, list)):
                result[key] = json.dumps(value)
            elif isinstance(value, (str, int, float, bool)):
                result[key] = value
            else:
                result[key] = str(value)
        return result

    with driver.session() as session:
        now = datetime.utcnow().isoformat()

        # Create/update profile
        session.run("""
            MERGE (p:Profile {name: $name})
            ON CREATE SET p.created_at = $now, p.updated_at = $now
            ON MATCH SET p.updated_at = $now
        """, name=profile_name, now=now)

        # Delete existing data (overwrite mode)
        session.run("""
            MATCH (n:Resource {profile: $name})
            DETACH DELETE n
        """, name=profile_name)

        # Insert nodes
        for node in nodes:
            props = flatten_props(node.get("properties", {}))
            props["id"] = node.get("id", str(uuid.uuid4()))
            props["type"] = node.get("type") or "Unknown"
            props["provider"] = node.get("provider") or "aws"
            props["profile"] = profile_name

            session.run("""
                MERGE (n:Resource {id: $id, profile: $profile})
                SET n += $props
            """, id=props["id"], profile=profile_name, props=props)

        # Insert edges
        for edge in edges:
            props = flatten_props(edge.get("properties", {}))
            edge_type = edge.get("type") or "REL"
            props["type"] = edge_type
            props["profile"] = profile_name

            src = edge.get("src", "")
            dst = edge.get("dst", "")

            if not src or not dst:
                continue

            # Ensure nodes exist
            session.run("""
                MERGE (src:Resource {id: $src_id, profile: $profile})
                ON CREATE SET src.type = 'External', src.provider = 'external'
            """, src_id=src, profile=profile_name)

            session.run("""
                MERGE (dst:Resource {id: $dst_id, profile: $profile})
                ON CREATE SET dst.type = 'External', dst.provider = 'external'
            """, dst_id=dst, profile=profile_name)

            session.run("""
                MATCH (a:Resource {id: $src, profile: $profile})
                MATCH (b:Resource {id: $dst, profile: $profile})
                MERGE (a)-[r:REL]->(b)
                SET r += $props
            """, src=src, dst=dst, profile=profile_name, props=props)

        # Update profile counts
        session.run("""
            MATCH (p:Profile {name: $name})
            SET p.node_count = $node_count, p.edge_count = $edge_count
        """, name=profile_name, node_count=len(nodes), edge_count=len(edges))
