"""AWS collection job management for web UI credential ingestion."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class JobStatus(Enum):
    """Collection job status."""
    PENDING = "pending"
    VALIDATING = "validating"
    COLLECTING = "collecting"
    NORMALIZING = "normalizing"
    ANALYZING = "analyzing"
    SAVING = "saving"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class CollectionProgress:
    """Progress tracking for a collection job."""
    current_service: str = ""
    completed_services: List[str] = field(default_factory=list)
    total_services: int = 0
    nodes_collected: int = 0
    edges_collected: int = 0
    errors: List[str] = field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


@dataclass
class CollectionJob:
    """Represents an AWS collection job."""
    id: str
    status: JobStatus
    progress: CollectionProgress
    account_id: Optional[str] = None
    profile_name: Optional[str] = None
    error: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "id": self.id,
            "status": self.status.value,
            "account_id": self.account_id,
            "profile_name": self.profile_name,
            "error": self.error,
            "created_at": self.created_at,
            "progress": {
                "current_service": self.progress.current_service,
                "completed_services": self.progress.completed_services,
                "total_services": self.progress.total_services,
                "nodes_collected": self.progress.nodes_collected,
                "edges_collected": self.progress.edges_collected,
                "errors": self.progress.errors,
                "started_at": self.progress.started_at,
                "completed_at": self.progress.completed_at,
            }
        }


class JobManager:
    """Manages collection jobs in memory."""

    def __init__(self, max_jobs: int = 100):
        self._jobs: Dict[str, CollectionJob] = {}
        self._lock = threading.Lock()
        self._max_jobs = max_jobs

    def create_job(self, services: List[str]) -> CollectionJob:
        """Create a new collection job.

        Args:
            services: List of AWS services to collect

        Returns:
            New CollectionJob instance
        """
        with self._lock:
            # Cleanup old completed jobs if at capacity
            if len(self._jobs) >= self._max_jobs:
                self._cleanup_old_jobs()

            job = CollectionJob(
                id=str(uuid.uuid4()),
                status=JobStatus.PENDING,
                progress=CollectionProgress(total_services=len(services)),
            )
            self._jobs[job.id] = job
            return job

    def get_job(self, job_id: str) -> Optional[CollectionJob]:
        """Get a job by ID."""
        return self._jobs.get(job_id)

    def update_job(self, job_id: str, **kwargs) -> Optional[CollectionJob]:
        """Update job fields."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                for key, value in kwargs.items():
                    if hasattr(job, key):
                        setattr(job, key, value)
            return job

    def list_jobs(self, limit: int = 50) -> List[CollectionJob]:
        """List recent jobs."""
        jobs = list(self._jobs.values())
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]

    def cancel_job(self, job_id: str) -> bool:
        """Mark a job as cancelled."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.status not in (JobStatus.COMPLETED, JobStatus.FAILED):
                job.status = JobStatus.CANCELLED
                return True
            return False

    def _cleanup_old_jobs(self):
        """Remove old completed/failed jobs."""
        completed = [
            j for j in self._jobs.values()
            if j.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED)
        ]
        completed.sort(key=lambda j: j.created_at)
        # Remove oldest half
        for job in completed[:len(completed) // 2]:
            del self._jobs[job.id]


# Global job manager
_job_manager: Optional[JobManager] = None


def get_job_manager() -> JobManager:
    """Get the global job manager instance."""
    global _job_manager
    if _job_manager is None:
        _job_manager = JobManager()
    return _job_manager


def run_collection_job(
    job: CollectionJob,
    credentials: "AWSCredentials",
    services: List[str],
    driver,
    profile_name: Optional[str] = None
) -> None:
    """Run a collection job in a background thread.

    Args:
        job: The job to run
        credentials: AWS credentials (cleared after use)
        services: List of services to collect
        driver: Neo4j driver for saving results
        profile_name: Optional profile name (auto-generated if None)
    """
    from ..collectors.session import create_session, validate_credentials, CallerIdentity
    from awshound.collector import collect_services
    from awshound.normalize import normalize
    from arguscloud.rules import analyze

    try:
        # Update job status
        job.status = JobStatus.VALIDATING
        job.progress.started_at = datetime.utcnow().isoformat()

        # Validate credentials
        try:
            identity = validate_credentials(credentials)
            job.account_id = identity.account_id
        except ValueError as e:
            job.status = JobStatus.FAILED
            job.error = str(e)
            return

        # Generate profile name if not provided
        if not profile_name:
            profile_name = f"AWS-{identity.account_id}"
        job.profile_name = profile_name

        # Create session
        session = create_session(credentials)

        # Clear credentials immediately after session creation
        credentials.clear()

        # Collect services
        job.status = JobStatus.COLLECTING
        raw_data = {}

        for service in services:
            if job.status == JobStatus.CANCELLED:
                return

            job.progress.current_service = service
            try:
                # Use the existing collector
                result = collect_services(session, services=[service])
                if result:
                    raw_data.update(result)
                job.progress.completed_services.append(service)
            except Exception as e:
                # Log only error type to avoid information leakage
                logger.warning(f"Failed to collect {service}: {type(e).__name__}")
                logger.debug(f"Full error for {service}: {e}")
                job.progress.errors.append(f"{service}: {type(e).__name__}")

        # Normalize
        job.status = JobStatus.NORMALIZING
        job.progress.current_service = "normalizing"

        try:
            nodes, edges = normalize(raw_data)
            job.progress.nodes_collected = len(nodes)
            job.progress.edges_collected = len(edges)
        except Exception as e:
            logger.error(f"Normalization failed: {e}")
            job.status = JobStatus.FAILED
            job.error = f"Normalization failed: {str(e)}"
            return

        # Analyze (run security rules)
        job.status = JobStatus.ANALYZING
        job.progress.current_service = "analyzing"

        try:
            from arguscloud.core.graph import GraphData
            graph = GraphData(nodes=nodes, edges=edges)
            attack_paths = analyze(graph)
            edges.extend(attack_paths)
            job.progress.edges_collected = len(edges)
        except Exception as e:
            logger.warning(f"Analysis failed: {e}")
            job.progress.errors.append(f"Analysis: {str(e)}")

        # Save to Neo4j
        job.status = JobStatus.SAVING
        job.progress.current_service = "saving"

        try:
            _save_to_neo4j(driver, profile_name, nodes, edges)
        except Exception as e:
            logger.error(f"Save failed: {e}")
            job.status = JobStatus.FAILED
            job.error = f"Failed to save to database: {str(e)}"
            return

        # Complete
        job.status = JobStatus.COMPLETED
        job.progress.current_service = ""
        job.progress.completed_at = datetime.utcnow().isoformat()

    except Exception as e:
        logger.exception(f"Collection job failed: {e}")
        job.status = JobStatus.FAILED
        job.error = str(e)
    finally:
        # Ensure credentials are cleared
        try:
            credentials.clear()
        except Exception as e:
            logger.error(f"SECURITY: Failed to clear credentials: {type(e).__name__}")
            # Force garbage collection as fallback
            import gc
            gc.collect()


def _save_to_neo4j(driver, profile_name: str, nodes: List, edges: List) -> None:
    """Save collected data to Neo4j under a profile."""
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

        # Delete existing data for this profile (overwrite mode)
        session.run("""
            MATCH (n:Resource {profile: $name})
            DETACH DELETE n
        """, name=profile_name)

        # Insert nodes
        for node in nodes:
            props = flatten_props(node.properties if hasattr(node, 'properties') else {})
            props["id"] = node.id if hasattr(node, 'id') else str(node)
            props["type"] = node.type if hasattr(node, 'type') else "Unknown"
            props["provider"] = node.provider.value if hasattr(node, 'provider') else "aws"
            props["profile"] = profile_name

            session.run("""
                MERGE (n:Resource {id: $id, profile: $profile})
                SET n += $props
            """, id=props["id"], profile=profile_name, props=props)

        # Insert edges
        for edge in edges:
            props = flatten_props(edge.properties if hasattr(edge, 'properties') else {})
            edge_type = edge.type if hasattr(edge, 'type') else "REL"
            props["type"] = edge_type
            props["profile"] = profile_name

            src = edge.src if hasattr(edge, 'src') else str(edge)
            dst = edge.dst if hasattr(edge, 'dst') else str(edge)

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
