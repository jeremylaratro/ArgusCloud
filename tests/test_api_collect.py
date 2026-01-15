"""Tests for arguscloud.api.collect module.

This module tests collection job management including job creation,
status tracking, cancellation, and the collection workflow.
"""

from __future__ import annotations

import pytest
import threading
import time
from unittest.mock import MagicMock, patch
from typing import List

from arguscloud.api.collect import (
    JobStatus,
    CollectionProgress,
    CollectionJob,
    JobManager,
    get_job_manager,
)


class TestJobStatus:
    """Tests for JobStatus enum."""

    def test_job_status_values(self):
        """Test all job status values exist."""
        assert JobStatus.PENDING.value == "pending"
        assert JobStatus.VALIDATING.value == "validating"
        assert JobStatus.COLLECTING.value == "collecting"
        assert JobStatus.NORMALIZING.value == "normalizing"
        assert JobStatus.ANALYZING.value == "analyzing"
        assert JobStatus.SAVING.value == "saving"
        assert JobStatus.COMPLETED.value == "completed"
        assert JobStatus.FAILED.value == "failed"
        assert JobStatus.CANCELLED.value == "cancelled"


class TestCollectionProgress:
    """Tests for CollectionProgress dataclass."""

    def test_collection_progress_defaults(self):
        """Test CollectionProgress with default values."""
        progress = CollectionProgress()

        assert progress.current_service == ""
        assert progress.completed_services == []
        assert progress.total_services == 0
        assert progress.nodes_collected == 0
        assert progress.edges_collected == 0
        assert progress.errors == []
        assert progress.started_at is None
        assert progress.completed_at is None

    def test_collection_progress_with_values(self):
        """Test CollectionProgress with custom values."""
        progress = CollectionProgress(
            current_service="iam",
            completed_services=["sts"],
            total_services=5,
            nodes_collected=100,
            edges_collected=50,
            errors=["s3: AccessDenied"],
            started_at="2024-01-01T00:00:00Z",
            completed_at=None
        )

        assert progress.current_service == "iam"
        assert len(progress.completed_services) == 1
        assert progress.total_services == 5
        assert progress.nodes_collected == 100


class TestCollectionJob:
    """Tests for CollectionJob dataclass."""

    def test_collection_job_creation(self):
        """Test CollectionJob creation with required fields."""
        job = CollectionJob(
            id="test-job-id",
            status=JobStatus.PENDING,
            progress=CollectionProgress(total_services=3)
        )

        assert job.id == "test-job-id"
        assert job.status == JobStatus.PENDING
        assert job.progress.total_services == 3
        assert job.account_id is None
        assert job.profile_name is None
        assert job.error is None

    def test_collection_job_to_dict(self):
        """Test CollectionJob serialization to dict."""
        job = CollectionJob(
            id="test-job-id",
            status=JobStatus.COLLECTING,
            progress=CollectionProgress(
                current_service="iam",
                completed_services=["sts"],
                total_services=5,
                nodes_collected=50
            ),
            account_id="123456789012",
            profile_name="test-profile"
        )

        result = job.to_dict()

        assert result["id"] == "test-job-id"
        assert result["status"] == "collecting"
        assert result["account_id"] == "123456789012"
        assert result["profile_name"] == "test-profile"
        assert result["progress"]["current_service"] == "iam"
        assert result["progress"]["completed_services"] == ["sts"]
        assert result["progress"]["nodes_collected"] == 50

    def test_collection_job_to_dict_includes_error(self):
        """Test CollectionJob serialization includes error."""
        job = CollectionJob(
            id="test-job-id",
            status=JobStatus.FAILED,
            progress=CollectionProgress(),
            error="Credential validation failed"
        )

        result = job.to_dict()

        assert result["status"] == "failed"
        assert result["error"] == "Credential validation failed"


class TestJobManager:
    """Tests for JobManager class."""

    @pytest.fixture
    def job_manager(self) -> JobManager:
        """Create a fresh JobManager instance."""
        return JobManager(max_jobs=10)

    def test_create_job_returns_job(self, job_manager: JobManager):
        """Test create_job returns a new CollectionJob."""
        services = ["iam", "s3", "ec2"]

        job = job_manager.create_job(services)

        assert job is not None
        assert job.id is not None
        assert job.status == JobStatus.PENDING
        assert job.progress.total_services == 3

    def test_create_job_generates_unique_ids(self, job_manager: JobManager):
        """Test create_job generates unique job IDs."""
        job1 = job_manager.create_job(["iam"])
        job2 = job_manager.create_job(["s3"])

        assert job1.id != job2.id

    def test_get_job_returns_existing_job(self, job_manager: JobManager):
        """Test get_job returns an existing job by ID."""
        job = job_manager.create_job(["iam"])

        retrieved = job_manager.get_job(job.id)

        assert retrieved is not None
        assert retrieved.id == job.id

    def test_get_job_returns_none_for_missing(self, job_manager: JobManager):
        """Test get_job returns None for non-existent job."""
        result = job_manager.get_job("nonexistent-id")

        assert result is None

    def test_update_job_modifies_job(self, job_manager: JobManager):
        """Test update_job modifies job fields."""
        job = job_manager.create_job(["iam"])

        updated = job_manager.update_job(
            job.id,
            status=JobStatus.COLLECTING,
            account_id="123456789012"
        )

        assert updated is not None
        assert updated.status == JobStatus.COLLECTING
        assert updated.account_id == "123456789012"

    def test_update_job_returns_none_for_missing(self, job_manager: JobManager):
        """Test update_job returns None for non-existent job."""
        result = job_manager.update_job(
            "nonexistent-id",
            status=JobStatus.FAILED
        )

        assert result is None

    def test_list_jobs_returns_all_jobs(self, job_manager: JobManager):
        """Test list_jobs returns all created jobs."""
        job_manager.create_job(["iam"])
        job_manager.create_job(["s3"])
        job_manager.create_job(["ec2"])

        jobs = job_manager.list_jobs()

        assert len(jobs) == 3

    def test_list_jobs_respects_limit(self, job_manager: JobManager):
        """Test list_jobs respects the limit parameter."""
        for i in range(5):
            job_manager.create_job([f"service-{i}"])

        jobs = job_manager.list_jobs(limit=2)

        assert len(jobs) == 2

    def test_list_jobs_orders_by_created_at_desc(self, job_manager: JobManager):
        """Test list_jobs returns jobs in reverse chronological order."""
        job1 = job_manager.create_job(["iam"])
        time.sleep(0.01)  # Small delay to ensure different timestamps
        job2 = job_manager.create_job(["s3"])

        jobs = job_manager.list_jobs()

        # Most recent job should be first
        assert jobs[0].id == job2.id
        assert jobs[1].id == job1.id

    def test_cancel_job_marks_pending_as_cancelled(self, job_manager: JobManager):
        """Test cancel_job marks pending job as cancelled."""
        job = job_manager.create_job(["iam"])

        result = job_manager.cancel_job(job.id)

        assert result is True
        assert job.status == JobStatus.CANCELLED

    def test_cancel_job_marks_collecting_as_cancelled(self, job_manager: JobManager):
        """Test cancel_job marks in-progress job as cancelled."""
        job = job_manager.create_job(["iam"])
        job.status = JobStatus.COLLECTING

        result = job_manager.cancel_job(job.id)

        assert result is True
        assert job.status == JobStatus.CANCELLED

    def test_cancel_job_returns_false_for_completed(self, job_manager: JobManager):
        """Test cancel_job returns False for already completed jobs."""
        job = job_manager.create_job(["iam"])
        job.status = JobStatus.COMPLETED

        result = job_manager.cancel_job(job.id)

        assert result is False
        assert job.status == JobStatus.COMPLETED

    def test_cancel_job_returns_false_for_missing(self, job_manager: JobManager):
        """Test cancel_job returns False for non-existent job."""
        result = job_manager.cancel_job("nonexistent-id")

        assert result is False

    def test_job_manager_cleans_up_old_jobs(self):
        """Test JobManager cleans up old jobs when at capacity."""
        manager = JobManager(max_jobs=5)

        # Create 5 jobs and mark some as completed
        for i in range(5):
            job = manager.create_job([f"service-{i}"])
            if i < 3:
                job.status = JobStatus.COMPLETED

        # Creating another should trigger cleanup
        new_job = manager.create_job(["new-service"])

        # Should have cleaned up some old jobs
        jobs = manager.list_jobs(limit=100)
        assert new_job in jobs


class TestGetJobManager:
    """Tests for get_job_manager singleton function."""

    def test_get_job_manager_returns_instance(self):
        """Test get_job_manager returns a JobManager instance."""
        with patch("arguscloud.api.collect._job_manager", None):
            manager = get_job_manager()

            assert manager is not None
            assert isinstance(manager, JobManager)

    def test_get_job_manager_returns_same_instance(self):
        """Test get_job_manager returns the same instance on multiple calls."""
        with patch("arguscloud.api.collect._job_manager", None):
            manager1 = get_job_manager()
            manager2 = get_job_manager()

            assert manager1 is manager2


class TestJobManagerThreadSafety:
    """Tests for JobManager thread safety."""

    def test_concurrent_job_creation(self):
        """Test concurrent job creation is thread-safe."""
        manager = JobManager(max_jobs=100)
        jobs_created: List[str] = []
        lock = threading.Lock()

        def create_jobs():
            for i in range(10):
                job = manager.create_job([f"service-{i}"])
                with lock:
                    jobs_created.append(job.id)

        threads = [threading.Thread(target=create_jobs) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All jobs should have unique IDs
        assert len(jobs_created) == 50
        assert len(set(jobs_created)) == 50

    def test_concurrent_job_updates(self):
        """Test concurrent job updates are thread-safe."""
        manager = JobManager()
        job = manager.create_job(["iam"])

        def update_job():
            for i in range(10):
                manager.update_job(
                    job.id,
                    progress=CollectionProgress(nodes_collected=i)
                )

        threads = [threading.Thread(target=update_job) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Job should still be valid
        result = manager.get_job(job.id)
        assert result is not None
