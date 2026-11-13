"""
Storage interface for pipeline job state, and its test double.

The production writes are made by api/worker.py and api/db.py (PostgreSQL only,
ADR-0053).  The SQLiteJobStorage wrapper that used to sit here had no caller left
and was removed (#441).

Test usage:
    storage = InMemoryJobStorage()
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class JobStorage(ABC):
    """Where a pipeline job records its state: status, entities, bundle, LLM result and progress events."""

    @abstractmethod
    def update_status(self, job_id: str, status: str) -> None:
        """Set the status of the job."""

    @abstractmethod
    def save_entities(self, job_id: str, entities: list) -> None:
        """Store the entities that the job extracted."""

    @abstractmethod
    def save_bundle(self, job_id: str, bundle_json: str) -> None:
        """Store the job's STIX bundle, as JSON text."""

    @abstractmethod
    def save_llm_result(self, job_id: str, llm_result_json: str) -> None:
        """Store the job's raw LLM result, as JSON text."""

    @abstractmethod
    def emit_progress(self, job_id: str, event_type: str, data: dict) -> None:
        """Record one progress event of the job: its type and its data."""


class InMemoryJobStorage(JobStorage):
    """Test-only implementation — no database required."""

    def __init__(self) -> None:
        self.statuses: dict[str, str] = {}
        self.entities: dict[str, list] = {}
        self.bundles: dict[str, str] = {}
        self.llm_results: dict[str, str] = {}
        self.events: list[tuple[str, str, dict]] = []

    def update_status(self, job_id: str, status: str) -> None:
        """Keep the status of the job in memory."""
        self.statuses[job_id] = status

    def save_entities(self, job_id: str, entities: list) -> None:
        """Keep a copy of the entities of the job, replacing any kept before."""
        self.entities[job_id] = list(entities)

    def save_bundle(self, job_id: str, bundle_json: str) -> None:
        """Keep the bundle of the job in memory."""
        self.bundles[job_id] = bundle_json

    def save_llm_result(self, job_id: str, llm_result_json: str) -> None:
        """Keep the LLM result of the job in memory."""
        self.llm_results[job_id] = llm_result_json

    def emit_progress(self, job_id: str, event_type: str, data: dict) -> None:
        """Append the progress event to the list in `events`."""
        self.events.append((job_id, event_type, data))
