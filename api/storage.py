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

    @abstractmethod
    def update_status(self, job_id: str, status: str) -> None: ...

    @abstractmethod
    def save_entities(self, job_id: str, entities: list) -> None: ...

    @abstractmethod
    def save_bundle(self, job_id: str, bundle_json: str) -> None: ...

    @abstractmethod
    def save_llm_result(self, job_id: str, llm_result_json: str) -> None: ...

    @abstractmethod
    def emit_progress(self, job_id: str, event_type: str, data: dict) -> None: ...


class InMemoryJobStorage(JobStorage):
    """Test-only implementation — no database required."""

    def __init__(self) -> None:
        self.statuses: dict[str, str] = {}
        self.entities: dict[str, list] = {}
        self.bundles: dict[str, str] = {}
        self.llm_results: dict[str, str] = {}
        self.events: list[tuple[str, str, dict]] = []

    def update_status(self, job_id: str, status: str) -> None:
        self.statuses[job_id] = status

    def save_entities(self, job_id: str, entities: list) -> None:
        self.entities[job_id] = list(entities)

    def save_bundle(self, job_id: str, bundle_json: str) -> None:
        self.bundles[job_id] = bundle_json

    def save_llm_result(self, job_id: str, llm_result_json: str) -> None:
        self.llm_results[job_id] = llm_result_json

    def emit_progress(self, job_id: str, event_type: str, data: dict) -> None:
        self.events.append((job_id, event_type, data))
