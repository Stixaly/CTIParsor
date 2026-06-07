"""
Storage abstraction for pipeline job state.

Decouples the worker orchestration logic from SQLite so that:
  - Unit tests can use InMemoryJobStorage without touching the database
  - A future swap to Postgres or Redis requires changing only this module

Production usage:
    storage = SQLiteJobStorage()

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


class SQLiteJobStorage(JobStorage):
    """Production implementation — thin wrapper around api.db functions."""

    def update_status(self, job_id: str, status: str) -> None:
        from api import db
        db.set_job_status(job_id, status)

    def save_entities(self, job_id: str, entities: list) -> None:
        from api import db
        conn = db.get_conn()
        with conn:
            conn.executemany(
                """INSERT OR REPLACE INTO entities
                   (id, job_id, value, entity_type, context, confidence, mitre_id, accepted, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        f"{job_id}_{e.value}_{e.entity_type.value}",
                        job_id,
                        e.value,
                        e.entity_type.value,
                        e.context,
                        e.confidence,
                        e.mitre_id,
                        None,
                        e.source,
                    )
                    for e in entities
                ],
            )
            conn.commit()

    def save_bundle(self, job_id: str, bundle_json: str) -> None:
        from api import db
        conn = db.get_conn()
        with conn:
            conn.execute(
                "UPDATE jobs SET bundle_json=?, updated_at=? WHERE id=?",
                (bundle_json, db.now_iso(), job_id),
            )
            conn.commit()

    def save_llm_result(self, job_id: str, llm_result_json: str) -> None:
        from api import db
        conn = db.get_conn()
        with conn:
            conn.execute(
                "UPDATE jobs SET llm_result_json=?, updated_at=? WHERE id=?",
                (llm_result_json, db.now_iso(), job_id),
            )
            conn.commit()

    def emit_progress(self, job_id: str, event_type: str, data: dict) -> None:
        from api import db
        db.emit_progress(job_id, event_type, data)


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
