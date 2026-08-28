# pipeline/figure_store.py
from __future__ import annotations

import json
import logging
import sqlite3
import uuid

from api.db import get_conn, now_iso, transaction
from pipeline.stage1f_figures import FigureSpan
from pipeline.vlm import FigureEdge, FigureRead

logger = logging.getLogger(__name__)


def read_to_json(read: FigureRead) -> str:
    """Serialize a FigureRead to a JSON string."""
    data = {
        "kind": read.kind,
        "verbatim_text": read.verbatim_text,
        "edges": [
            {"src": e.src, "dst": e.dst, "label": e.label} for e in read.edges
        ],
        "iocs": read.iocs,
        "provider": read.provider,
        "model": read.model,
        "elapsed_s": read.elapsed_s,
        "input_tokens": read.input_tokens,
        "output_tokens": read.output_tokens,
        "error": read.error,
    }
    return json.dumps(data, ensure_ascii=False)


def read_from_json(raw: str) -> FigureRead | None:
    """Deserialize a JSON string into a FigureRead, returning None on failure."""
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None

        kind = data.get("kind")
        if not isinstance(kind, str):
            kind = "unread"

        verbatim_text_raw = data.get("verbatim_text")
        verbatim_text = [
            s for s in verbatim_text_raw if isinstance(s, str)
        ] if isinstance(verbatim_text_raw, list) else []

        iocs_raw = data.get("iocs")
        iocs = [s for s in iocs_raw if isinstance(s, str)] if isinstance(iocs_raw, list) else []

        edges_raw = data.get("edges")
        edges: list[FigureEdge] = []
        if isinstance(edges_raw, list):
            for e in edges_raw:
                if isinstance(e, dict):
                    src = e.get("src")
                    dst = e.get("dst")
                    if isinstance(src, str) and isinstance(dst, str) and src and dst:
                        label = e.get("label")
                        if not isinstance(label, str):
                            label = ""
                        edges.append(FigureEdge(src=src, dst=dst, label=label))

        provider = data.get("provider")
        if not isinstance(provider, str):
            provider = ""

        model = data.get("model")
        if not isinstance(model, str):
            model = ""

        elapsed_s_raw = data.get("elapsed_s")
        try:
            elapsed_s = float(elapsed_s_raw)
        except (TypeError, ValueError):
            elapsed_s = 0.0

        input_tokens_raw = data.get("input_tokens")
        try:
            input_tokens = int(input_tokens_raw) if input_tokens_raw is not None else None
        except (TypeError, ValueError):
            input_tokens = None

        output_tokens_raw = data.get("output_tokens")
        try:
            output_tokens = int(output_tokens_raw) if output_tokens_raw is not None else None
        except (TypeError, ValueError):
            output_tokens = None

        error = data.get("error")
        if not isinstance(error, str):
            error = None

        return FigureRead(
            kind=kind,
            verbatim_text=verbatim_text,
            edges=edges,
            iocs=iocs,
            provider=provider,
            model=model,
            elapsed_s=elapsed_s,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            error=error,
        )
    except Exception:
        logger.warning("Failed to parse FigureRead from JSON", exc_info=True)
        return None


class SqliteReadCache:
    """ReadCache backed by the `figure_reads` table."""

    def get(self, sha256: str, model: str, prompt_version: int) -> FigureRead | None:
        """Retrieve a cached FigureRead."""
        if not sha256:
            return None
        try:
            with get_conn() as conn:
                cur = conn.execute(
                    "SELECT read_json FROM figure_reads WHERE sha256=? AND model=? AND prompt_version=?",
                    (sha256, model, prompt_version),
                )
                row = cur.fetchone()
                if row is None:
                    return None
                return read_from_json(row["read_json"])
        except sqlite3.Error:
            logger.warning("Failed to get from cache", exc_info=True)
            return None

    def put(self, sha256: str, model: str, prompt_version: int, read: FigureRead) -> None:
        """Store a FigureRead in the cache."""
        if not sha256 or read.kind == "unread":
            return
        try:
            with get_conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO figure_reads "
                    "(sha256, model, prompt_version, read_json, created_at) "
                    "VALUES (?,?,?,?,?)",
                    (sha256, model, prompt_version, read_to_json(read), now_iso()),
                )
        except sqlite3.Error:
            logger.warning("Failed to put to cache", exc_info=True)


def save_spans(job_id: str, spans: list[FigureSpan], provider: str) -> int:
    """Save figure spans to the database, replacing existing ones for the job."""
    try:
        # `transaction`, not `with get_conn()`: the DELETE and the INSERTs must
        # be all-or-nothing.  Under autocommit the plain with-block committed the
        # DELETE immediately, so a failure part-way through left the job with
        # some of its figures gone and none of the new ones written.
        with transaction(get_conn()) as conn:
            conn.execute("DELETE FROM report_figures WHERE job_id=?", (job_id,))
            for span in spans:
                bbox_str = ",".join(f"{v:.2f}" for v in span.bbox)
                conn.execute(
                    "INSERT INTO report_figures "
                    "(id, job_id, ordinal, page, bbox, kind, char_start, "
                    " char_end, provider, model, sha256) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        str(uuid.uuid4()),
                        job_id,
                        span.ordinal,
                        span.page,
                        bbox_str,
                        span.kind,
                        span.char_start,
                        span.char_end,
                        provider,
                        span.model,
                        span.sha256,
                    ),
                )
            return len(spans)
    except sqlite3.Error:
        logger.warning("Failed to save spans", exc_info=True)
        return 0


def load_spans(job_id: str) -> list[FigureSpan]:
    """Load figure spans for a job."""
    try:
        with get_conn() as conn:
            cur = conn.execute(
                "SELECT ordinal, page, bbox, kind, char_start, char_end, "
                "       model, sha256 "
                "FROM report_figures WHERE job_id=? ORDER BY ordinal",
                (job_id,),
            )
            rows = cur.fetchall()
            spans: list[FigureSpan] = []
            for row in rows:
                bbox_parts = row["bbox"].split(",")
                try:
                    bbox = tuple(float(p) for p in bbox_parts)
                    if len(bbox) != 4:
                        bbox = (0.0, 0.0, 0.0, 0.0)
                except ValueError:
                    bbox = (0.0, 0.0, 0.0, 0.0)
                spans.append(
                    FigureSpan(
                        ordinal=row["ordinal"],
                        page=row["page"],
                        bbox=bbox,
                        kind=row["kind"],
                        char_start=row["char_start"],
                        char_end=row["char_end"],
                        model=row["model"],
                        sha256=row["sha256"],
                    )
                )
            return spans
    except sqlite3.Error:
        logger.warning("Failed to load spans", exc_info=True)
        return []


def figure_at_offset(job_id: str, offset: int) -> FigureSpan | None:
    """Find the figure span containing the given character offset."""
    try:
        with get_conn() as conn:
            cur = conn.execute(
                "SELECT ordinal, page, bbox, kind, char_start, char_end, "
                "       model, sha256 "
                "FROM report_figures "
                "WHERE job_id=? AND char_start<=? AND char_end>? "
                "ORDER BY char_start DESC LIMIT 1",
                (job_id, offset, offset),
            )
            row = cur.fetchone()
            if row is None:
                return None
            bbox_parts = row["bbox"].split(",")
            try:
                bbox = tuple(float(p) for p in bbox_parts)
                if len(bbox) != 4:
                    bbox = (0.0, 0.0, 0.0, 0.0)
            except ValueError:
                bbox = (0.0, 0.0, 0.0, 0.0)
            return FigureSpan(
                ordinal=row["ordinal"],
                page=row["page"],
                bbox=bbox,
                kind=row["kind"],
                char_start=row["char_start"],
                char_end=row["char_end"],
                model=row["model"],
                sha256=row["sha256"],
            )
    except sqlite3.Error:
        logger.warning("Failed to find figure at offset", exc_info=True)
        return None
