"""One pipeline for every entry point (ADR-0059).

The API worker, the CLI (`main.py`) and the benchmark harness used to run three
different sequences of stages.  The CLI skipped the gazetteer, the semantic TTP
stage, CyNER, GLiNER, the alias lists, type-conflict resolution and figures;
the `full` ATE benchmark sent the whole text as one chunk and quietly fell back
to regex + semantic when no LLM was configured.  A benchmark number therefore
did not describe what the application did.

`run_document()` is now that sequence, once.  What differs between callers is
not the stages but what happens around them — persisting to PostgreSQL,
emitting progress events, resuming a crashed Stage 3 — and that goes through
`Hooks`.  Every run returns a `RunResult` whose `stages` say which stage ran,
which was skipped (and why: disabled, model unavailable, no provider) and which
failed, so a caller can refuse a degraded run instead of scoring it.

Stage ids are the ones the progress events already use: 1, 1f, 2, 2b, 2c, 2d,
2e, 2g, 3, 3e, 3doc, 2f, 4, 5.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from api.logging_config import get_logger
from models.schemas import EntityType, RawEntity
from pipeline.env_flags import env_int

if TYPE_CHECKING:
    from pipeline.stage3_llm import LLMEnrichmentResult

logger = get_logger(__name__)

RAN, SKIPPED, FAILED = "ran", "skipped", "failed"

# Every stage the orchestrator knows, in the order it runs them.
STAGES: tuple[str, ...] = (
    "1", "1f", "2", "2b", "2c", "2d", "2e", "2g",
    "3", "3d", "3f", "3e", "3doc", "2f", "4", "4b", "4c", "5",
)

STAGE_LABELS: dict[str, str] = {
    "1": "ingestion", "1f": "figures", "2": "regex IoCs", "2b": "gazetteer",
    "2c": "semantic TTPs", "2d": "CyNER", "2e": "GLiNER", "2g": "alias lists",
    "3": "LLM enrichment", "3d": "relationship verification", "3f": "TTP verification",
    "3e": "cross-model consensus", "3doc": "document-level relations",
    "2f": "CVE enrichment", "4": "STIX mapping", "4b": "graph completion",
    "4c": "long-distance inference", "5": "validation",
}


class StageRequired(RuntimeError):
    """A stage the caller required did not run."""

    def __init__(self, outcome: StageOutcome):
        self.outcome = outcome
        super().__init__(
            f"stage {outcome.stage} ({STAGE_LABELS.get(outcome.stage, '?')}) was required "
            f"but {outcome.status}: {outcome.reason or 'no reason given'}"
        )


class RunAborted(Exception):
    """Raised by a hook to stop the run without it counting as a failure
    (the worker: another worker took the job's lease)."""


@dataclass
class StageOutcome:
    stage: str
    status: str
    reason: str = ""
    seconds: float = 0.0
    counts: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class RunOptions:
    """What to run.  `from_env()` is the one place the environment is read for
    these choices; every entry point starts there and overrides what it must."""

    disabled: frozenset[str] = frozenset()
    required: frozenset[str] = frozenset()
    # None = decide from the environment when the stage is reached.
    consensus: bool | None = None
    document_relations: bool | None = None
    verify_relationships: bool | None = None     # Stage 3d
    verify_ttps: bool | None = None              # Stage 3f
    llm_parallelism: int = 3
    checkpoint_every: int = 5

    @classmethod
    def from_env(cls, *, disabled=(), required=(), **overrides) -> RunOptions:
        """`PIPELINE_DISABLED_STAGES` (comma-separated ids, e.g. "2d,2e") turns
        stages off for every run of this process — an ablation through the API
        path itself.  `disabled` adds to it."""
        from pipeline.stage3_llm import document_level_relations_enabled
        from pipeline.stage3d_verify import verify_enabled as rel_verify_enabled
        from pipeline.stage3e_consensus import consensus_enabled
        from pipeline.stage3f_ttp_verify import verify_enabled as ttp_verify_enabled

        values: dict[str, Any] = {
            "consensus": consensus_enabled(),
            "document_relations": document_level_relations_enabled(),
            "verify_relationships": rel_verify_enabled(),
            "verify_ttps": ttp_verify_enabled(),
            "llm_parallelism": env_int("LLM_PARALLELISM", default=3),
            "checkpoint_every": env_int("CHECKPOINT_EVERY", default=5),
        }
        values.update(overrides)
        env_disabled = {s.strip() for s in os.getenv("PIPELINE_DISABLED_STAGES", "").split(",")
                        if s.strip()}
        return cls(disabled=frozenset(disabled) | env_disabled, required=frozenset(required),
                   **values)

    def __post_init__(self) -> None:
        unknown = (set(self.disabled) | set(self.required)) - set(STAGES)
        if unknown:
            raise ValueError(f"unknown stage id(s): {', '.join(sorted(unknown))}; "
                             f"known: {', '.join(STAGES)}")

    def switch(self, stage: str, configured: bool | None, default: Callable[[], bool]) -> bool:
        """Effective on/off for an optional stage: off when disabled, else the
        configured value, else the environment's."""
        if stage in self.disabled:
            return False
        return configured if configured is not None else default()


@dataclass
class Document:
    """The input.  Either `file_path` (ingested by Stage 1) or `text` (already
    extracted — Stage 1 then only refangs it)."""

    file_path: str | None = None
    text: str | None = None
    original_filename: str = ""
    # The PDF whose figures Stage 1f reads; None = derived from file_path.
    figure_pdf: Path | None = None
    tlp_level: str | None = None
    pap_level: str | None = None
    # Where Stage 5 writes the bundle; None = Stage 5 is skipped.
    output_path: str | None = None

    @property
    def name(self) -> str:
        return self.original_filename or (Path(self.file_path).name if self.file_path else "text")

    @property
    def report_name(self) -> str:
        return re.sub(r"[^\w\-]", "_", Path(self.name).stem)


class Hooks:
    """What a caller does around the stages.  Every method may be left as is."""

    #: Stage 3 crash-resume store; None = no resume.
    checkpoint: FileCheckpoint | None = None

    def progress(self, event: str, data: dict) -> None:
        """A progress event, with the payloads the review UI already consumes."""

    def check_timeout(self) -> None:
        """Raise to stop the run (called between stages and between LLM chunks)."""

    def text_ready(self, text: str, figure_spans: list, figure_provider: str) -> None:
        """The final report text (refanged, figures appended) is known."""

    def extraction_ready(self, entities: list[RawEntity], llm_result: LLMEnrichmentResult,
                         text: str) -> None:
        """Stages 2-3 are done; the first hard-to-undo write belongs here.
        Raise RunAborted to stop before Stage 4."""

    def policy(self) -> dict | None:
        """The relationship policy Stage 4 applies (read when Stage 4 starts)."""
        return None

    def policy_used(self, policy: dict | None) -> None:
        """Stage 4 is about to run under `policy` — record the run config here."""


@dataclass
class RunResult:
    document: Document
    stages: list[StageOutcome] = field(default_factory=list)
    text: str = ""
    reference_date: datetime | None = None
    chunks: list[str] = field(default_factory=list)
    entities_per_chunk: list[list[RawEntity]] = field(default_factory=list)
    entities: list[RawEntity] = field(default_factory=list)
    gazetteer: list[RawEntity] = field(default_factory=list)
    semantic_ttps: list[RawEntity] = field(default_factory=list)
    cyner: list[RawEntity] = field(default_factory=list)
    gliner: list[RawEntity] = field(default_factory=list)
    alias_list: list[RawEntity] = field(default_factory=list)
    figure_spans: list = field(default_factory=list)
    figure_provider: str = ""
    llm_result: LLMEnrichmentResult | None = None
    policy: dict | None = None
    bundle: Any = None
    ioc_coverage: dict | None = None
    synthesis: dict | None = None
    valid: bool | None = None

    def outcome(self, stage: str) -> StageOutcome | None:
        return next((o for o in self.stages if o.stage == stage), None)

    def ran(self, stage: str) -> bool:
        o = self.outcome(stage)
        return o is not None and o.status == RAN

    def not_run(self) -> list[StageOutcome]:
        return [o for o in self.stages if o.status != RAN]

    def stage_report(self) -> list[dict]:
        return [o.as_dict() for o in self.stages]


# ── Stage 3 checkpoint ───────────────────────────────────────────────────────


class FileCheckpoint:
    """Stage 3 crash-resume file, written atomically (tmp → rename).

    A checkpoint is only resumed when its fingerprint matches: the chunk texts,
    the provider and model, the prompts' hash and the options that change
    Stage 3 output.  The chunk COUNT alone used to be the check, so a job
    re-run on an edited document, another model or another prompt with the
    same number of chunks resumed results that belonged to a different run.
    """

    def __init__(self, path: Path, job_id: str):
        self.path = path
        self.job_id = job_id

    def load(self, fingerprint: str, total: int) -> tuple[dict[int, Any], str]:
        from pipeline.stage3_llm import LLMEnrichmentResult

        if not self.path.exists():
            return {}, ""
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("fingerprint") != fingerprint or data.get("total_chunks") != total:
                logger.warning("[Stage 3] Checkpoint belongs to another run (fingerprint or "
                               "chunk count differs) — ignoring")
                return {}, ""
            loaded = {int(k): LLMEnrichmentResult.model_validate_json(v)
                      for k, v in data.get("chunks", {}).items()}
            return loaded, data.get("saved_at", "")
        except Exception as exc:
            logger.warning(f"[Stage 3] Could not load checkpoint ({exc}) — starting fresh")
            return {}, ""

    def save(self, fingerprint: str, total: int, results: dict[int, Any]) -> None:
        from api.db import now_iso

        data = {
            "job_id": self.job_id,
            "fingerprint": fingerprint,
            "total_chunks": total,
            "saved_at": now_iso(),
            "chunks": {str(k): v.model_dump_json() for k, v in results.items()},
        }
        tmp = self.path.with_suffix(".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(data), encoding="utf-8")
            tmp.replace(self.path)
            logger.debug(f"[Stage 3] Checkpoint saved ({len(results)}/{total} chunks)")
        except Exception as exc:
            logger.warning(f"[Stage 3] Checkpoint save failed: {exc}")

    def clear(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except Exception:
            pass


def _entities_key(entities: list) -> list:
    return sorted((e.value, e.entity_type.value, e.mitre_id or "", round(e.confidence, 4))
                  for e in entities)


def stage3_fingerprint(settings: dict, inputs: dict) -> str:
    """Everything that decides what Stage 3 returns: `settings` from
    stage3_llm.stage3_settings (models, every prompt, sampling, 3d/3f
    switches, consensus model, limits) and `inputs` — the chunks and every
    argument enrich_chunk receives with them."""
    payload = json.dumps({"settings": settings, "inputs": inputs}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ── Helpers shared with the finalize path ────────────────────────────────────


def figure_source_pdf(file_path: str | Path | None) -> Path | None:
    """The PDF whose figures belong to this document, or None when there is none.

    An upload is its own source.  A URL capture is not: ADR-0029 deliberately
    feeds the pipeline `{job_id}.txt`, the rendered DOM, because the PDF's text
    layer wraps a 64-character hash into column fragments and loses 28% of the
    observables — on the COLDRIVER report, 9 of 12 SHA-256 hashes.  But the
    capture also writes `{job_id}.pdf` beside it as the archive, and the archive
    is where the figures are.  So the text comes from the DOM and the figures
    from the PDF.

    Offsets are unaffected: `inject_append` appends figure blocks *after* the
    document text, so the spans it records are relative to the final
    `report_text` whichever document the crops came from.

    `.pdf.part` is never returned — that is a capture which timed out
    mid-render, and `/jobs/{id}/source` already refuses to serve it.
    """
    if file_path is None:
        return None
    path = Path(file_path)
    if path.suffix.lower() == ".pdf":
        return path if path.is_file() else None
    sibling = path.with_suffix(".pdf")
    return sibling if sibling.is_file() else None


def chunk_size_for(doc_len: int) -> int:
    """Adaptive chunk size — larger chunks for large documents so the number of
    LLM calls stays manageable (~33% fewer calls at 4 500 than at 3 000)."""
    if doc_len > 60_000:
        return 5000
    if doc_len > 30_000:
        return 4000
    return 3000


def build_doc_context(gazetteer_entities: list, cyner_entities: list,
                      gliner_entities: list, semantic_ttp_entities: list) -> str:
    """A concise document-level entity summary passed to every LLM chunk call.

    Solves the "IoC appendix" problem (CyNER/Fujii 2024): threat-intel reports
    often list IoCs in a separate appendix section with no local context.
    Without this summary the LLM sees only raw IPs/hashes in those chunks and
    cannot create `ioc_associations` linking them to the right malware family.
    """
    lines: list[str] = []

    malware_names = sorted({e.value for e in (gazetteer_entities + cyner_entities)
                            if e.entity_type == EntityType.MALWARE})
    if malware_names:
        lines.append(f"Malware in this report: {', '.join(malware_names)}")

    actor_names = sorted({e.value for e in (gazetteer_entities + cyner_entities)
                          if e.entity_type == EntityType.THREAT_ACTOR})
    if actor_names:
        lines.append(f"Threat actors: {', '.join(actor_names)}")

    top_ttps = sorted(
        [e for e in semantic_ttp_entities if e.mitre_id and e.confidence >= 0.55],
        key=lambda x: x.confidence, reverse=True,
    )[:5]
    if top_ttps:
        lines.append(f"Key techniques: {', '.join(f'{e.value} ({e.mitre_id})' for e in top_ttps)}")

    for label, etype in (
        ("Targeted sectors", EntityType.IDENTITY),
        ("Targeted countries", EntityType.LOCATION),
        ("Campaign name(s)", EntityType.CAMPAIGN),
        ("Attack infrastructure", EntityType.INFRASTRUCTURE),
    ):
        names = sorted({e.value for e in gliner_entities if e.entity_type == etype})
        if names:
            lines.append(f"{label}: {', '.join(names)}")

    return "\n".join(lines)


def chunk_has_signals(chunk: str, chunk_ents: list, known_values: set[str]) -> bool:
    """True if this chunk is worth sending to the LLM.

    Skipped: chunks under 200 characters (headings, page numbers, footers), and
    chunks with no regex IoC where none of the document's known entity names
    appears — cover pages, tables of contents, bibliographies.
    """
    if len(chunk.strip()) < 200:
        return False
    if chunk_ents:
        return True
    lower = chunk.lower()
    return any(v in lower for v in known_values)


def load_file_bytes(path: str | Path | None) -> tuple[str | None, bytes | None]:
    """(sha256 hex, raw bytes) of the source file, or (None, None) when unreadable."""
    if path is None:
        return None, None
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None, None
    return hashlib.sha256(data).hexdigest(), data


def build_bundle(
    entities: list[RawEntity],
    llm_result: LLMEnrichmentResult,
    *,
    report_name: str,
    report_text: str,
    original_filename: str,
    source_hash: str | None,
    source_bytes: bytes | None,
    policy: dict | None,
    tlp_level: str | None,
    pap_level: str | None,
    cve_metadata: dict | None = None,
    graph_completion: bool = True,
    long_distance: bool = True,
):
    """Stage 4 (with the Stage 4c long-distance inferer it needs) — shared by
    a pipeline run and by finalize.  `cve_metadata` comes from lookup_cves()."""
    from pipeline.stage4_stix_mapping import build_stix_bundle
    from pipeline.stage4c_long_distance import default_long_distance_inferer

    return build_stix_bundle(
        entities, llm_result, report_name,
        report_text=report_text,
        original_filename=original_filename,
        source_hash=source_hash,
        source_bytes=source_bytes,
        cve_metadata=cve_metadata or {},
        relationship_policy=policy,
        tlp_level=tlp_level,
        pap_level=pap_level,
        long_distance_infer=default_long_distance_inferer(policy) if long_distance else None,
        graph_completion=graph_completion,
    )


def lookup_cves(entities: list[RawEntity]) -> dict[str, dict]:
    """Stage 2f: CIRCL metadata for the document's CVEs.  Serves the job
    store's cache even when the network lookup (CVE_ENRICHMENT) is off, so it
    needs the database — callers decide what a failure costs."""
    from pipeline.stage2f_cve_enrichment import enrich_cves

    cve_ids = {e.value for e in entities if e.entity_type == EntityType.CVE}
    return enrich_cves(cve_ids) if cve_ids else {}


def synthesis_stats(bundle) -> dict | None:
    """The Report SDO's per-rule synthesis accounting (ADR-0026), or None."""
    for obj in bundle.objects:
        otype = obj.get("type") if hasattr(obj, "get") else getattr(obj, "type", None)
        if otype == "report":
            return (obj.get("x_synthesis_stats") if hasattr(obj, "get")
                    else getattr(obj, "x_synthesis_stats", None))
    return None


# ── The run ──────────────────────────────────────────────────────────────────


class _Run:
    """State of one run_document() call; one method per stage."""

    def __init__(self, document: Document, options: RunOptions, hooks: Hooks):
        self.doc = document
        self.opts = options
        self.hooks = hooks
        self.r = RunResult(document=document)

    # -- bookkeeping ---------------------------------------------------------

    def record(self, stage: str, status: str, reason: str = "", seconds: float = 0.0,
               **counts: int) -> None:
        # One line: a reason may carry a driver's multi-line error message.
        outcome = StageOutcome(stage, status, " ".join(reason.split()), round(seconds, 3), counts)
        self.r.stages.append(outcome)
        if status != RAN:
            log = logger.warning if status == FAILED else logger.info
            log(f"[Stage {stage}] {status}: {reason}")
        if stage in self.opts.required and status != RAN:
            raise StageRequired(outcome)

    def gate(self, stage: str, available: Callable[[], bool] | None = None,
             unavailable_reason: str = "model or index unavailable") -> bool:
        """True if `stage` should run; otherwise records why it will not."""
        if stage in self.opts.disabled:
            self.record(stage, SKIPPED, "disabled")
            return False
        if available is not None and not available():
            self.record(stage, SKIPPED, unavailable_reason)
            return False
        return True

    # -- stages --------------------------------------------------------------

    def ingest(self) -> None:
        from pipeline.stage1_ingestion import chunk_text, extract_reference_date, ingest
        from pipeline.stage2_extraction import refang

        t0 = time.monotonic()
        self.hooks.check_timeout()
        if self.doc.text is not None:
            raw_text = self.doc.text
            reason = "text provided"
        elif self.doc.file_path is not None:
            raw_text = ingest(self.doc.file_path)
            # Best-effort document creation time (TimeML/TIMEX3-style anchor)
            # for Stage 3 to resolve simple relative relationship dates against.
            self.r.reference_date = extract_reference_date(self.doc.file_path)
            reason = ""
        else:
            raise ValueError("Document needs a file_path or a text")
        self.hooks.check_timeout()
        # Refang immediately so entity values (stored refanged) can be found in
        # the displayed text.  "keepassxc[.]us[.]org" → "keepassxc.us.org"
        self.r.text = refang(raw_text)
        t_ingest = time.monotonic() - t0

        self.figures()

        t0 = time.monotonic()
        max_chars = chunk_size_for(len(self.r.text))
        self.r.chunks = chunk_text(self.r.text, max_chars=max_chars)
        logger.info(f"[Stage 1] {len(self.r.text):,} chars — {len(self.r.chunks)} chunks "
                    f"(max_chars={max_chars})")
        self.record("1", RAN, reason, t_ingest + time.monotonic() - t0,
                    chars=len(self.r.text), chunks=len(self.r.chunks))
        self.hooks.progress("stage", {
            "stage": 1, "label": "Ingestion",
            "chars": len(self.r.text), "chunks": len(self.r.chunks),
        })
        self.hooks.text_ready(self.r.text, self.r.figure_spans, self.r.figure_provider)

    def figures(self) -> None:
        """Stage 1f (ADR-0032, ADR-0033).  Runs after refang and before
        chunking, and that order is load-bearing: refang shortens the text, so
        a span computed before it would point at the wrong characters."""
        pdf = self.doc.figure_pdf or figure_source_pdf(self.doc.file_path)
        if not self.gate("1f"):
            return
        if pdf is None:
            self.record("1f", SKIPPED, "no PDF")
            return
        from pipeline.vlm import get_backend
        vision = get_backend()
        if vision is None:
            self.record("1f", SKIPPED, "no vision backend configured")
            return
        from pipeline.figure_store import SqliteReadCache
        from pipeline.stage1f_figures import inject_append, map_verbatim, read_figures
        from pipeline.stage2_extraction import refang

        t0 = time.monotonic()
        try:
            # The head of the report is MM-AttacKG's Global-Context: title and
            # opening paragraphs tell a model which campaign a bare hostname
            # on a screenshot belongs to.  Already refanged, like the rest.
            reads = read_figures(str(pdf), vision, cache=SqliteReadCache(),
                                 global_context=self.r.text[:2000])
            reads = map_verbatim(reads, refang)
            self.r.text, self.r.figure_spans = inject_append(self.r.text, reads)
            self.r.figure_provider = vision.name
            kept = sum(1 for _, r, _ in reads if r.kind != "unread")
            logger.info(f"[Stage 1f] {len(reads)} figures, {kept} read via "
                        f"{vision.name}/{vision.model}")
            self.hooks.progress("stage", {"stage": "1f", "label": "Figures",
                                          "figures": len(reads), "read": kept})
            self.record("1f", RAN, "", time.monotonic() - t0, figures=len(reads), read=kept)
        except Exception as exc:
            # A figure that cannot be read must never cost the report.
            self.r.figure_spans = []
            self.record("1f", FAILED, str(exc), time.monotonic() - t0)

    def extract(self) -> None:
        from pipeline.base import BaseExtractionStage, resolve_type_conflicts
        from pipeline.stage2_extraction import extract_entities

        text = self.r.text

        # Stage 2 — regex IoCs, per chunk (Stage 3 needs each chunk's own),
        # deduplicated by (value, type) keeping the highest confidence.
        best: dict[tuple, RawEntity] = {}
        self.r.entities_per_chunk = [[] for _ in self.r.chunks]
        if self.gate("2"):
            t0 = time.monotonic()
            self.r.entities_per_chunk = [extract_entities(c) for c in self.r.chunks]
            for chunk_ents in self.r.entities_per_chunk:
                for e in chunk_ents:
                    key = (e.value.lower(), e.entity_type)
                    if key not in best or e.confidence > best[key].confidence:
                        best[key] = e
            self.record("2", RAN, "", time.monotonic() - t0, entities=len(best))

        # Stage 2b — gazetteer; regex wins a tie (more precise for exact values).
        from pipeline.stage2b_gazetteer import available as gaz_available
        from pipeline.stage2b_gazetteer import match_gazetteer
        if self.gate("2b", gaz_available):
            t0 = time.monotonic()
            self.r.gazetteer = match_gazetteer(text)
            for ge in self.r.gazetteer:
                best.setdefault((ge.value.lower(), ge.entity_type), ge)
            self.record("2b", RAN, "", time.monotonic() - t0, entities=len(self.r.gazetteer))
        entities = list(best.values())

        # Stage 2c — semantic TTP detection.
        from pipeline.stage2c_ttp_semantic import detect_ttps_semantic, semantic_available
        if self.gate("2c", semantic_available):
            t0 = time.monotonic()
            self.r.semantic_ttps = detect_ttps_semantic(text)
            keys = {(e.value.lower(), e.entity_type) for e in entities}
            for se in self.r.semantic_ttps:
                key = (se.value.lower(), se.entity_type)
                if key not in keys:
                    entities.append(se)
                    keys.add(key)
            self.record("2c", RAN, "", time.monotonic() - t0, entities=len(self.r.semantic_ttps))

        # Stage 2d — CyNER.
        from pipeline.stage2d_cyner import cyner_available, extract_cyner_entities
        if self.gate("2d", cyner_available):
            t0 = time.monotonic()
            self.r.cyner = extract_cyner_entities(text)
            entities = BaseExtractionStage.merge_into(entities, self.r.cyner)
            self.record("2d", RAN, "", time.monotonic() - t0, entities=len(self.r.cyner))

        # Stage 2e — GLiNER zero-shot NER: sectors, campaigns, infrastructure,
        # novel actors and malware ("0-CTI", CY4GATE 2025 — ADR-0004 P2-A).
        from pipeline.stage2e_gliner import (
            _merge_gliner_into,
            extract_gliner_entities,
            gliner_available,
        )
        if self.gate("2e", gliner_available):
            t0 = time.monotonic()
            self.r.gliner = extract_gliner_entities(text)
            entities = _merge_gliner_into(entities, self.r.gliner)
            self.record("2e", RAN, "", time.monotonic() - t0, entities=len(self.r.gliner))

        # Stage 2g — "X (aka Y, Z)" alias lists, deterministic.
        from pipeline.stage2g_alias_list import extract_alias_list_entities
        if self.gate("2g"):
            t0 = time.monotonic()
            self.r.alias_list = extract_alias_list_entities(text)
            entities = BaseExtractionStage.merge_into(entities, self.r.alias_list)
            self.record("2g", RAN, "", time.monotonic() - t0, entities=len(self.r.alias_list))

        # Same value, different type from two stages (gazetteer `tool` vs
        # CyNER `malware`): merge_into's (value, type) key kept both.
        self.r.entities = resolve_type_conflicts(entities)

        logger.info(f"[Stage 2] Extracted {len(self.r.entities)} entities "
                    f"(gazetteer={len(self.r.gazetteer)}, semantic_ttp={len(self.r.semantic_ttps)}, "
                    f"cyner={len(self.r.cyner)}, gliner={len(self.r.gliner)}, "
                    f"alias_list={len(self.r.alias_list)})")
        self.hooks.progress("stage", {
            "stage": 2, "label": "Extraction",
            "entities": len(self.r.entities),
            "gazetteer": len(self.r.gazetteer),
            "semantic_ttps": len(self.r.semantic_ttps),
            "cyner": len(self.r.cyner),
            "gliner": len(self.r.gliner),
            "alias_list": len(self.r.alias_list),
        })

    def enrich(self) -> None:
        from pipeline.stage3_llm import (
            _merge_results,
            _provider_ready,
            provider_label,
        )

        results: list[LLMEnrichmentResult] = []
        if self.gate("3", _provider_ready,
                     f"LLM provider not ready ({provider_label()})"):
            results = self._chunks_to_llm()
            self._document_relations(results)
        else:
            for sid in ("3d", "3f", "3e", "3doc"):
                self.record(sid, SKIPPED, "Stage 3 did not run")

        # Stage 3c normalisation runs either way: it is what merges the
        # semantic TTPs and the gazetteer names into the result.
        self.r.llm_result = _merge_results(
            results,
            gazetteer_entities=self.r.gazetteer,
            semantic_ttp_entities=self.r.semantic_ttps,
            cyner_entities=self.r.cyner,
        )

    def _chunks_to_llm(self) -> list[LLMEnrichmentResult]:
        from pipeline import llm_stats
        from pipeline.stage3_llm import LLMEnrichmentResult, enrich_chunk, stage3_settings
        from pipeline.stage3d_verify import verify_enabled as rel_verify_enabled
        from pipeline.stage3e_consensus import consensus_enabled, consensus_provider, reconcile
        from pipeline.stage3f_ttp_verify import verify_enabled as ttp_verify_enabled

        r, hooks, opts = self.r, self.hooks, self.opts
        chunks, total = r.chunks, len(r.chunks)
        consensus = opts.switch("3e", opts.consensus, consensus_enabled)
        verify_rels = opts.switch("3d", opts.verify_relationships, rel_verify_enabled)
        verify_ttps = opts.switch("3f", opts.verify_ttps, ttp_verify_enabled)

        known_values = {e.value.lower()
                        for e in r.gazetteer + r.cyner + r.semantic_ttps + r.gliner}
        doc_context = build_doc_context(r.gazetteer, r.cyner, r.gliner, r.semantic_ttps)
        # Names the high-precision NER stages found, so the hallucination
        # filter can skip its fuzzy scan for them.
        ner_allow_list = set(known_values)

        fingerprint = stage3_fingerprint(
            stage3_settings(consensus=consensus, verify_rels=verify_rels, verify_ttps=verify_ttps),
            {"chunks": chunks,
             "entities_per_chunk": [_entities_key(e) for e in r.entities_per_chunk],
             "gazetteer": _entities_key(r.gazetteer), "cyner": _entities_key(r.cyner),
             "semantic": _entities_key(r.semantic_ttps), "doc_context": doc_context,
             "allow_list": sorted(ner_allow_list), "reference_date": r.reference_date},
        )
        checkpoint = hooks.checkpoint
        chunk_results: dict[int, LLMEnrichmentResult] = {}
        if checkpoint is not None:
            chunk_results, saved_at = checkpoint.load(fingerprint, total)
            if chunk_results:
                logger.info(f"[Stage 3] Resuming from checkpoint — {len(chunk_results)}/{total} "
                            f"chunks already done (saved {saved_at})")

        totals = {
            "malware": sum(len(x.malware_families) for x in chunk_results.values()),
            "actors": sum(len(x.threat_actors) for x in chunk_results.values()),
            "tools": sum(len(x.tools) for x in chunk_results.values()),
            "relationships": sum(len(x.relationships) for x in chunk_results.values()),
        }

        work: list[tuple[int, str, list]] = []
        skipped = 0
        for i, (chunk, ents) in enumerate(zip(chunks, r.entities_per_chunk), 1):
            if i in chunk_results:
                continue
            if chunk_has_signals(chunk, ents, known_values):
                work.append((i, chunk, ents))
            else:
                skipped += 1
                logger.debug(f"[Stage 3] chunk {i}/{total} — skipped (no CTI signals)")

        t0 = time.monotonic()
        stats_before = llm_stats.snapshot()
        parallelism = max(1, self.opts.llm_parallelism)
        logger.info(f"[Stage 3] {len(work)} chunks → LLM ({skipped} skipped, "
                    f"{len(chunk_results)} from checkpoint, parallelism={parallelism})")
        log_lock = threading.Lock()
        doubled = 0

        def process(idx: int, chunk: str, ents: list) -> tuple[int, LLMEnrichmentResult, bool]:
            with log_lock:
                logger.info(f"[Stage 3] chunk {idx}/{total} — {len(chunk)} chars "
                            f"[elapsed {time.monotonic() - t0:.0f}s]")
            t_chunk = time.monotonic()
            def call(provider: str | None = None) -> LLMEnrichmentResult:
                return enrich_chunk(
                    chunk, ents,
                    gazetteer_entities=r.gazetteer,
                    cyner_entities=r.cyner,
                    semantic_ttp_entities=r.semantic_ttps,
                    doc_context=doc_context or None,
                    ner_allow_list=ner_allow_list,
                    provider=provider,
                    reference_date=r.reference_date,
                    verify_rels=verify_rels,
                    verify_ttps_on=verify_ttps,
                )

            res = call()
            # Stage 3e — cross-model consensus, only on chunks that produced
            # relationships (the highest hallucination-risk output).
            second_run = False
            if res.relationships and consensus:
                res = reconcile(res, call(consensus_provider()))
                second_run = True
            parts = [f"{n} {label}" for n, label in (
                (len(res.malware_families), "malware"), (len(res.threat_actors), "actors"),
                (len(res.tools), "tools"), (len(res.relationships), "rels")) if n]
            with log_lock:
                logger.info(f"[Stage 3] chunk {idx}/{total} ✓ {time.monotonic() - t_chunk:.1f}s — "
                            f"{', '.join(parts) or 'nothing extracted'}")
            return idx, res, second_run

        with ThreadPoolExecutor(max_workers=parallelism) as executor:
            futures = [executor.submit(process, i, c, e) for i, c, e in work]
            completed = since_ckpt = 0
            for future in as_completed(futures):
                hooks.check_timeout()
                idx, res, second_run = future.result()
                chunk_results[idx] = res
                doubled += second_run
                completed += 1
                since_ckpt += 1
                totals["malware"] += len(res.malware_families)
                totals["actors"] += len(res.threat_actors)
                totals["tools"] += len(res.tools)
                totals["relationships"] += len(res.relationships)

                if checkpoint is not None and since_ckpt >= self.opts.checkpoint_every:
                    checkpoint.save(fingerprint, total, chunk_results)
                    since_ckpt = 0

                hooks.progress("stage", {
                    "stage": 3, "label": "LLM enrichment",
                    "chunk": completed, "total": len(work), **totals,
                })
                hooks.progress("partial_graph", _partial_graph(res))

        if checkpoint is not None:
            checkpoint.clear()   # only reached on clean completion

        logger.info(f"[Stage 3] done — {len(work)} LLM calls, {skipped} skipped, "
                    f"total elapsed {time.monotonic() - t0:.0f}s")
        logger.info(f"[Stage 3] totals: {totals['malware']} malware, {totals['actors']} actors, "
                    f"{totals['tools']} tools, {totals['relationships']} relationships")
        stats_after = llm_stats.snapshot()
        d = llm_stats.delta(stats_before, stats_after)
        kinds = ("extraction_ok", "extraction_empty", "extraction_invalid", "extraction_provider_failed")
        counts = dict(llm_calls=len(work), provider_calls=d.get("provider_calls", 0),
                      provider_failures=d.get("provider_failures", 0),
                      **{k: d.get(k, 0) for k in kinds},
                      skipped_chunks=skipped, from_checkpoint=total - len(work) - skipped, **totals)
        attempted = sum(d.get(k, 0) for k in kinds)
        unusable = attempted - d.get("extraction_ok", 0)
        detail = (f"{d.get('extraction_provider_failed', 0)} failed requests, "
                  f"{d.get('extraction_empty', 0)} empty answers, "
                  f"{d.get('extraction_invalid', 0)} unparseable answers")
        if attempted and unusable == attempted:
            # No usable answer at all (wrong model name, server down, a model
            # that answers nothing or no JSON): the empty result is not
            # "nothing found", and must not read as such.
            last = f" — last error: {stats_after['last_error']}" if d.get("provider_failures") else ""
            self.record("3", FAILED, f"no usable LLM answer in {attempted} extraction calls: "
                        f"{detail}{last}", time.monotonic() - t0, **counts)
        else:
            self.record("3", RAN, f"{unusable} of {attempted} extraction calls unusable: {detail}"
                        if unusable else "", time.monotonic() - t0, **counts)
        for sid, on, prefix in (("3d", verify_rels, "rel_verification"),
                                ("3f", verify_ttps, "ttp_verification")):
            ok, unparsed, failed = (d.get(f"{prefix}_ok", 0), d.get(f"{prefix}_unparsed", 0),
                                    d.get(f"{prefix}_failed", 0))
            if not on:
                self.record(sid, SKIPPED, "disabled")
            elif ok + unparsed + failed == 0:
                self.record(sid, RAN, "nothing to verify", 0.0, ok=0, unparsed=0, failed=0)
            elif ok == 0 and unparsed + failed:
                # A verification that never answers keeps every claim — the
                # stage was requested and did nothing.
                self.record(sid, FAILED, f"no usable verification answer ({unparsed} unparseable, "
                            f"{failed} failed): every claim kept unverified", 0.0,
                            ok=ok, unparsed=unparsed, failed=failed)
            else:
                self.record(sid, RAN, f"{unparsed + failed} of {ok + unparsed + failed} verifications "
                            "unusable, those claims kept unverified" if unparsed + failed else "",
                            0.0, ok=ok, unparsed=unparsed, failed=failed)
        if consensus:
            self.record("3e", RAN, "", 0.0, chunks=doubled)
        else:
            self.record("3e", SKIPPED, "disabled")
        # Results in chunk order; a skipped chunk contributes an empty result.
        return [chunk_results.get(i, LLMEnrichmentResult()) for i in range(1, total + 1)]

    def _document_relations(self, results: list) -> None:
        """ADR-0057 (opt-in): one call over the whole report for relationships
        whose two facts sit in different chunks.  Its result is appended to the
        per-chunk ones, so the existing merge dedups it."""
        from pipeline.stage3_llm import document_level_relations_enabled, enrich_document_relations

        enabled = (self.opts.document_relations if self.opts.document_relations is not None
                   else document_level_relations_enabled())
        if "3doc" in self.opts.disabled or not enabled:
            self.record("3doc", SKIPPED, "disabled")
            return
        t0 = time.monotonic()
        known = list(self.r.entities)
        keys = {(e.value.lower(), e.entity_type) for e in known}
        for res in results:
            for name, etype in ([(n, EntityType.THREAT_ACTOR) for n in res.threat_actors]
                                + [(n, EntityType.MALWARE) for n in res.malware_families]
                                + [(n, EntityType.TOOL) for n in res.tools]):
                if (name.lower(), etype) not in keys:
                    known.append(RawEntity(value=name, entity_type=etype, source="llm"))
                    keys.add((name.lower(), etype))
        logger.info(f"[Stage 3 doc-relations] {len(known)} known entities, "
                    f"{len(self.r.text)} chars of report text")
        doc_result = enrich_document_relations(self.r.text, known)
        logger.info(f"[Stage 3 doc-relations] {len(doc_result.relationships)} relationships found")
        results.append(doc_result)
        self.record("3doc", RAN, "", time.monotonic() - t0,
                    relationships=len(doc_result.relationships))

    def map_to_stix(self) -> None:
        from pipeline.stage2f_cve_enrichment import enrichment_enabled
        from pipeline.stage4_stix_mapping import verify_ioc_coverage

        if not self.gate("4"):
            for sid in ("2f", "4b", "4c", "5"):
                self.record(sid, SKIPPED, "Stage 4 did not run")
            return
        r = self.r
        r.policy = self.hooks.policy()
        self.hooks.policy_used(r.policy)

        cve_meta: dict = {}
        if self.gate("2f"):
            t0 = time.monotonic()
            cve_count = sum(1 for e in r.entities if e.entity_type == EntityType.CVE)
            try:
                cve_meta = lookup_cves(r.entities)
                self.record("2f", RAN, "" if enrichment_enabled() else "cache only (CVE_ENRICHMENT off)",
                            time.monotonic() - t0, cves=cve_count, described=len(cve_meta))
            except Exception as exc:
                # The cache lives in the job store; the CLI runs without one.
                # A CVE without a description is still a CVE.
                self.record("2f", FAILED, f"CVE cache unavailable: {exc}", time.monotonic() - t0)

        t0 = time.monotonic()
        source_hash, source_bytes = load_file_bytes(self.doc.file_path)
        assert r.llm_result is not None   # enrich() always sets it
        r.bundle = build_bundle(
            r.entities, r.llm_result,
            report_name=self.doc.report_name,
            report_text=r.text,
            original_filename=self.doc.name,
            source_hash=source_hash,
            source_bytes=source_bytes,
            policy=r.policy,
            tlp_level=self.doc.tlp_level,
            pap_level=self.doc.pap_level,
            cve_metadata=cve_meta,
            graph_completion="4b" not in self.opts.disabled,
            long_distance="4c" not in self.opts.disabled,
        )
        n_objects = len(list(r.bundle.objects))
        logger.info(f"[Stage 4] STIX mapping complete — {n_objects} objects")

        # Every regex/defang-extracted IoC must have become an SCO + Indicator.
        cov = verify_ioc_coverage(r.entities, r.bundle)
        r.ioc_coverage = cov
        if cov["ok"]:
            logger.info(f"[Stage 4] IoC coverage OK — all {cov['total_iocs']} regex/defang "
                        f"IoCs have a STIX observable + Indicator")
        else:
            logger.warning(f"[Stage 4] IoC coverage gaps — "
                           f"{len(cov['missing_indicator'])}/{cov['total_iocs']} IoCs without an "
                           f"Indicator, {len(cov['missing_sco'])} without an SCO")
            for m in cov["missing_indicator"][:10]:
                logger.warning(f"    no indicator: [{m['type']}] {m['value']}")

        # Read back off the Report SDO, so the progress channel consumes the
        # same record that ships inside the bundle (ADR-0026).
        r.synthesis = synthesis_stats(r.bundle)
        pin = (r.synthesis or {}).get("pin") or {}
        if pin.get("rules"):
            logger.info("[Stage 4] policy pins — %d of %d candidate edges emitted across "
                        "%d rules (budget %d, mode %s)",
                        pin.get("total_emitted", 0), pin.get("total_candidates", 0),
                        len(pin["rules"]), pin.get("budget", 0), pin.get("mode", ""))
        self.record("4", RAN, "", time.monotonic() - t0, objects=n_objects,
                    iocs=cov["total_iocs"], with_indicator=cov["with_indicator"])
        comp = (r.synthesis or {}).get("completion") or {}
        if "4b" in self.opts.disabled:
            self.record("4b", SKIPPED, "disabled")
        else:
            self.record("4b", RAN, "", 0.0, aliases_merged=comp.get("aliases_merged", 0),
                        reference_added=comp.get("reference_added", 0),
                        transitive_added=comp.get("transitive_added", 0))
        ld_policy = ((r.policy or {}).get("completion") or {}).get("long_distance")
        if "4c" in self.opts.disabled:
            self.record("4c", SKIPPED, "disabled")
        elif not ld_policy:
            self.record("4c", SKIPPED, "not enabled by the relationship policy")
        else:
            self.record("4c", RAN, "", 0.0, long_distance_added=comp.get("long_distance_added", 0))
        self.hooks.progress("stage", {
            "stage": 4, "label": "STIX mapping", "objects": n_objects,
            "ioc_coverage": {"total": cov["total_iocs"],
                             "with_indicator": cov["with_indicator"], "ok": cov["ok"]},
            "synthesis": r.synthesis,
        })

    def validate(self) -> None:
        if self.r.bundle is None:
            return   # Stage 4 already recorded Stage 5 as skipped
        if not self.gate("5"):
            return
        if not self.doc.output_path:
            self.record("5", SKIPPED, "no output path")
            return
        from pipeline.stage5_validation import validate_and_export

        t0 = time.monotonic()
        Path(self.doc.output_path).parent.mkdir(parents=True, exist_ok=True)
        self.r.valid = validate_and_export(self.r.bundle, self.doc.output_path)
        logger.info(f"[Stage 5] Validation complete — valid={self.r.valid}")
        self.record("5", RAN, "" if self.r.valid else "bundle failed schema validation",
                    time.monotonic() - t0, valid=int(bool(self.r.valid)))
        self.hooks.progress("stage", {"stage": 5, "label": "Validation", "valid": self.r.valid})


def _partial_graph(res) -> dict:
    """What one chunk found, streamed so the graph draws as it fills.  Preview
    only: these nodes carry no evidence and never reach the bundle."""
    nodes: list[dict] = []
    nodes += [{"id": a, "type": "threat_actor", "name": a} for a in res.threat_actors]
    nodes += [{"id": m, "type": "malware", "name": m} for m in res.malware_families]
    nodes += [{"id": t, "type": "tool", "name": t} for t in res.tools]
    nodes += [{"id": t.technique_name, "type": "ttp", "name": t.technique_name} for t in res.ttps]
    for rel in res.relationships:
        # An endpoint may not have been extracted as an entity of its own.
        nodes.append({"id": rel.source_value, "type": "unknown", "name": rel.source_value})
        nodes.append({"id": rel.target_value, "type": "unknown", "name": rel.target_value})
    links = [{"source": x.source_value, "target": x.target_value, "type": x.relationship_type}
             for x in res.relationships]
    return {"nodes": nodes, "links": links}


def run_document(document: Document, options: RunOptions | None = None,
                 hooks: Hooks | None = None) -> RunResult:
    """Run Stages 1 → 5 on one document.  See the module docstring."""
    run = _Run(document, options or RunOptions.from_env(), hooks or Hooks())
    run.ingest()
    run.hooks.check_timeout()
    run.extract()
    run.hooks.check_timeout()
    run.enrich()
    assert run.r.llm_result is not None
    run.hooks.extraction_ready(run.r.entities, run.r.llm_result, run.r.text)
    run.map_to_stix()
    run.validate()
    return run.r
