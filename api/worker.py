"""
Background worker — runs the 5-stage pipeline and emits progress events to SQLite.
"""
import hashlib
import json
import multiprocessing as mp
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from uuid import uuid4

# Ensure project root is on sys.path so pipeline imports work
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Initialize logging
from api.logging_config import get_logger

logger = get_logger(__name__)

from api.db import _lock, backup_db, emit_progress, get_conn, now_iso, set_job_status
from models.schemas import RawEntity

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Worker concurrency and timeout limits
# ---------------------------------------------------------------------------
# Maximum execution time per job in seconds (0 = unlimited)
_MAX_JOB_TIMEOUT = int(os.environ.get("WORKER_JOB_TIMEOUT", "1800"))  # 30 minutes
# Maximum concurrent jobs (each runs in its own subprocess)
_MAX_CONCURRENT_JOBS = int(os.environ.get("WORKER_MAX_CONCURRENT", "10"))

# Note: WORKER_MAX_MEMORY_MB is no longer used.  RLIMIT_AS is not set because
# it limits virtual address space (not physical RAM), which breaks dlopen() for
# ML libraries that memory-map large .so files.  Physical memory protection is
# provided by subprocess isolation + the OS OOM killer instead.

# Global job counter and lock for concurrency control
_job_counter = 0
_job_counter_lock = threading.Lock()


def _check_job_limit():
    """Check if we've reached the maximum concurrent jobs."""
    if _MAX_CONCURRENT_JOBS <= 0:
        return True  # No limit
    with _job_counter_lock:
        if _job_counter >= _MAX_CONCURRENT_JOBS:
            logger.warning(f"Concurrent job limit reached: {_job_counter} >= {_MAX_CONCURRENT_JOBS}")
            return False
        return True


def _increment_job_counter():
    """Increment the job counter."""
    with _job_counter_lock:
        global _job_counter
        _job_counter += 1


def _decrement_job_counter():
    """Decrement the job counter."""
    with _job_counter_lock:
        global _job_counter
        _job_counter = max(0, _job_counter - 1)


def _sha256_file(path: str | Path) -> str | None:
    """Return the SHA-256 hex digest of a file, or None if the file is missing."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Document-level context builder — ADR-004 P2-B
# ---------------------------------------------------------------------------

def _build_doc_context(
    gazetteer_entities: list,
    cyner_entities:     list,
    gliner_entities:    list,
    semantic_ttp_entities: list,
) -> str:
    """
    Build a concise document-level entity summary to pass to each LLM chunk call.

    Solves the "IoC appendix" problem (CyNER/Fujii 2024): threat-intel reports
    often list IoCs in a separate appendix section that has no local context.
    Without this summary, the LLM sees only raw IPs/hashes in those chunks and
    cannot create `ioc_associations` linking them to the correct malware family.

    By passing the full-document entity summary to EVERY chunk, the LLM can
    correctly link "185.220.101.45 → Cobalt Strike" even when the two appear in
    different chunks.
    """
    from models.schemas import EntityType

    lines: list[str] = []

    # --- Malware families (from gazetteer + CyNER) ---
    malware_names = sorted({
        e.value for e in (gazetteer_entities + cyner_entities)
        if e.entity_type == EntityType.MALWARE
    })
    if malware_names:
        lines.append(f"Malware in this report: {', '.join(malware_names)}")

    # --- Threat actors ---
    actor_names = sorted({
        e.value for e in (gazetteer_entities + cyner_entities)
        if e.entity_type == EntityType.THREAT_ACTOR
    })
    if actor_names:
        lines.append(f"Threat actors: {', '.join(actor_names)}")

    # --- Top TTPs (highest confidence, with MITRE IDs) ---
    top_ttps = sorted(
        [e for e in semantic_ttp_entities if e.mitre_id and e.confidence >= 0.55],
        key=lambda x: x.confidence,
        reverse=True,
    )[:5]
    if top_ttps:
        ttp_strs = [f"{e.value} ({e.mitre_id})" for e in top_ttps]
        lines.append(f"Key techniques: {', '.join(ttp_strs)}")

    # --- GLiNER-specific entities (sectors, countries, campaigns) ---
    sectors = sorted({
        e.value for e in gliner_entities if e.entity_type == EntityType.IDENTITY
    })
    countries = sorted({
        e.value for e in gliner_entities if e.entity_type == EntityType.LOCATION
    })
    campaigns = sorted({
        e.value for e in gliner_entities if e.entity_type == EntityType.CAMPAIGN
    })
    infra = sorted({
        e.value for e in gliner_entities if e.entity_type == EntityType.INFRASTRUCTURE
    })

    if sectors:
        lines.append(f"Targeted sectors: {', '.join(sectors)}")
    if countries:
        lines.append(f"Targeted countries: {', '.join(countries)}")
    if campaigns:
        lines.append(f"Campaign name(s): {', '.join(campaigns)}")
    if infra:
        lines.append(f"Attack infrastructure: {', '.join(infra)}")

    return "\n".join(lines)


def _save_entities(job_id: str, raw_entities, llm_result) -> None:
    """Persist Stage 2 IoCs, Stage 2b gazetteer, and Stage 3 LLM entities to the DB."""
    rows_ioc = []
    for e in raw_entities:
        # Use the source field from RawEntity (ioc | gazetteer) so provenance is tracked
        source = getattr(e, "source", "ioc")
        rows_ioc.append((
            str(uuid4()), job_id,
            e.value, e.entity_type.value,
            e.context, e.confidence,
            e.mitre_id, None, source,
        ))

    rows_llm = []
    for name in llm_result.malware_families:
        rows_llm.append((str(uuid4()), job_id, name, "malware", "", 0.9, None, None, "llm"))
    for name in llm_result.threat_actors:
        rows_llm.append((str(uuid4()), job_id, name, "threat_actor", "", 0.9, None, None, "llm"))
    for name in llm_result.tools:
        rows_llm.append((str(uuid4()), job_id, name, "tool", "", 0.9, None, None, "llm"))
    if llm_result.campaign_name:
        rows_llm.append((str(uuid4()), job_id, llm_result.campaign_name, "campaign", "", 0.9, None, None, "llm"))
    for ttp in llm_result.ttps:
        rows_llm.append((
            str(uuid4()), job_id, ttp.technique_name, "ttp",
            ttp.description, 0.9, ttp.mitre_id, None, "llm",
        ))

    rows_rel = []
    for rel in llm_result.relationships:
        rows_rel.append((
            str(uuid4()), job_id,
            rel.source_value, rel.relationship_type, rel.target_value,
            rel.confidence, 1, rel.evidence_text,
        ))

    with _lock:
        with get_conn() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO entities "
                "(id,job_id,value,entity_type,context,confidence,mitre_id,accepted,source) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                rows_ioc + rows_llm,
            )
            conn.executemany(
                "INSERT OR IGNORE INTO relationships "
                "(id,job_id,source_value,relationship_type,target_value,confidence,accepted,evidence_text) "
                "VALUES (?,?,?,?,?,?,?,?)",
                rows_rel,
            )
            conn.commit()


def _run_pipeline(job_id: str, file_path: str, original_filename: str) -> None:
    """
    Run the full pipeline for a job with timeout enforcement.
    """
    global _job_counter

    if not _check_job_limit():
        set_job_status(job_id, "queued")
        emit_progress(job_id, "done", {"status": "queued", "error": "Job queue full"})
        return

    _increment_job_counter()
    start_time = time.monotonic()

    try:
        # RLIMIT_AS (virtual address space) is intentionally NOT set here.
        #
        # A modern Python ML process maps 8–20 GB of virtual address space through
        # dlopen() / mmap() for shared libraries (scipy, torch, transformers .so
        # files), numpy arrays, and HuggingFace memory-mapped model weights — even
        # when physical RAM usage is only 2–4 GB.  Setting RLIMIT_AS too low causes
        # dlopen() to fail with ENOMEM ("failed to map segment from shared object"),
        # which is a hard import error that silently breaks entire pipeline stages.
        #
        # Physical-memory protection is provided by two other mechanisms:
        #   1. Subprocess isolation — a crash (std::bad_alloc → SIGABRT, or the OS
        #      OOM killer → SIGKILL) only terminates the worker subprocess.  The
        #      parent's watcher thread detects exit code ≠ 0 and writes
        #      status=failed so the frontend updates immediately.
        #   2. WORKER_JOB_TIMEOUT — jobs that run too long are cancelled via the
        #      check_timeout() function below.
        #
        # If you still need a hard memory cap (e.g. on a shared server), use
        # systemd's MemoryMax= or Docker's --memory flag at the container level
        # rather than RLIMIT_AS inside Python.

        set_job_status(job_id, "processing")

        # Check elapsed time periodically
        def check_timeout():
            elapsed = time.monotonic() - start_time
            if _MAX_JOB_TIMEOUT > 0 and elapsed > _MAX_JOB_TIMEOUT:
                raise TimeoutError(f"Job timeout exceeded: {elapsed:.0f}s > {_MAX_JOB_TIMEOUT}s")

        # --- Stage 1 ---
        from pipeline.stage1_ingestion import chunk_text, ingest
        from pipeline.stage2_extraction import extract_entities, refang

        check_timeout()
        raw_text = ingest(file_path)

        check_timeout()
        # Refang immediately so entity values (stored refanged) can be found in the
        # displayed document text.  "keepassxc[.]us[.]org" → "keepassxc.us.org"
        text = refang(raw_text)

        # Adaptive chunk size — larger chunks for large documents so the total
        # number of LLM calls stays manageable.  Each extra 1 500 chars saves
        # ~1 LLM call per 30 000 chars of document (~33% fewer calls at 4 500).
        _doc_len = len(text)
        if _doc_len > 60_000:
            _max_chars = 5000   # very large (>60k chars) — minimize LLM calls
        elif _doc_len > 30_000:
            _max_chars = 4000   # large (30–60k chars)
        else:
            _max_chars = 3000   # standard

        chunks = chunk_text(text, max_chars=_max_chars)
        logger.info(f"[Stage 1] {_doc_len:,} chars — {len(chunks)} chunks (max_chars={_max_chars})")
        emit_progress(job_id, "stage", {
            "stage": 1, "label": "Ingestion",
            "chars": len(text), "chunks": len(chunks),
        })

        # Save refanged text once
        with _lock:
            with get_conn() as conn:
                conn.execute("UPDATE jobs SET report_text=?, updated_at=? WHERE id=?",
                             (text, now_iso(), job_id))
                conn.commit()

        # --- Stage 2 — Regex IoC extraction ---
        entities_per_chunk = [extract_entities(chunk) for chunk in chunks]
        # Dedup by (value, type) keeping the highest-confidence occurrence
        _best: dict[tuple, RawEntity] = {}
        for chunk_ents in entities_per_chunk:
            for e in chunk_ents:
                key = (e.value.lower(), e.entity_type)
                if key not in _best or e.confidence > _best[key].confidence:
                    _best[key] = e
        regex_entities = list(_best.values())

        # --- Stage 2b — Gazetteer NER (malware / tool / APT group names) ---
        from pipeline.stage2b_gazetteer import available as gaz_available
        from pipeline.stage2b_gazetteer import match_gazetteer
        gazetteer_entities: list[RawEntity] = []
        if gaz_available():
            gazetteer_entities = match_gazetteer(text)
            # Merge into regex entities — skip any already found by regex at
            # equal or higher confidence (regex is more precise for exact values)
            regex_keys = {(e.value.lower(), e.entity_type) for e in regex_entities}
            for ge in gazetteer_entities:
                key = (ge.value.lower(), ge.entity_type)
                if key not in regex_keys:
                    _best[key] = ge
                    regex_keys.add(key)

        all_entities = list(_best.values())

        # --- Stage 2c — Semantic TTP detection ---
        from pipeline.stage2c_ttp_semantic import detect_ttps_semantic, semantic_available
        semantic_ttp_entities: list[RawEntity] = []
        if semantic_available():
            semantic_ttp_entities = detect_ttps_semantic(text)
            # Merge into all_entities (dedup by mitre_id — keep highest confidence)
            sem_keys = {(e.value.lower(), e.entity_type) for e in all_entities}
            for se in semantic_ttp_entities:
                key = (se.value.lower(), se.entity_type)
                if key not in sem_keys:
                    all_entities.append(se)
                    sem_keys.add(key)

        # --- Stage 2d — CyNER cybersecurity NER ---
        from pipeline.stage2d_cyner import _merge_cyner_into, cyner_available, extract_cyner_entities
        cyner_entities: list[RawEntity] = []
        if cyner_available():
            cyner_entities = extract_cyner_entities(text)
            all_entities = _merge_cyner_into(all_entities, cyner_entities)

        # --- Stage 2e — GLiNER zero-shot NER (novel/unnamed entities) ---
        # Discovers entity types CyNER and the gazetteer cannot: targeted sectors,
        # campaign names, attack infrastructure, novel actors & malware.
        # Paper: "0-CTI" — CY4GATE (2025) — ADR-004 P2-A
        from pipeline.stage2e_gliner import _merge_gliner_into, extract_gliner_entities, gliner_available
        gliner_entities: list[RawEntity] = []
        if gliner_available():
            gliner_entities = extract_gliner_entities(text)
            all_entities = _merge_gliner_into(all_entities, gliner_entities)

        logger.info(f"[Stage 2] Extracted {len(all_entities)} entities "
                   f"(gazetteer={len(gazetteer_entities)}, semantic_ttp={len(semantic_ttp_entities)}, "
                   f"cyner={len(cyner_entities)}, gliner={len(gliner_entities)})")
        emit_progress(job_id, "stage", {
            "stage": 2, "label": "Extraction",
            "entities": len(all_entities),
            "gazetteer": len(gazetteer_entities),
            "semantic_ttps": len(semantic_ttp_entities),
            "cyner": len(cyner_entities),
            "gliner": len(gliner_entities),
        })

        # --- Stage 3 — LLM enrichment (relationships, novel entities, campaign) ---

        # Build a set of entity values found globally (all NER stages)
        # so we can check whether a chunk that has zero IoCs still *mentions* a known entity.
        global_entity_values: set[str] = set()
        for e in gazetteer_entities + cyner_entities + semantic_ttp_entities + gliner_entities:
            global_entity_values.add(e.value.lower())

        # --- Document-level context for LLM (ADR-004 P2-B) ---
        # Solves the "IoC appendix" problem (CyNER/Fujii 2024):
        # IoCs listed at the end of a report have no local context in their chunk.
        # Passing the document-level entity summary to EVERY chunk call lets the LLM
        # correctly link appendix IoCs to the malware/actor from the narrative.
        doc_context = _build_doc_context(
            gazetteer_entities, cyner_entities, gliner_entities, semantic_ttp_entities
        )

        def _chunk_has_signals(chunk_text: str, chunk_ents: list) -> bool:
            """Return True if this chunk is worth sending to the LLM.

            A chunk is skipped when:
            - It is shorter than 200 chars (heading, page number, footer), OR
            - It has no IoC entities detected by regex AND none of the globally-
              detected entity names appear in it.

            This filters cover pages, table-of-contents, bibliography sections,
            and other boilerplate that carries zero threat intel.
            """
            # Hard minimum: very short chunks are always boilerplate
            if len(chunk_text.strip()) < 200:
                return False
            if chunk_ents:
                return True
            chunk_lower = chunk_text.lower()
            return any(ev in chunk_lower for ev in global_entity_values)

        # Per-document NER allow-list — all entity values found by high-precision
        # NER stages (gazetteer, CyNER, GLiNER, semantic TTP).  Passed to the
        # hallucination filter so it can skip the O(n) fuzzy scan for names it
        # already knows are real.  Lookup is O(1) via set membership.
        ner_allow_list: set[str] = {
            e.value.lower()
            for e in (
                gazetteer_entities
                + cyner_entities
                + gliner_entities
                + semantic_ttp_entities
            )
        }

        # ── Stage 3 — parallel LLM enrichment with crash-resume ─────────────
        #
        # Crash-resume design:
        #   • A checkpoint file is written atomically (via a .tmp rename) every
        #     CHECKPOINT_EVERY completions so a restart loses at most that many
        #     LLM calls.
        #   • On startup the worker looks for an existing checkpoint whose
        #     total_chunks matches the current document.  Matching chunks are
        #     loaded and their indices removed from llm_work so they are not
        #     re-sent to the LLM.
        #   • The checkpoint file is deleted when Stage 3 finishes cleanly.
        #     A lingering file always means the previous run crashed mid-stage.
        #   • File location: output/{job_id}_stage3.ckpt.json

        _PARALLELISM      = int(os.getenv("LLM_PARALLELISM",   "3"))
        _CHECKPOINT_EVERY = int(os.getenv("CHECKPOINT_EVERY",  "5"))

        from pipeline.stage3_llm import LLMEnrichmentResult as _LLMResult
        from pipeline.stage3_llm import enrich_chunk

        total      = len(chunks)
        skipped    = 0
        _ckpt_path = _ROOT / "output" / f"{job_id}_stage3.ckpt.json"
        _ckpt_path.parent.mkdir(parents=True, exist_ok=True)

        # ── Checkpoint helpers ──────────────────────────────────────────────

        def _ckpt_save(results: dict) -> None:
            """Write checkpoint atomically (tmp → rename) to avoid partial files."""
            data = {
                "job_id":       job_id,
                "total_chunks": total,
                "saved_at":     now_iso(),
                "chunks": {
                    str(k): v.model_dump_json()
                    for k, v in results.items()
                },
            }
            tmp = _ckpt_path.with_suffix(".tmp")
            try:
                tmp.write_text(json.dumps(data), encoding="utf-8")
                tmp.rename(_ckpt_path)
                logger.debug(f"[Stage 3] Checkpoint saved ({len(results)}/{total} chunks)")
            except Exception as _e:
                logger.warning(f"[Stage 3] Checkpoint save failed: {_e}")

        def _ckpt_load() -> tuple[dict, str]:
            """
            Load a prior checkpoint if it exists and belongs to this job/document.
            Returns (dict[int → LLMResult], saved_at_str) — empty dict if no valid checkpoint.
            """
            if not _ckpt_path.exists():
                return {}, ""
            try:
                data = json.loads(_ckpt_path.read_text(encoding="utf-8"))
                if data.get("total_chunks") != total:
                    logger.warning(f"[Stage 3] Checkpoint chunk count mismatch "
                                  f"({data.get('total_chunks')} ≠ {total}) — ignoring")
                    return {}, ""
                loaded: dict = {}
                for k_str, v_json in data.get("chunks", {}).items():
                    loaded[int(k_str)] = _LLMResult.model_validate_json(v_json)
                return loaded, data.get("saved_at", "")
            except Exception as _e:
                logger.warning(f"[Stage 3] Could not load checkpoint ({_e}) — starting fresh")
                return {}, ""

        # ── Attempt checkpoint resume ───────────────────────────────────────

        chunk_results, _ckpt_saved_at = _ckpt_load()
        if chunk_results:
            logger.info(
                f"[Stage 3] Resuming from checkpoint — {len(chunk_results)}/{total} "
                f"chunks already done (saved {_ckpt_saved_at})"
            )

        # Reconstruct running totals from any already-loaded results
        _run_malware = sum(len(r.malware_families) for r in chunk_results.values())
        _run_actors  = sum(len(r.threat_actors)    for r in chunk_results.values())
        _run_tools   = sum(len(r.tools)            for r in chunk_results.values())
        _run_rels    = sum(len(r.relationships)    for r in chunk_results.values())

        # ── Build work list (exclude checkpoint hits and signal-free chunks) ─

        llm_work: list[tuple[int, str, list]] = []
        for i, (chunk, ents) in enumerate(zip(chunks, entities_per_chunk), 1):
            if i in chunk_results:
                continue          # already processed in a previous run
            if not _chunk_has_signals(chunk, ents):
                skipped += 1
                logger.debug(f"[Stage 3] chunk {i}/{total} — skipped (no CTI signals)")
            else:
                llm_work.append((i, chunk, ents))

        n_llm      = len(llm_work)
        _stage3_t0 = time.monotonic()
        logger.info(
            f"[Stage 3] {n_llm} chunks → LLM ({skipped} skipped, "
            f"{len(chunk_results)} from checkpoint, parallelism={_PARALLELISM})"
        )

        # ── Parallel processing ─────────────────────────────────────────────

        _log_lock = threading.Lock()

        def _process_chunk(idx: int, chunk: str, ents: list) -> tuple[int, _LLMResult]:
            with _log_lock:
                logger.info(
                    f"[Stage 3] chunk {idx}/{total} — {len(chunk)} chars "
                    f"[elapsed {time.monotonic()-_stage3_t0:.0f}s]"
                )
            _t  = time.monotonic()
            res = enrich_chunk(
                chunk, ents,
                gazetteer_entities=gazetteer_entities,
                cyner_entities=cyner_entities,
                semantic_ttp_entities=semantic_ttp_entities,  # tells LLM which TTPs already found
                doc_context=doc_context or None,
                ner_allow_list=ner_allow_list,
            )
            elapsed = time.monotonic() - _t
            m, a, t_c, r = (len(res.malware_families), len(res.threat_actors),
                             len(res.tools),            len(res.relationships))
            parts = [f"{x} {n}" for x, n in
                     ((m,"malware"),(a,"actors"),(t_c,"tools"),(r,"rels")) if x]
            with _log_lock:
                logger.info(
                    f"[Stage 3] chunk {idx}/{total} ✓ {elapsed:.1f}s — "
                    f"{', '.join(parts) or 'nothing extracted'}"
                )
            return idx, res

        with ThreadPoolExecutor(max_workers=_PARALLELISM) as executor:
            futures = {
                executor.submit(_process_chunk, i, chunk, ents): i
                for i, chunk, ents in llm_work
            }
            completed           = 0
            _since_last_ckpt    = 0

            for future in as_completed(futures):
                # Check timeout before processing result
                check_timeout()

                idx, res = future.result()
                chunk_results[idx] = res
                completed        += 1
                _since_last_ckpt += 1

                # Accumulate running totals (main thread — no lock needed)
                _run_malware += len(res.malware_families)
                _run_actors  += len(res.threat_actors)
                _run_tools   += len(res.tools)
                _run_rels    += len(res.relationships)

                # Persist checkpoint every CHECKPOINT_EVERY completions
                if _since_last_ckpt >= _CHECKPOINT_EVERY:
                    _ckpt_save(chunk_results)
                    _since_last_ckpt = 0
                    logger.debug(f"[Stage 3] Checkpoint saved ({len(chunk_results)}/{total} chunks)")

                emit_progress(job_id, "stage", {
                    "stage": 3, "label": "LLM enrichment",
                    "chunk": completed, "total": n_llm,
                    "malware": _run_malware, "actors": _run_actors,
                    "tools":   _run_tools,   "relationships": _run_rels,
                })

        # Clean up checkpoint — only reached on clean completion
        try:
            _ckpt_path.unlink(missing_ok=True)
        except Exception:
            pass

        # Rebuild results in original chunk order
        all_results: list[_LLMResult] = [
            chunk_results.get(i, _LLMResult()) for i in range(1, total + 1)
        ]

        logger.info(
            f"[Stage 3] done — {n_llm} LLM calls, {skipped} skipped, "
            f"total elapsed {time.monotonic()-_stage3_t0:.0f}s"
        )
        logger.info(
            f"[Stage 3] totals: {_run_malware} malware, {_run_actors} actors, "
            f"{_run_tools} tools, {_run_rels} relationships"
        )

        from pipeline.stage3_llm import _merge_results
        llm_result = _merge_results(
            all_results,
            gazetteer_entities=gazetteer_entities,
            semantic_ttp_entities=semantic_ttp_entities,
            cyner_entities=cyner_entities,
        )

        # Save entities and relationships
        _save_entities(job_id, all_entities, llm_result)

        # Persist LLM result JSON for finalize
        llm_json = llm_result.model_dump_json()
        with _lock:
            with get_conn() as conn:
                conn.execute("UPDATE jobs SET llm_result_json=?, updated_at=? WHERE id=?",
                             (llm_json, now_iso(), job_id))
                conn.commit()

        # --- Stage 4 ---
        import json as _json_s4

        from pipeline.stage4_stix_mapping import build_stix_bundle
        report_name  = re.sub(r"[^\w\-]", "_", Path(original_filename).stem)
        source_hash  = _sha256_file(file_path)

        # Load the relationship policy from the DB (if one has been saved)
        _policy_s4: dict | None = None
        try:
            with get_conn() as _pc:
                _prow = _pc.execute(
                    "SELECT policy_json FROM relationship_policy WHERE id=1"
                ).fetchone()
            if _prow and _prow["policy_json"] not in ("", "{}"):
                _policy_s4 = _json_s4.loads(_prow["policy_json"])
        except Exception:
            pass

        # TLP / PAP markings selected by the user at upload time
        with get_conn() as _mc:
            _mrow = _mc.execute(
                "SELECT tlp_level, pap_level FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
        _tlp_level = _mrow["tlp_level"] if _mrow else None
        _pap_level = _mrow["pap_level"] if _mrow else None

        bundle = build_stix_bundle(
            all_entities, llm_result, report_name,
            report_text=text,
            original_filename=original_filename,
            source_hash=source_hash,
            relationship_policy=_policy_s4,
            tlp_level=_tlp_level,
            pap_level=_pap_level,
        )
        logger.info(f"[Stage 4] STIX mapping complete — {len(list(bundle.objects))} objects")
        emit_progress(job_id, "stage", {
            "stage": 4, "label": "STIX mapping", "objects": len(list(bundle.objects)),
        })

        # --- Stage 5 ---
        from pipeline.stage5_validation import validate_and_export
        out_path = str(_ROOT / "output" / f"{report_name}_bundle.json")
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        valid = validate_and_export(bundle, out_path)
        bundle_json = bundle.serialize(pretty=True)
        logger.info(f"[Stage 5] Validation complete — valid={valid}")
        emit_progress(job_id, "stage", {
            "stage": 5, "label": "Validation", "valid": valid,
        })

        with _lock:
            with get_conn() as conn:
                conn.execute(
                    "UPDATE jobs SET bundle_json=?, status=?, updated_at=? WHERE id=?",
                    (bundle_json, "for_review", now_iso(), job_id),
                )
                conn.commit()

        emit_progress(job_id, "done", {"status": "for_review"})

        # Backup database after successful processing
        try:
            backup_db()
            logger.info(f"[Worker] Database backup completed for job {job_id}")
        except Exception as e:
            logger.error(f"[Worker] Database backup failed: {e}")

    except TimeoutError as exc:
        error_msg = str(exc)
        set_job_status(job_id, "failed")
        emit_progress(job_id, "done", {"status": "failed", "error": error_msg})
        logger.error(f"[Worker TIMEOUT] job {job_id}: {error_msg}")
    except Exception as exc:
        import traceback
        error_msg = traceback.format_exc()
        set_job_status(job_id, "failed")
        emit_progress(job_id, "done", {"status": "failed", "error": str(exc)})
        logger.error(f"[Worker ERROR] job {job_id}: {error_msg}")
    finally:
        # No need to reset RLIMIT_AS — this subprocess is about to exit.
        # Counter management is handled by the parent process's watcher thread;
        # the call here is a no-op (subprocess has its own copy of _job_counter).
        _decrement_job_counter()
        logger.info(f"[Worker] Subprocess finished for job {job_id}")


def _subprocess_entry(job_id: str, file_path: str, original_filename: str) -> None:
    """
    Entry point for the isolated worker subprocess.

    This function runs inside a fresh Python interpreter (mp.get_context("spawn")).
    Setting thread-count env vars here — before any ML library import — limits the
    number of OpenMP/MKL worker threads each model spawns, which is the primary
    lever for reducing peak resident memory on CPU-only inference.

    RLIMIT_AS is applied inside _run_pipeline; it now correctly limits only this
    subprocess, not the uvicorn process.
    """
    # ── Thread-count caps ────────────────────────────────────────────────────
    # Each OpenMP worker allocates its own BLAS workspace.  2 threads is a
    # reasonable default for WSL/single-socket CPU inference.  Users who have
    # more RAM can raise this via env vars before starting the server.
    os.environ.setdefault("OMP_NUM_THREADS", "2")
    os.environ.setdefault("MKL_NUM_THREADS", "2")
    os.environ.setdefault("OPENBLAS_NUM_THREADS", "2")
    # HuggingFace fast tokenizers spawn a Rust thread pool; disable parallelism
    # for batches of 1 (standard pipeline use case) to save ~200-400 MB.
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

    _run_pipeline(job_id, file_path, original_filename)


def run_pipeline_async(job_id: str, file_path: str, original_filename: str) -> None:
    """
    Spawn an isolated subprocess for the pipeline and watch for crashes.

    Previous design used threading.Thread.  The problem: when a C++ extension
    (sentence-transformers, GLiNER, CyNER / XLM-RoBERTa) calls operator new and
    the system is out of memory, the C++ runtime calls std::terminate() → abort().
    abort() sends SIGABRT to the *whole process*, killing uvicorn — there is no
    way to catch a C++ exception from Python's except clause.

    Fix: run the pipeline in a separate process via multiprocessing.  SIGABRT only
    kills that subprocess; uvicorn continues serving.  A lightweight watcher thread
    in the parent detects the non-zero exit code and writes status=failed + emits a
    progress event so the frontend does not hang indefinitely.

    Why "spawn" not "fork":
      fork inherits the parent's open file descriptors, thread state, and any
      partially-initialised native libraries (e.g. torch's OpenMP pool).  This can
      produce deadlocks.  spawn starts a clean interpreter — slightly slower to
      start (~1-2 s on first import) but safe with all PyTorch/transformers builds.
    """
    if not _check_job_limit():
        set_job_status(job_id, "queued")
        emit_progress(job_id, "done", {"status": "queued", "error": "Job queue full"})
        logger.warning(f"[Worker] Job {job_id} queued — job queue full")
        return

    _increment_job_counter()
    logger.info(f"[Worker] Spawning isolated subprocess for job {job_id}")

    ctx = mp.get_context("spawn")
    proc = ctx.Process(
        target=_subprocess_entry,
        args=(job_id, file_path, original_filename),
        daemon=True,
        name=f"pipeline-{job_id}",
    )
    proc.start()
    logger.debug(f"[Worker] Subprocess pid={proc.pid} started for job {job_id}")

    _SIGNAL_NAMES: dict[int, str] = {
        -6:  "SIGABRT (std::bad_alloc or abort() in a native library)",
        -9:  "SIGKILL (OS out-of-memory killer)",
        -11: "SIGSEGV (segmentation fault in native code)",
    }

    def _watch(p: mp.Process, jid: str) -> None:
        p.join()                         # blocks until the subprocess exits
        _decrement_job_counter()         # parent-side counter; subprocess has its own copy
        code = p.exitcode
        if code == 0:
            logger.info(f"[Worker] Subprocess for job {jid} exited cleanly")
            return
        # `Process.exitcode` is `int | None` (None means "still running", which
        # shouldn't happen after join() but mypy can't know that) — narrow it
        # before using it as a dict key / format value.
        reason = (
            _SIGNAL_NAMES.get(code, f"exit code {code}")
            if code is not None
            else "unknown (process has no exit code)"
        )
        logger.error(f"[Worker] Subprocess for job {jid} crashed: {reason}")
        try:
            # The subprocess may have already written status=failed before dying,
            # but if the crash happened inside a native extension (std::bad_alloc
            # before Python gets control), it will not have done so.
            # set_job_status is idempotent — calling it again is safe.
            set_job_status(jid, "failed")
            emit_progress(jid, "done", {
                "status": "failed",
                "error": (
                    f"Pipeline worker process terminated unexpectedly ({reason}). "
                    "The document may require more memory than is available. "
                    "Try a smaller file, reduce WORKER_MAX_MEMORY_MB, or set "
                    "SKIP_HEAVY_MODELS=1 to disable ML models and use regex-only extraction."
                ),
            })
        except Exception as exc:
            logger.error(
                f"[Worker] Could not update job {jid} status after subprocess crash: {exc}"
            )

    watcher = threading.Thread(
        target=_watch,
        args=(proc, job_id),
        daemon=True,
        name=f"watcher-{job_id}",
    )
    watcher.start()


def _lexicon_rescan(job_id: str, report_text: str) -> int:
    """
    Report Lexicon Re-scan — per-report few-shot adaptation (Approach 1).

    After the reviewer accepts entities in the UI, those accepted values form a
    domain-specific lexicon for this document.  This function scans the full
    report text for every occurrence of each accepted entity value that the
    initial pipeline passes (regex, NER, LLM) may have missed.

    Why this matters:
      The LLM might extract "GREYVIBE" once from the executive summary, but the
      same name appears 12 more times in the body.  Stage 2 regex won't catch
      named malware families; Stage 2e (GLiNER) may miss low-confidence spans.
      The reviewer's accept decision is the highest-quality signal available —
      propagating it back over the full text closes the coverage gap at zero
      ML cost (pure string matching, O(text × entities)).

    Returns the number of new entity rows inserted.
    """
    from uuid import uuid4

    if not report_text:
        return 0

    text_lower = report_text.lower()

    with _lock:
        with get_conn() as conn:
            # Load accepted entities that are suitable for text-span matching.
            # Exclude generic SCO types (IPs, hashes) whose value is already
            # found exactly by regex — focus on named SDO entities.
            _SDO_TYPES = {
                "malware", "threat_actor", "intrusion_set", "tool",
                "campaign", "identity", "location", "infrastructure",
                "technique", "tactic", "procedure", "ttp",
                "vulnerability", "cve", "indicator", "incident",
            }
            rows = conn.execute(
                "SELECT id, value, entity_type, confidence, mitre_id, source "
                "FROM entities WHERE job_id=? AND accepted=1",
                (job_id,),
            ).fetchall()

            # Build a deduplicated lookup of existing (value_lower, entity_type) pairs
            existing_keys: set[tuple[str, str]] = {
                (r["value"].lower(), r["entity_type"]) for r in rows
            }

            to_insert: list[tuple] = []
            seen_new: set[tuple[str, str]] = set()

            for row in rows:
                etype = row["entity_type"]
                if etype not in _SDO_TYPES:
                    continue   # skip regex-handled SCOs
                value = row["value"].strip()
                if len(value) < 4:
                    continue   # too short — too many false positives
                value_lower = value.lower()

                # Scan the full text for ALL occurrences of this value
                pos = 0
                found_new = False
                while True:
                    idx = text_lower.find(value_lower, pos)
                    if idx == -1:
                        break
                    # Word-boundary check — don't match mid-word
                    before_ok = (idx == 0 or not text_lower[idx - 1].isalnum())
                    after_ok  = (
                        idx + len(value_lower) >= len(text_lower)
                        or not text_lower[idx + len(value_lower)].isalnum()
                    )
                    if before_ok and after_ok:
                        found_new = True   # at least one span found (even if original)
                    pos = idx + 1

                if not found_new:
                    continue

                # The entity appears in the text.  Insert a "report_lexicon" copy
                # only if not already present as a different source.
                new_key = (value_lower, etype)
                if new_key in existing_keys or new_key in seen_new:
                    continue
                seen_new.add(new_key)

                # Context: first 200 chars around first occurrence
                first_idx = text_lower.find(value_lower)
                ctx_start = max(0, first_idx - 60)
                ctx_end   = min(len(report_text), first_idx + len(value) + 60)
                context   = report_text[ctx_start:ctx_end].strip()

                to_insert.append((
                    str(uuid4()), job_id, value, etype,
                    context, row["confidence"], row["mitre_id"],
                    1,                  # accepted=True (reviewer already validated the label)
                    "report_lexicon",   # source tag — distinguishable from pipeline sources
                ))

            if to_insert:
                conn.executemany(
                    "INSERT OR IGNORE INTO entities "
                    "(id,job_id,value,entity_type,context,confidence,mitre_id,accepted,source) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    to_insert,
                )
                conn.commit()
                logger.info(
                    f"[lexicon_rescan] +{len(to_insert)} entity rows "
                    f"(source=report_lexicon, from {len(rows)} accepted SDO entities)"
                )

    return len(to_insert)


def re_run_final_stages(job_id: str, skip_rescan: bool = False) -> str | None:
    """
    Re-runs Stage 4+5 using the accepted entities currently in the DB.
    Returns the new bundle JSON, or None on failure.

    skip_rescan=True  — used by the auto-finalize (background debounce) to
                        skip the lexicon re-scan for speed.  The manual Finalize
                        button always passes skip_rescan=False (full re-scan).

    Entity sources stored during the pipeline:
      ioc       – regex-extracted IoC (Stage 2)
      gazetteer – MITRE name dictionary (Stage 2b)
      semantic  – embedding TTP match (Stage 2c)
      cyner     – CyNER cybersecurity NER (Stage 2d)
      gliner    – GLiNER zero-shot NER (Stage 2e)
      llm       – LLM extraction (Stage 3)
      manual    – reviewer-added via "Add as entity"

    Previously only source='ioc' and source='llm' were read, so accepted
    entities from all other sources — including every manually added entity —
    were silently dropped from the final bundle.  The fix reads all sources
    and routes each entity by its entity_type to the correct STIX path.
    """
    import sys
    from pathlib import Path
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

    from models.schemas import EntityType, RawEntity
    from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted
    from pipeline.stage4_stix_mapping import build_stix_bundle
    from pipeline.stage5_validation import validate_and_export

    with _lock:
        with get_conn() as conn:
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                return None

    # ── Report lexicon re-scan — runs BEFORE rebuilding the bundle ────────────
    # Uses the reviewer's accepted entities as a per-report domain lexicon and
    # scans the full text for additional occurrences of known named entities
    # that the initial NER/LLM passes may have missed.
    # Skipped when skip_rescan=True (auto-finalize path) to keep latency low.
    report_text = job["report_text"] or ""
    if not skip_rescan:
        new_count = _lexicon_rescan(job_id, report_text)
        if new_count:
            logger.info(f"[finalize] Lexicon re-scan added {new_count} new entity rows")

    with _lock:
        with get_conn() as conn:
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                return None

            # ALL accepted/unreviewed entities regardless of source
            all_entity_rows = conn.execute(
                "SELECT * FROM entities WHERE job_id=? AND (accepted IS NULL OR accepted=1)",
                (job_id,),
            ).fetchall()

            # ALL accepted/unreviewed relationships (DB is authoritative —
            # includes every manual addition, edit, or deletion from the UI)
            rel_rows = conn.execute(
                "SELECT * FROM relationships WHERE job_id=? AND (accepted IS NULL OR accepted=1)",
                (job_id,),
            ).fetchall()

    # ── Route entities to the correct STIX path ───────────────────────────────
    #
    # build_stix_bundle accepts two inputs:
    #   raw_entities  — RawEntity objects that map to SCOs (network IoCs, hashes)
    #                   or to SDOs handled via _entity_to_sdo / explicit loops
    #                   (CVE, technique, tactic, procedure, infrastructure, …)
    #   llm_result    — named lists for malware/threat-actor/tool SDOs
    #
    # Entity types that build_stix_bundle handles via raw_entities:
    _RAW_ENTITY_TYPES: frozenset[str] = frozenset({
        # SCOs
        EntityType.IPV4.value, EntityType.IPV6.value, EntityType.DOMAIN.value,
        EntityType.URL.value, EntityType.EMAIL.value, EntityType.MD5.value,
        EntityType.SHA1.value, EntityType.SHA256.value, EntityType.MAC_ADDR.value,
        EntityType.ASN.value, EntityType.FILE.value, EntityType.REGISTRY_KEY.value,
        EntityType.MUTEX.value, EntityType.NETWORK_TRAFFIC.value,
        EntityType.USER_ACCOUNT.value,
        # SDOs — stage4 handles these via _entity_to_sdo or explicit loops
        EntityType.CVE.value,
        EntityType.TECHNIQUE.value, EntityType.TACTIC.value,
        EntityType.PROCEDURE.value, EntityType.TTP.value,
        EntityType.INFRASTRUCTURE.value, EntityType.INTRUSION_SET.value,
        EntityType.LOCATION.value, EntityType.IDENTITY.value,
        EntityType.CAMPAIGN.value, EntityType.INCIDENT.value,
    })

    raw_entities: list[RawEntity] = []
    malware_names:       list[str] = []
    threat_actor_names:  list[str] = []
    tool_names:          list[str] = []
    seen_names: dict[str, set[str]] = {
        "malware": set(), "threat_actor": set(), "tool": set()
    }

    for row in all_entity_rows:
        etype_str = row["entity_type"]
        value     = row["value"]

        if etype_str in _RAW_ENTITY_TYPES:
            try:
                raw_entities.append(RawEntity(
                    value=value,
                    entity_type=EntityType(etype_str),
                    context=row["context"] or "",
                    confidence=row["confidence"],
                    mitre_id=row["mitre_id"],
                    source=row["source"],
                ))
            except Exception:
                pass  # defensive — skip any unknown enum value

        elif etype_str == EntityType.MALWARE.value:
            key = value.lower()
            if key not in seen_names["malware"]:
                malware_names.append(value)
                seen_names["malware"].add(key)

        elif etype_str == EntityType.THREAT_ACTOR.value:
            key = value.lower()
            if key not in seen_names["threat_actor"]:
                threat_actor_names.append(value)
                seen_names["threat_actor"].add(key)

        elif etype_str == EntityType.TOOL.value:
            key = value.lower()
            if key not in seen_names["tool"]:
                tool_names.append(value)
                seen_names["tool"].add(key)

        # EntityType.INTRUSION_SET is already in _RAW_ENTITY_TYPES and handled
        # by _entity_to_sdo.  Any unrecognised type strings are silently skipped.

    # ── Load original LLM JSON for fields that have no individual entity rows ───
    # (TTPs, ioc_associations, campaign_name, targeted_sectors/countries,
    #  course_of_action are stored only as aggregate JSON, not as individual rows)
    llm_result = LLMEnrichmentResult()
    if job["llm_result_json"]:
        try:
            llm_result = LLMEnrichmentResult.model_validate_json(job["llm_result_json"])
        except Exception:
            pass

    # ── Build rejection filter sets from the DB ────────────────────────────────
    # Bug fix: the JSON blob bypasses accept/reject decisions made in the UI.
    # Fetch rejected entity rows and use them to filter the JSON-blob fields
    # (ttps, campaign_name, targeted_countries, targeted_sectors) so that
    # objects the reviewer explicitly rejected don't sneak back into the bundle.
    with _lock:
        with get_conn() as conn:
            rejected_rows = conn.execute(
                "SELECT value, entity_type, mitre_id FROM entities "
                "WHERE job_id=? AND accepted=0",
                (job_id,),
            ).fetchall()

    rejected_ttp_names:    set[str] = set()
    rejected_ttp_mitre:    set[str] = set()
    rejected_locations:    set[str] = set()
    rejected_identities:   set[str] = set()
    rejected_campaigns:    set[str] = set()

    for r in rejected_rows:
        et  = r["entity_type"]
        val = r["value"].lower().strip()
        mid = (r["mitre_id"] or "").lower().strip()

        if et in ("technique", "tactic", "procedure", "ttp"):
            rejected_ttp_names.add(val)
            if mid:
                rejected_ttp_mitre.add(mid)
        elif et == "location":
            rejected_locations.add(val)
        elif et == "identity":
            rejected_identities.add(val)
        elif et == "campaign":
            rejected_campaigns.add(val)

    # Filter TTPs — a TTP is excluded if its name OR MITRE ID was explicitly rejected
    filtered_ttps = [
        t for t in llm_result.ttps
        if t.technique_name.lower() not in rejected_ttp_names
        and (not t.mitre_id or t.mitre_id.lower() not in rejected_ttp_mitre)
    ]

    # Filter campaign_name — excluded if the user rejected the campaign entity
    campaign_name = llm_result.campaign_name
    if campaign_name and campaign_name.lower().strip() in rejected_campaigns:
        campaign_name = None

    # Filter targeted countries and sectors — excluded if entity was rejected
    filtered_countries = [
        c for c in llm_result.targeted_countries
        if c.lower().strip() not in rejected_locations
    ]
    filtered_sectors = [
        s for s in llm_result.targeted_sectors
        if s.lower().strip() not in rejected_identities
    ]

    db_relationships = [
        RelationshipExtracted(
            source_value=row["source_value"],
            relationship_type=row["relationship_type"],
            target_value=row["target_value"],
            confidence=row["confidence"],
            evidence_text=row["evidence_text"] if "evidence_text" in row.keys() else None,
        )
        for row in rel_rows
    ]

    llm_result = LLMEnrichmentResult(
        # DB is the authoritative source for named SDOs — includes gazetteer,
        # CyNER, GLiNER, manual additions, and reviewer edits on top of LLM output.
        malware_families=malware_names,
        threat_actors=threat_actor_names,
        tools=tool_names,
        # JSON-blob fields, now filtered through the reviewer's decisions:
        ttps=filtered_ttps,
        ioc_associations=llm_result.ioc_associations,
        campaign_name=campaign_name,
        targeted_sectors=filtered_sectors,
        targeted_countries=filtered_countries,
        course_of_action=llm_result.course_of_action,
        # DB relationships override everything (manual adds/edits/deletions):
        relationships=db_relationships,
    )

    original_filename = job["original_filename"]
    report_name       = re.sub(r"[^\w\-]", "_", Path(original_filename).stem)

    # Locate the uploaded file to recompute its hash (stable — file never changes)
    upload_matches = list((_ROOT / "uploads").glob(f"{job_id}.*"))
    source_hash    = _sha256_file(upload_matches[0]) if upload_matches else None

    # Load the relationship policy for the finalize rebuild
    import json as _json_fin
    _policy_fin: dict | None = None
    try:
        with get_conn() as _pconn:
            _prow2 = _pconn.execute(
                "SELECT policy_json FROM relationship_policy WHERE id=1"
            ).fetchone()
        if _prow2 and _prow2["policy_json"] not in ("", "{}"):
            _policy_fin = _json_fin.loads(_prow2["policy_json"])
    except Exception:
        pass

    bundle = build_stix_bundle(
        raw_entities, llm_result, report_name,
        report_text=report_text,
        original_filename=original_filename,
        source_hash=source_hash,
        relationship_policy=_policy_fin,
        tlp_level=job["tlp_level"],
        pap_level=job["pap_level"],
    )
    bundle_json = bundle.serialize(pretty=True)

    out_path = str(_ROOT / "output" / f"{report_name}_bundle.json")
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    validate_and_export(bundle, out_path)

    with _lock:
        with get_conn() as conn:
            conn.execute(
                "UPDATE jobs SET bundle_json=?, status='completed', updated_at=? WHERE id=?",
                (bundle_json, now_iso(), job_id),
            )
            conn.commit()

    return bundle_json
