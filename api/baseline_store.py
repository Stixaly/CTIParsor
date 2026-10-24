"""The job-store side of a baseline (ADR-0090): what is written to
`job_baselines`, what the log says about the objects left out, and the
worker's schema validation.  `pipeline/baseline_stix.py` stays pure; the HTTP
routes (api/routes/_common.py) and the worker both come here.

The intake copies strings from the bundle, which is the attacker's.  A lone
surrogate cannot be encoded to UTF-8 (the JSON response of a route would
fail) and a line break would forge a log line, so `scrubbed` and `for_log`
clean them; a NUL stays, JSON writes it as `\\u0000` and PostgreSQL never
sees it as a raw character.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from api.db import _lock, get_conn, now_iso, transaction
from api.logging_config import get_logger
from pipeline import baseline_stix
from pipeline.baseline_stix import BaselineError, Intake

logger = get_logger(__name__)

# Objects named one by one, in the log and in a job's response; the rest are counted.
EXCLUDED_LISTED = 200


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return value.encode("utf-16", "surrogatepass").decode("utf-16", "replace")   # lone surrogate -> U+FFFD
    if isinstance(value, dict):
        return {_scrub(k): _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def scrubbed(intake: Intake) -> Intake:
    """The same intake with no lone surrogate in any string."""
    return Intake(**_scrub(asdict(intake)))


def intake_json(intake: Intake) -> str:
    """`job_baselines.intake_json`.  ASCII only, so a NUL is `\\u0000`."""
    return json.dumps(asdict(intake), ensure_ascii=True)


def for_log(text: str) -> str:
    """`text` on one line: a character that does not print (a line break, a
    control character, a lone surrogate) becomes U+FFFD."""
    return "".join(c if c.isprintable() else "�" for c in text)


def log_exclusions(job_id: str, excluded: list[dict]) -> None:
    """One WARNING per object the baseline leaves out (ADR-0090, D3), for the first
    EXCLUDED_LISTED; past them one line says how many more, and the job's intake
    lists them (GET /api/jobs/{id}/baseline/intake)."""
    for item in excluded[:EXCLUDED_LISTED]:
        logger.warning("[baseline] job %s: dropped invalid STIX object %s (%s): %s — %s", job_id,
                       for_log(item["id"]), for_log(item["type"]), for_log(item["reason"]),
                       for_log(item["detail"]))
    if len(excluded) > EXCLUDED_LISTED:
        logger.warning("[baseline] job %s: … and %d more excluded object(s), listed in the job's intake",
                       job_id, len(excluded) - EXCLUDED_LISTED)


def validate_in_worker(job_id: str) -> None:
    """For a job in `enrich` mode, run the intake again with the JSON schemas
    (the HTTP request ran stix2 only: the schemas take seconds per thousand
    objects) and store the result; `validated` becomes 1.  One WARNING per
    object the schemas exclude that the request did not.

    Raises BaselineError when the bundle cannot be used (the chosen Report
    itself fails the schemas): the job fails with that message.  Nothing to do
    for a job in `full` mode, nor for one already validated (a requeue, a lease
    reclaimed, a crash-resume).
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT j.pipeline_mode, b.bundle_json, b.report_id, b.intake_json, b.validated FROM jobs j "
            "LEFT JOIN job_baselines b ON b.job_id = j.id WHERE j.id=?", (job_id,)).fetchone()
    if row is None or row["pipeline_mode"] != "enrich" or row["validated"]:
        return
    if row["bundle_json"] is None:
        raise BaselineError("the job is in enrich mode but holds no baseline")
    index, fresh, _ = baseline_stix.intake(
        row["bundle_json"].encode("utf-8"), report_id=row["report_id"], validate=True)
    if index is None:                      # only a preview returns no index
        raise BaselineError("the baseline needs a report to be chosen")
    fresh = scrubbed(fresh)
    known = {(e["id"], e["reason"]) for e in json.loads(row["intake_json"])["excluded"]}
    added = [e for e in fresh.excluded if (e["id"], e["reason"]) not in known]
    with _lock:
        with get_conn() as conn:
            with transaction(conn):
                conn.execute(
                    "UPDATE job_baselines SET index_json=?, intake_json=?, validated=1, updated_at=? WHERE job_id=?",
                    (index.to_json(), intake_json(fresh), now_iso(), job_id))
    log_exclusions(job_id, added)
