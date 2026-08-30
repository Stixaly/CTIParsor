# pipeline/stage2f_cve_enrichment.py
from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.request

from api.db import get_conn, now_iso
from pipeline.env_flags import env_bool

logger = logging.getLogger(__name__)

_MAX_FETCH = 25
_MAX_TOTAL_SECONDS = 30.0
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def is_valid_cve(cve_id: str) -> bool:
    """Is this a well-formed CVE id?

    Called before the id ever reaches a URL. The ids come from a regex over
    attacker-controlled report text, and this function is public, so nothing
    upstream can be assumed to have normalised them.
    """
    if not isinstance(cve_id, str):
        return False
    return bool(_CVE_PATTERN.match(cve_id.strip().upper()))


def enrichment_enabled() -> bool:
    """Is the CIRCL lookup allowed to reach the network?

    Off by default. Stages 1, 2, 4 and 5 are documented as fully offline, and
    this adds an external call to Stage 2 — so it is opt-in, the same way
    VISION_PROVIDER=none keeps Stage 1f off until asked.
    """
    return env_bool("CVE_ENRICHMENT", default=False)


def _fetch_from_circl(cve_id: str) -> dict | None:
    """Fetch one CVE's description and CVSS v3 score from CIRCL, or None."""
    if not is_valid_cve(cve_id):
        return None

    url = f"https://cve.circl.lu/api/cve/{cve_id.strip().upper()}"
    req = urllib.request.Request(url, headers={"User-Agent": "CTIParsor/1.0"})

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status != 200:
                return None
            body = json.loads(response.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to fetch %s from CIRCL: %s", cve_id, e)
        return None

    if not isinstance(body, dict):
        return None

    description = None
    containers = body.get("containers")
    if isinstance(containers, dict):
        cna = containers.get("cna")
        if isinstance(cna, dict):
            descriptions = cna.get("descriptions")
            if isinstance(descriptions, list):
                for d in descriptions:
                    if isinstance(d, dict) and d.get("lang") == "en":
                        description = d.get("value")
                        break

    score = None
    vector = None
    if isinstance(containers, dict):
        adps = containers.get("adp")
        if isinstance(adps, list):
            for adp in adps:
                if not isinstance(adp, dict):
                    continue
                metrics = adp.get("metrics")
                if not isinstance(metrics, list):
                    continue
                for m in metrics:
                    if not isinstance(m, dict):
                        continue
                    if "cvssV3_1" in m and isinstance(m["cvssV3_1"], dict):
                        score = m["cvssV3_1"].get("baseScore")
                        vector = m["cvssV3_1"].get("vectorString")
                        break
                    elif "cvssV3_0" in m and isinstance(m["cvssV3_0"], dict):
                        score = m["cvssV3_0"].get("baseScore")
                        vector = m["cvssV3_0"].get("vectorString")
                        break
                if score is not None:
                    break

        if score is None:
            cna = containers.get("cna")
            if isinstance(cna, dict):
                metrics = cna.get("metrics")
                if isinstance(metrics, list):
                    for m in metrics:
                        if not isinstance(m, dict):
                            continue
                        if "cvssV3_1" in m and isinstance(m["cvssV3_1"], dict):
                            score = m["cvssV3_1"].get("baseScore")
                            vector = m["cvssV3_1"].get("vectorString")
                            break
                        elif "cvssV3_0" in m and isinstance(m["cvssV3_0"], dict):
                            score = m["cvssV3_0"].get("baseScore")
                            vector = m["cvssV3_0"].get("vectorString")
                            break

    return {"description": description, "cvss_score": score, "cvss_vector": vector}


def get_cached(cve_ids: set[str]) -> tuple[dict[str, dict], set[str]]:
    """Return (data, known) for the given ids.

    `known` includes remembered misses — rows with no description and no
    score. Returning only `data` would make an unknown CVE look uncached and
    be re-fetched on every single run.
    """
    if not cve_ids:
        return {}, set()

    data: dict[str, dict] = {}
    known: set[str] = set()

    with get_conn() as conn:
        placeholders = ",".join("?" for _ in cve_ids)
        rows = conn.execute(
            f"SELECT cve_id, description, cvss_score, cvss_vector FROM cve_cache WHERE cve_id IN ({placeholders})",
            list(cve_ids),
        ).fetchall()

        for row in rows:
            known.add(row["cve_id"])
            if row["description"] is not None or row["cvss_score"] is not None:
                data[row["cve_id"]] = {
                    "description": row["description"],
                    "cvss_score": row["cvss_score"],
                    "cvss_vector": row["cvss_vector"],
                }

    return data, known


def save_to_cache(cve_id: str, data: dict | None) -> None:
    """Store a lookup result. `data=None` records the miss, deliberately."""
    with get_conn() as conn:
        if data is None:
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache"
                " (cve_id, description, cvss_score, cvss_vector, fetched_at)"
                " VALUES (?, NULL, NULL, NULL, ?)",
                (cve_id, now_iso()),
            )
        else:
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache"
                " (cve_id, description, cvss_score, cvss_vector, fetched_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    cve_id,
                    data.get("description"),
                    data.get("cvss_score"),
                    data.get("cvss_vector"),
                    now_iso(),
                ),
            )


def enrich_cves(cve_ids: set[str]) -> dict[str, dict]:
    """Add CIRCL metadata to the CVEs that have it, within a bounded budget.

    Serves the cache unconditionally; reaches the network only when enabled,
    and then for at most _MAX_FETCH ids inside _MAX_TOTAL_SECONDS. Without
    those caps a report carrying 200 CVEs would add minutes of sequential
    5-second timeouts to the pipeline.
    """
    valid_ids = {cve.strip().upper() for cve in cve_ids if is_valid_cve(cve)}
    invalid_count = len(cve_ids) - len(valid_ids)
    if invalid_count > 0:
        logger.debug("%d invalid CVE identifiers filtered out", invalid_count)

    data, known = get_cached(valid_ids)

    if not enrichment_enabled():
        return data

    missing = valid_ids - known
    if not missing:
        return data

    start_time = time.monotonic()
    fetch_count = 0
    skipped = 0

    for cve in sorted(missing):
        if fetch_count >= _MAX_FETCH:
            skipped = len(missing) - fetch_count
            break

        if time.monotonic() - start_time >= _MAX_TOTAL_SECONDS:
            skipped = len(missing) - fetch_count
            break

        result = _fetch_from_circl(cve)
        save_to_cache(cve, result)
        fetch_count += 1

        if result is not None:
            data[cve] = result

    if skipped > 0:
        logger.warning("%d CVEs not enriched due to fetch limits", skipped)

    return data
