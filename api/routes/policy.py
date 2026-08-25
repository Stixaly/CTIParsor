"""
GET /api/relationship-policy           — return the current policy JSON
PUT /api/relationship-policy           — replace the policy (full replacement)
GET /api/relationship-policy/last-run  — per-rule synthesis accounting of the
                                         most recent bundle (ADR-0026)

Policy shape:
  { "version": 1,
    "global": "enforce" | "auto",
    "rules": [{ "src", "verb", "tgt", "mode": "pin"|"auto", "enabled": bool }],
    "max_pinned_edges": int,        # total budget for pin materialisation (200)
    "pin_budget_mode":              # how that budget is split across rules
      "fair-share" | "sequential",  #   fair-share (default) | first-come (legacy)
    "pin_evidence": {               # ADR-0027 — gate pins on textual proximity
      "mode":                       #   cooccurrence (default) | cartesian
        "cooccurrence" | "cartesian",
      "window": int },              #   sentences apart, default 3
    "completion": {                 # optional — Stage 4b graph completion
      "transitive": bool,           # deterministic transitive inference (default on)
      "alias": bool,                # same-object alias merge (default on)
      "reference": bool,            # ATT&CK curated-edge grounding (default on)
      "long_distance": bool,        # LLM long-distance prediction (default off)
      "fuzzy_alias": bool,          # fuzzy name matching in alias merge (default off)
      "semantic_alias": bool,       # embedding-based alias matching (default off)
      "max_new_edges": int } }      # safety cap on inferred edges (default 200)

"completion" is the "let the tool decide" switch; per-rule "pin" is "the analyst
specifies the link" and always wins over inference.
"""
import json

from fastapi import APIRouter, HTTPException, Request

from api.db import _lock, get_conn

router = APIRouter(prefix="/api/relationship-policy", tags=["policy"])

_DEFAULT_POLICY = {
    "version": 1,
    "global": "enforce",
    "rules": [],
}

# Shape returned by /last-run when there is nothing to report.  The keys are
# always present so the client never has to test for their existence.
_EMPTY_LAST_RUN: dict = {
    "job_id": None,
    "filename": None,
    "created_at": None,
    "pin": None,
    "completion": None,
    "available": False,
}


def _extract_synthesis_stats(bundle_json: str | None) -> dict | None:
    """Return the `x_synthesis_stats` carried by a bundle's report SDO, or None.

    Stage 4 stamps the property on the report object (ADR-0026); bundles built
    before it have no such property.  `bundle_json` comes straight out of a
    database column, so every step is guarded and nothing raises: a corrupt row
    must not take down a settings page.
    """
    if not bundle_json:
        return None
    try:
        parsed = json.loads(bundle_json)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    objects = parsed.get("objects")
    if not isinstance(objects, list):
        return None
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "report":
            continue
        stats = obj.get("x_synthesis_stats")
        return stats if isinstance(stats, dict) else None
    return None


@router.get("/last-run")
def get_last_run() -> dict:
    """Synthesis accounting of the most recent bundle — what each pinned rule
    actually produced on the last run.

    Exactly ONE job is examined, deliberately: `bundle_json` runs to well over a
    megabyte, and scanning back until a bundle carries the property would make
    the endpoint's latency depend on how many old bundles are stored.  "Last
    run" means the last run, not "the last run that has this data" — when the
    newest bundle predates ADR-0026 the answer is `available: false`, which is
    the honest one and lets the UI say so.
    """
    try:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT id, original_filename, created_at, bundle_json "
                "FROM jobs "
                "WHERE bundle_json IS NOT NULL AND bundle_json != '' "
                "ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
    except Exception:
        return dict(_EMPTY_LAST_RUN)

    if row is None:
        return dict(_EMPTY_LAST_RUN)

    stats = _extract_synthesis_stats(row["bundle_json"])
    pin = stats.get("pin") if isinstance(stats, dict) else None
    completion = stats.get("completion") if isinstance(stats, dict) else None

    return {
        "job_id": row["id"],
        "filename": row["original_filename"],
        "created_at": row["created_at"],
        "pin": pin if isinstance(pin, dict) else None,
        "completion": completion if isinstance(completion, dict) else None,
        "available": isinstance(pin, dict),
    }


@router.get("")
def get_policy() -> dict:
    """Return the stored relationship policy, or the factory default."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT policy_json FROM relationship_policy WHERE id=1"
        ).fetchone()
    if row and row["policy_json"] and row["policy_json"] != "{}":
        try:
            return json.loads(row["policy_json"])
        except Exception:
            pass
    return _DEFAULT_POLICY.copy()


@router.put("")
async def put_policy(request: Request) -> dict:
    """Replace the relationship policy (full replacement, not patch)."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Request body must be valid JSON")

    # Light validation
    if not isinstance(body, dict):
        raise HTTPException(400, "Policy must be a JSON object")
    if "rules" in body and not isinstance(body["rules"], list):
        raise HTTPException(400, "'rules' must be an array")
    # Validate the items, not just the container: `{"rules": ["oops"]}` used to
    # pass this check, get stored, and then fail every subsequent job in
    # build_stix_bundle with an opaque AttributeError.
    for _i, _rule in enumerate(body.get("rules") or []):
        if not isinstance(_rule, dict):
            raise HTTPException(400, f"'rules[{_i}]' must be a JSON object")
    if "global" in body and body["global"] not in ("enforce", "auto"):
        raise HTTPException(400, "'global' must be 'enforce' or 'auto'")
    if "pin_budget_mode" in body and body["pin_budget_mode"] not in (
        "fair-share", "sequential"
    ):
        raise HTTPException(
            400, "'pin_budget_mode' must be 'fair-share' or 'sequential'"
        )
    if "max_pinned_edges" in body and (
        not isinstance(body["max_pinned_edges"], int)
        or isinstance(body["max_pinned_edges"], bool)
        or body["max_pinned_edges"] < 0
    ):
        raise HTTPException(400, "'max_pinned_edges' must be a non-negative integer")
    if "pin_evidence" in body:
        ev = body["pin_evidence"]
        if not isinstance(ev, dict):
            raise HTTPException(400, "'pin_evidence' must be a JSON object")
        if "mode" in ev and ev["mode"] not in ("cooccurrence", "cartesian"):
            raise HTTPException(
                400, "'pin_evidence.mode' must be 'cooccurrence' or 'cartesian'"
            )
        if "window" in ev and (
            not isinstance(ev["window"], int)
            or isinstance(ev["window"], bool)
            or ev["window"] < 0
        ):
            raise HTTPException(
                400, "'pin_evidence.window' must be a non-negative integer"
            )
    if "completion" in body:
        comp = body["completion"]
        if not isinstance(comp, dict):
            raise HTTPException(400, "'completion' must be a JSON object")
        for _flag in ("transitive", "alias", "reference", "long_distance",
                      "fuzzy_alias", "semantic_alias"):
            if _flag in comp and not isinstance(comp[_flag], bool):
                raise HTTPException(400, f"'completion.{_flag}' must be a boolean")
        if "max_new_edges" in comp and (
            not isinstance(comp["max_new_edges"], int)
            or isinstance(comp["max_new_edges"], bool)
            or comp["max_new_edges"] < 0
        ):
            raise HTTPException(400, "'completion.max_new_edges' must be a non-negative integer")

    policy_json = json.dumps(body)
    with _lock:
        with get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO relationship_policy (id, policy_json) VALUES (1, ?)",
                (policy_json,),
            )
            conn.commit()
    return body
