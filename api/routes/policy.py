"""
GET /api/relationship-policy  — return the current policy JSON
PUT /api/relationship-policy  — replace the policy (full replacement)

Policy shape:
  { "version": 1,
    "global": "enforce" | "auto",
    "rules": [{ "src", "verb", "tgt", "mode": "pin"|"auto", "enabled": bool }],
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
    if "global" in body and body["global"] not in ("enforce", "auto"):
        raise HTTPException(400, "'global' must be 'enforce' or 'auto'")
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
