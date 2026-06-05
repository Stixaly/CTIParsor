"""
GET /api/relationship-policy  — return the current policy JSON
PUT /api/relationship-policy  — replace the policy (full replacement)

Policy shape:
  { "version": 1,
    "global": "enforce" | "auto",
    "rules": [{ "src", "verb", "tgt", "mode": "pin"|"auto", "enabled": bool }] }
"""
import json
from fastapi import APIRouter, Request, HTTPException
from api.db import get_conn, _lock

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

    policy_json = json.dumps(body)
    with _lock:
        with get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO relationship_policy (id, policy_json) VALUES (1, ?)",
                (policy_json,),
            )
            conn.commit()
    return body
