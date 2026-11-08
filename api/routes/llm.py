"""What the TLP egress policy (ADR-0097) allows, before a report is imported.

Reads the environment only: no network, no LLM client.
"""
from fastapi import APIRouter, HTTPException, Query

from api.response_models.llm import EgressPreview
from pipeline import egress
from pipeline.egress import EgressDecision

router = APIRouter(prefix="/api/llm", tags=["llm"])


def _verdict(decision: EgressDecision) -> dict:
    return {**decision.record(), "reason": decision.reason}


@router.get("/egress", response_model=EgressPreview, response_model_exclude_unset=True,
            responses={400: {"description": "Unknown TLP level."}})
def get_egress(tlp: str | None = Query(None, description="CLEAR, GREEN, AMBER, AMBER+STRICT or RED; "
                                                         "absent = the default marking.")):
    """May a report marked `tlp` go to the configured text and figure providers?"""
    from pipeline.orchestrator import text_egress
    from pipeline.vlm import vision_provider_name

    try:
        level = egress.effective_tlp(tlp)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    named = vision_provider_name()
    return {
        "tlp": level,
        "text": _verdict(text_egress(level)),
        "figures": _verdict(egress.decide(level, named)) if named else None,
    }
