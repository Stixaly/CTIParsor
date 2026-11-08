"""Response models of api/routes/llm.py."""
from pydantic import Field

from api.response_models import Response as ApiResponse


class EgressVerdict(ApiResponse):
    """`EgressDecision.record()` of pipeline/egress.py, plus the reason of a refusal."""

    tlp: str
    provider: str
    host: str | None
    local: bool
    allowed: bool
    reason: str = Field(description="Why the report may not go there; empty when it may.")


class EgressPreview(ApiResponse):
    """GET /api/llm/egress."""

    tlp: str = Field(description="The marking that applies: the one asked for, else the default (STIX_TLP, AMBER).")
    text: EgressVerdict = Field(description="The Stage 3 provider, and whether the report's text may go to it.")
    figures: EgressVerdict | None = Field(
        description="The Stage 1f provider; null when the vision setting names no backend (nothing is sent).")
