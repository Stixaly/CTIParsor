"""Response models of `api/routes/policy.py` (ADR-0026, ADR-0027, ADR-0063).

The policy is stored as the body of the PUT, after the checks in `put_policy`.
The GET returns that stored body, or the factory default `{version, global,
rules}`.  A stored body may predate those checks, so no enumerated value is a
`Literal`: the expected values are listed in each description.  Every optional
key is absent when the body does not carry it, so the two policy routes use
`response_model_exclude_unset=True`.  `version` is not checked by the PUT: it is
typed as any JSON value.
"""
from __future__ import annotations

from typing import Any

from pydantic import Field, JsonValue

from api.response_models import Response


class PolicyRule(Response):
    src: str | None = Field(default=None, description="A STIX 2.1 object type, SDO or SCO.")
    verb: str | None = Field(default=None, description="A STIX 2.1 relationship type.")
    tgt: str | None = Field(default=None, description="A STIX 2.1 object type, SDO or SCO.")
    mode: str | None = Field(default=None, description="'pin' or 'auto'.")
    enabled: JsonValue = Field(default=None, description="true or false (default true).")


class PinEvidence(Response):
    mode: str | None = Field(default=None, description="'cooccurrence' (default) or 'cartesian'.")
    window: int | None = Field(default=None, description="Sentences apart, non-negative.")


class Completion(Response):
    transitive: bool | None = None
    alias: bool | None = None
    reference: bool | None = None
    long_distance: bool | None = None
    fuzzy_alias: bool | None = None
    semantic_alias: bool | None = None
    max_new_edges: int | None = None


class TemporalExport(Response):
    mode: str | None = Field(default=None, description="'faithful' (default) or 'day'.")


class RelationshipPolicy(Response):
    version: JsonValue = None
    global_: str | None = Field(
        default=None, alias="global", description="'enforce' (default) or 'auto'.",
    )
    rules: list[PolicyRule] | None = None
    max_pinned_edges: int | None = None
    pin_budget_mode: str | None = Field(
        default=None, description="'fair-share' (default) or 'sequential'.",
    )
    pin_evidence: PinEvidence | None = None
    completion: Completion | None = None
    temporal_export: TemporalExport | None = None


class LastRun(Response):
    job_id: str | None
    filename: str | None
    created_at: str | None
    # Free-form: the synthesis accounting of ADR-0026 is stored inside each
    # bundle, and its keys grew across ADRs, so an older bundle has fewer.
    pin: dict[str, Any] | None
    completion: dict[str, Any] | None
    available: bool
