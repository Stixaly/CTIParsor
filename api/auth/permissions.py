"""The minimum role of every operation (ADR-0097, Roles; docs/api-permissions.md).

`(METHOD, path template)` -> `reader`, `analyst`, `admin`, or `open` (no sign-in).
The template is the route's, as OpenAPI writes it (`/api/jobs/{job_id}`).
tests/test_auth_permissions.py fails for an operation of the app with no entry
and for an entry that matches no operation: a new route has to be given a role
here before it can ship.

Two rules are not a single role:
  * `DELETE /api/jobs/{job_id}` is `analyst` here; an analyst may delete only a
    report they imported, an admin any (`api/routes/jobs.py`, `may_delete`).
  * `/metrics` is not in this table. It is mounted outside `/api` (`api/main.py`,
    `_OWN_RULE_ROUTERS`) and has its own rule: a loopback client, or the `METRICS_TOKEN`
    bearer (`api/routes/metrics.py`; docs/api-permissions.md).
"""
from __future__ import annotations

OPEN = "open"

PERMISSIONS: dict[tuple[str, str], str] = {
    ("GET", "/api/health"): OPEN,
    # Sessions (api/routes/auth.py): a sign-in cannot need to be signed in.
    ("POST", "/api/auth/login"): OPEN,
    ("GET", "/api/auth/methods"): OPEN,
    ("GET", "/api/auth/oidc/login"): OPEN,
    ("GET", "/api/auth/oidc/callback"): OPEN,
    ("POST", "/api/auth/logout"): "reader",
    ("GET", "/api/auth/me"): "reader",
    # admin.py: users and tokens. A token route under /api/auth/ only touches the caller's own tokens.
    ("GET", "/api/auth/tokens"): "reader",
    ("POST", "/api/auth/tokens"): "reader",
    ("DELETE", "/api/auth/tokens/{token_id}"): "reader",
    ("GET", "/api/admin/users"): "admin",
    ("POST", "/api/admin/users"): "admin",
    ("PATCH", "/api/admin/users/{user_id}"): "admin",
    ("POST", "/api/admin/users/{user_id}/password"): "admin",
    ("GET", "/api/admin/tokens"): "admin",
    ("POST", "/api/admin/tokens"): "admin",
    ("DELETE", "/api/admin/tokens/{token_id}"): "admin",
    # attack.py, baselines.py
    ("GET", "/api/attack/index"): "reader",
    ("GET", "/api/baselines/status"): "reader",
    ("POST", "/api/baselines/inspect"): "analyst",
    # jobs.py
    ("GET", "/api/jobs"): "reader",
    ("GET", "/api/jobs/{job_id}"): "reader",
    ("GET", "/api/jobs/{job_id}/baseline"): "reader",
    ("GET", "/api/jobs/{job_id}/baseline/intake"): "reader",
    ("PATCH", "/api/jobs/{job_id}"): "analyst",
    ("POST", "/api/jobs/{job_id}/finalize"): "analyst",
    ("DELETE", "/api/jobs/{job_id}"): "analyst",
    ("GET", "/api/jobs/{job_id}/source"): "reader",
    ("GET", "/api/jobs/{job_id}/bundle"): "reader",
    ("GET", "/api/jobs/{job_id}/bundle/ledger"): "reader",
    # entities.py
    ("GET", "/api/jobs/{job_id}/entities"): "reader",
    ("POST", "/api/jobs/{job_id}/entities"): "analyst",
    ("PATCH", "/api/jobs/{job_id}/entities/{entity_id}"): "analyst",
    ("POST", "/api/jobs/{job_id}/entities/accept-pending"): "analyst",
    ("POST", "/api/jobs/{job_id}/entities/bulk"): "analyst",
    ("DELETE", "/api/jobs/{job_id}/entities/{entity_id}"): "analyst",
    # relationships.py
    ("GET", "/api/jobs/{job_id}/relationships"): "reader",
    ("GET", "/api/jobs/{job_id}/relationships/valid-types"): "reader",
    ("POST", "/api/jobs/{job_id}/relationships"): "analyst",
    ("POST", "/api/jobs/{job_id}/relationships/bulk"): "analyst",
    ("PATCH", "/api/jobs/{job_id}/relationships/{rel_id}"): "analyst",
    ("DELETE", "/api/jobs/{job_id}/relationships/{rel_id}"): "analyst",
    # progress.py
    ("GET", "/api/jobs/{job_id}/progress"): "reader",
    # overrides.py
    ("GET", "/api/overrides"): "reader",
    ("POST", "/api/overrides/promote"): "analyst",
    ("POST", "/api/overrides"): "analyst",
    ("PATCH", "/api/overrides/{override_id}"): "analyst",
    ("DELETE", "/api/overrides/{override_id}"): "analyst",
    # policy.py
    ("GET", "/api/relationship-policy"): "reader",
    ("GET", "/api/relationship-policy/last-run"): "reader",
    ("PUT", "/api/relationship-policy"): "admin",
    # queue.py
    ("GET", "/api/queue/status"): "reader",
    # llm.py
    ("GET", "/api/llm/egress"): "reader",
    # coverage.py
    ("GET", "/api/detection-corpora"): "reader",
    ("GET", "/api/jobs/{job_id}/coverage"): "reader",
    ("GET", "/api/jobs/{job_id}/coverage/rules"): "reader",
    ("GET", "/api/jobs/{job_id}/coverage/artifacts"): "reader",
    ("GET", "/api/jobs/{job_id}/coverage/{technique_id}/rules"): "reader",
    ("GET", "/api/jobs/{job_id}/detections/proposals"): "reader",
    ("GET", "/api/jobs/{job_id}/detections/export/facets"): "reader",
    ("GET", "/api/jobs/{job_id}/detections/export"): "analyst",
    ("POST", "/api/jobs/{job_id}/detections/export"): "analyst",
    ("POST", "/api/rules/lookup"): "reader",
    # settings.py
    ("GET", "/api/settings/corpora"): "admin",
    ("GET", "/api/settings/formats"): "admin",
    ("POST", "/api/settings/corpora"): "admin",
    ("PATCH", "/api/settings/corpora/{name}"): "admin",
    ("DELETE", "/api/settings/corpora/{name}"): "admin",
    ("POST", "/api/settings/corpora/{name}/sync"): "admin",
    ("POST", "/api/settings/corpora/rebuild"): "admin",
    # thresholds.py
    ("GET", "/api/thresholds"): "reader",
    ("POST", "/api/thresholds/recalibrate"): "admin",
    ("PUT", "/api/thresholds/{source}/{entity_type}"): "admin",
    ("DELETE", "/api/thresholds/{source}/{entity_type}"): "admin",
    # audit.py (ADR-0097 item 17): who changed what, admin only.
    ("GET", "/api/audit"): "admin",
    # upload.py, ingest.py
    ("POST", "/api/upload"): "analyst",
    ("POST", "/api/ingest/text"): "analyst",
    ("POST", "/api/ingest/url"): "analyst",
}


def required_role(method: str, template: str) -> str | None:
    """The minimum role of an operation, `open`, or None when the table has no entry
    (the caller refuses: an operation nobody classified is not open)."""
    return PERMISSIONS.get((method.upper(), template))
