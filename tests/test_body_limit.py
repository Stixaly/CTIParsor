"""Request bodies held to their route's budget while they arrive (api/body_limit.py).

FastAPI spools a multipart form to disk before the handler runs, so the
handler's own size checks came after the whole body was read, and a body sent
without `Content-Length` was bounded by nothing.  The middleware is tested alone
(which of the client's chunks it asks for, what it answers) and in the
application (nothing spooled, nothing stored).
"""
from __future__ import annotations

import asyncio
import itertools
import json
import logging
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import httpx
import pytest
from starlette.responses import JSONResponse, PlainTextResponse

from api.body_limit import DEFAULT_BUDGET_BYTES, ENVELOPE_BYTES, BodyLimitMiddleware
from api.paths import uploads_dir

_REPORT = b"APT29 deployed SUNBURST and contacted 185.220.101.45 for C2.\n"
_ROOT = Path(__file__).resolve().parent.parent


# ── The middleware alone ─────────────────────────────────────────────────────

def _reader(seen: list[bytes]):
    """Reads the whole body, then answers 200; answers 400 when the client goes
    away mid-body, as FastAPI does."""
    async def app(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                await JSONResponse({"detail": "There was an error parsing the body"}, 400)(scope, receive, send)
                return
            seen.append(message.get("body", b""))
            if not message.get("more_body"):
                break
        await PlainTextResponse("ok")(scope, receive, send)
    return app


def _limited(app, budget: int):
    return BodyLimitMiddleware(app, budgets={("POST", "/up"): lambda: budget})


def _drive(app, chunks: list[bytes], *, path: str = "/up", root_path: str = "",
           headers: list[tuple[bytes, bytes]] | None = None):
    """Send `chunks` as one body; returns how many the client was asked for, and what it was sent."""
    pulled = 0
    sent: list[dict] = []

    async def receive():
        nonlocal pulled
        if pulled == len(chunks):
            return {"type": "http.disconnect"}
        pulled += 1
        return {"type": "http.request", "body": chunks[pulled - 1], "more_body": pulled < len(chunks)}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "http_version": "1.1", "method": "POST", "scheme": "http", "path": path,
             "raw_path": path.encode(), "root_path": root_path, "query_string": b"", "headers": headers or []}
    asyncio.run(app(scope, receive, send))
    return pulled, sent


def _statuses(sent: list[dict]) -> list[int]:
    return [m["status"] for m in sent if m["type"] == "http.response.start"]


def _body(sent: list[dict]) -> bytes:
    return b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


def test_a_body_without_content_length_is_cut_as_it_passes_the_budget():
    seen: list[bytes] = []
    pulled, sent = _drive(_limited(_reader(seen), 3500), [b"x" * 1000] * 50)
    assert pulled == 4                      # the 4th chunk passes 3,500 bytes: nothing is asked for after it
    assert sum(map(len, seen)) == 3000      # and the application never gets it
    assert _statuses(sent) == [413]         # its 400 to the "disconnect" is dropped
    assert json.loads(_body(sent)) == {"detail": "Request too large. /up accepts at most 3 KB."}


def test_a_content_length_over_the_budget_is_refused_before_a_byte_is_read():
    seen: list[bytes] = []
    pulled, sent = _drive(_limited(_reader(seen), 3500), [b"x" * 4000], headers=[(b"content-length", b"4000")])
    assert (pulled, seen, _statuses(sent)) == (0, [], [413])


def test_the_budget_itself_is_accepted():
    seen: list[bytes] = []
    for headers in ([(b"content-length", b"3500")], None):
        pulled, sent = _drive(_limited(_reader(seen), 3500), [b"x" * 3000, b"x" * 500], headers=headers)
        assert pulled == 2 and _statuses(sent) == [200]
    assert _statuses(_drive(_limited(_reader([]), 3500), [b"x" * 3000, b"x" * 501])[1]) == [413]


@pytest.mark.parametrize("value", [b"abc", b"-1", b"1 2", b"0x10", b"\xb2"])     # \xb2 is `²`, a digit to str.isdigit
def test_an_invalid_content_length_is_a_400_not_a_500(value):
    pulled, sent = _drive(_limited(_reader([]), 3500), [b"x"], headers=[(b"content-length", value)])
    assert pulled == 0 and _statuses(sent) == [400]


def test_a_content_length_of_thousands_of_digits_is_read_by_its_length():
    """`int()` refuses a string of more than 4,300 digits."""
    _, sent = _drive(_limited(_reader([]), 3500), [b"x"], headers=[(b"content-length", b"9" * 5000)])
    assert _statuses(sent) == [413]
    _, sent = _drive(_limited(_reader([]), 3500), [b"x"], headers=[(b"content-length", b"0" * 5000 + b"1")])
    assert _statuses(sent) == [200]


def test_a_root_path_in_front_does_not_slip_past_the_budget():
    """`uvicorn --root-path /cti` puts the prefix in `path`; the router matches without it."""
    _, sent = _drive(_limited(_reader([]), 3500), [b"x" * 4000], path="/cti/up", root_path="/cti")
    assert json.loads(_body(sent)) == {"detail": "Request too large. /up accepts at most 3 KB."}
    _, sent = _drive(_limited(_reader([]), 3500), [b"x" * 4000], path="/up", root_path="/cti")
    assert _statuses(sent) == [413]                 # a server that leaves the prefix out of `path`


def test_a_route_without_a_budget_is_left_alone():
    seen: list[bytes] = []
    pulled, sent = _drive(_limited(_reader(seen), 10), [b"x" * 1000] * 3, path="/other")
    assert pulled == 3 and sum(map(len, seen)) == 3000 and _statuses(sent) == [200]


def test_a_route_without_a_budget_of_its_own_is_held_to_the_default():
    app = BodyLimitMiddleware(_reader([]), budgets={("POST", "/up"): lambda: 3500}, default=lambda: 2048)
    for headers in ([(b"content-length", b"5000")], None):
        pulled, sent = _drive(app, [b"x" * 1000] * 5, path="/other", headers=headers)
        assert pulled == (0 if headers else 3) and _statuses(sent) == [413]
        assert json.loads(_body(sent)) == {"detail": "Request too large. /other accepts at most 2 KB."}
    assert _statuses(_drive(app, [b"x" * 3000], path="/up")[1]) == [200]     # its own budget, not the default


def test_a_path_is_matched_as_the_router_matches_it(caplog):
    """`{job_id}` is one segment, and the router's regex ends in `$`, which also
    takes the path followed by a newline: `/up%0A` reaches the `/up` route.  The
    path is quoted in the log, or the newline would start a line of its own."""
    app = BodyLimitMiddleware(_reader([]), budgets={("POST", "/up"): lambda: 3500,
                                                     ("POST", "/jobs/{job_id}/export"): lambda: 8000})
    with caplog.at_level(logging.INFO, logger="api.body_limit"):
        _, sent = _drive(app, [b"x" * 4000], path="/up\n")
    assert json.loads(_body(sent)) == {"detail": "Request too large. /up%0A accepts at most 3 KB."}
    assert [r.getMessage() for r in caplog.records] == [
        "[body-limit] POST /up%0A cut off: past its 3500-byte budget"]
    assert _statuses(_drive(app, [b"x" * 7000], path="/jobs/j-1/export")[1]) == [200]
    assert _statuses(_drive(app, [b"x" * 9000], path="/jobs/j-1/export")[1]) == [413]
    assert _statuses(_drive(app, [b"x" * 9000], path="/jobs/j-1/x/export")[1]) == [200]    # another route


def test_an_error_after_the_413_stays_behind_it():
    """The application may fail on the body it never got whole: the client has its 413."""
    async def failing(scope, receive, send):
        while (await receive())["type"] != "http.disconnect":
            pass
        raise RuntimeError("half a form")

    _, sent = _drive(_limited(failing, 10), [b"x" * 8] * 5)
    assert _statuses(sent) == [413]


def test_an_error_with_no_cut_is_raised():
    async def failing(scope, receive, send):
        raise RuntimeError("a bug")

    with pytest.raises(RuntimeError, match="a bug"):
        _drive(_limited(failing, 10), [b"x"])


def test_a_response_already_started_is_cut_off_from_the_body_not_replaced():
    """Too late for a 413: the application's answer goes on, without the rest of the body."""
    async def answers_first(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        while (await receive())["type"] != "http.disconnect":
            pass
        await send({"type": "http.response.body", "body": b"cut"})

    pulled, sent = _drive(_limited(answers_first, 10), [b"x" * 8] * 5)
    assert pulled == 2 and _statuses(sent) == [200] and _body(sent) == b"cut"


# ── In the application ───────────────────────────────────────────────────────

@pytest.fixture()
def client(temp_db_client):
    import api.main

    api.main.limiter.reset()                  # 10/minute is shared by every test
    with patch("api.worker.run_pipeline_async", return_value="started") as spawn:
        temp_db_client.spawn = spawn          # type: ignore[attr-defined]
        yield temp_db_client


@pytest.fixture()
def spooled(monkeypatch):
    """The bytes written to each temporary file Starlette's multipart parser opens
    for a file part (it rolls over to disk past 1 MB)."""
    import starlette.formparsers

    written: list[int] = []

    class Recording(starlette.formparsers.SpooledTemporaryFile):     # type: ignore[misc]
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._slot = len(written)
            written.append(0)

        def write(self, s):
            written[self._slot] += len(s)
            return super().write(s)

    monkeypatch.setattr(starlette.formparsers, "SpooledTemporaryFile", Recording)
    return written


@pytest.fixture()
def small_budget(monkeypatch) -> int:
    """POST /api/upload held to a 4 KB report and its form (68 KB), the mode off."""
    from api.routes import upload

    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "false")
    monkeypatch.setattr(upload, "_MAX_BYTES", 4096)
    return upload.body_budget()


def _form(content: bytes, filename: str = "report.txt") -> tuple[bytes, str]:
    """A one-file multipart body, encoded here so that it can also go without Content-Length."""
    boundary = "cti-body-limit"
    head = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: text/plain\r\n\r\n")
    return head.encode() + content + f"\r\n--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


def _stored() -> list[Path]:
    return list(uploads_dir().glob("*"))


@pytest.mark.parametrize("declared", [True, False], ids=["content-length", "no-content-length"])
def test_an_upload_over_its_budget_is_refused_before_anything_is_spooled_or_stored(
        client, small_budget, spooled, declared):
    """Without Content-Length the test client still hands the body over in one message:
    it is refused as it arrives.  The test below sends it in chunks."""
    body, content_type = _form(_REPORT * (2 * small_budget // len(_REPORT)))
    resp = client.post("/api/upload", content=body if declared else iter([body]),
                       headers={"content-type": content_type})
    assert ("content-length" in resp.request.headers) is declared
    assert resp.status_code == 413
    assert resp.json()["detail"] == "Request too large. /api/upload accepts at most 68 KB."
    assert spooled == [] and _stored() == []
    client.spawn.assert_not_called()


def test_an_upload_streamed_past_its_budget_is_cut_there(small_budget, spooled):
    """The whole stack, the body in 8 KB chunks without Content-Length: nothing is
    asked of the client after the chunk that passes the budget."""
    import api.main

    body, content_type = _form(b"a" * (20 * small_budget))
    size = 8 * 1024
    pulled = 0

    async def chunks():
        nonlocal pulled
        for start in range(0, len(body), size):
            pulled += 1
            yield body[start:start + size]

    async def post():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.main.app),
                                     base_url="http://testserver") as http:
            return await http.post("/api/upload", content=chunks(), headers={"content-type": content_type})

    resp = asyncio.run(post())
    assert resp.status_code == 413
    assert pulled == small_budget // size + 1
    assert sum(spooled) <= small_budget and _stored() == []


def test_an_upload_within_its_budget_is_stored(client, spooled):
    body, content_type = _form(_REPORT)
    for content in (body, iter([body])):
        resp = client.post("/api/upload", content=content, headers={"content-type": content_type})
        assert resp.status_code == 200
        assert (uploads_dir() / f"{resp.json()['job_id']}.txt").read_bytes() == _REPORT
    assert spooled == [len(_REPORT)] * 2


def test_pasted_text_over_its_budget_is_refused_without_content_length(client, monkeypatch):
    from api.routes import ingest

    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "false")
    monkeypatch.setattr(ingest, "_MAX_TEXT_CHARS", 1000)
    body = json.dumps({"text": "a" * ingest.text_body_budget()}).encode()
    resp = client.post("/api/ingest/text", content=iter([body]), headers={"content-type": "application/json"})
    assert resp.status_code == 413 and "/api/ingest/text accepts at most 69 KB" in resp.json()["detail"]
    assert _stored() == []
    client.spawn.assert_not_called()


def test_a_newline_after_the_path_does_not_slip_past_the_budget(client, small_budget, spooled):
    """`/api/upload%0A` reaches the upload route; it used to miss the budget and
    have its whole form spooled before the route's own 413."""
    body, content_type = _form(_REPORT * (2 * small_budget // len(_REPORT)))
    resp = client.post("/api/upload%0A", content=body, headers={"content-type": content_type})
    assert resp.status_code == 413
    assert resp.json()["detail"] == "Request too large. /api/upload%0A accepts at most 68 KB."
    assert spooled == [] and _stored() == []


# ── The default, on every route without a budget of its own ─────────────────

def _make_job(temp_db, job_id: str) -> str:
    with temp_db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, report_text, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (job_id, "r.txt", "reviewing", "APT29 used WellMess.", temp_db.now_iso(), temp_db.now_iso()),
        )
        conn.commit()
    return job_id


@pytest.mark.parametrize("declared", [True, False], ids=["content-length", "no-content-length"])
@pytest.mark.parametrize(("method", "path", "body"), [
    # read whole by `request.json()`
    ("PUT", "/api/relationship-policy", {"version": 1, "rules": [], "note": "x" * DEFAULT_BUDGET_BYTES}),
    # read whole by pydantic
    ("POST", "/api/jobs/job-big/relationships/bulk", {"ids": ["r" * 40] * (DEFAULT_BUDGET_BYTES // 40),
                                                      "action": "reject"}),
], ids=["policy", "bulk"])
def test_a_json_body_over_the_default_is_refused(client, temp_db, declared, method, path, body):
    _make_job(temp_db, "job-big")
    raw = json.dumps(body).encode()
    resp = client.request(method, path, content=raw if declared else iter([raw]),
                          headers={"content-type": "application/json"})
    assert ("content-length" in resp.request.headers) is declared
    assert resp.status_code == 413
    assert resp.json()["detail"] == f"Request too large. {path} accepts at most 1 MB."
    assert "note" not in client.get("/api/relationship-policy").json()


def test_the_largest_policy_the_ui_can_send_is_stored(client):
    """A rule for every pair of the types the PUT accepts (it refuses a second rule
    for a pair), as the Policy page writes an imported rule."""
    from api.routes.policy import _OBJECT_TYPES
    from models.schemas import STIX_RELATIONSHIP_TYPES

    verb = max(STIX_RELATIONSHIP_TYPES, key=len)
    rules = [{"id": f"rule-imp-{i}-1761500000000", "src": src, "verb": verb, "tgt": tgt,
              "mode": "auto", "enabled": True}
             for i, (src, tgt) in enumerate(itertools.product(sorted(_OBJECT_TYPES), repeat=2))]
    body = json.dumps({"version": 1, "global": "auto", "rules": rules}, separators=(",", ":")).encode()
    assert 150 * 1024 < len(body) < DEFAULT_BUDGET_BYTES / 4      # 177 KB: the default is 5.8 times it
    resp = client.put("/api/relationship-policy", content=iter([body]), headers={"content-type": "application/json"})
    assert resp.status_code == 200, resp.text
    assert len(client.get("/api/relationship-policy").json()["rules"]) == len(rules)


def test_a_review_group_at_its_cap_is_decided(client, temp_db):
    from api.routes.relationships import _BULK_MAX

    job_id = _make_job(temp_db, "job-group")
    with temp_db.get_conn() as conn:
        conn.execute(
            "INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value, confidence, "
            "accepted, decision_origin) VALUES (?,?,?,?,?,?,?,?)",
            ("rel-0", job_id, "APT29", "uses", "WellMess", 0.8, 1, "default"),
        )
        conn.commit()
    ids = ["rel-0"] + [str(uuid4()) for _ in range(_BULK_MAX - 1)]
    resp = client.post(f"/api/jobs/{job_id}/relationships/bulk", content=iter([json.dumps(
        {"ids": ids, "action": "reject"}).encode()]), headers={"content-type": "application/json"})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"updated": 1, "action": "reject"}


def test_a_detection_export_of_every_rule_in_the_store_has_room(client):
    """The export POSTs rule ids, which grow with the rule store: every one of the
    87,407 rules on disk, each at the longest id (49 characters), is 4.4 MB."""
    from api.routes.coverage import export_body_budget

    path = "/api/jobs/no-such-job/detections/export"
    body = json.dumps({"rule_ids": ["x" * 49] * 87_407}).encode()
    assert DEFAULT_BUDGET_BYTES < len(body) < export_body_budget()
    resp = client.post(path, content=iter([body]), headers={"content-type": "application/json"})
    assert resp.status_code == 404 and resp.json()["detail"] == "Job not found"     # read whole, then answered

    body = json.dumps({"rule_ids": ["x" * 49] * (export_body_budget() // 49)}).encode()
    resp = client.post(path, content=iter([body]), headers={"content-type": "application/json"})
    assert resp.status_code == 413 and resp.json()["detail"] == f"Request too large. {path} accepts at most 8 MB."


# ── The budgets ──────────────────────────────────────────────────────────────

def _middleware_kwargs() -> dict:
    import api.main

    (middleware,) = [m for m in api.main.app.user_middleware if m.cls is BodyLimitMiddleware]
    return middleware.kwargs


def _budgets() -> dict:
    return _middleware_kwargs()["budgets"]


def test_the_baseline_has_room_only_while_the_mode_is_on(monkeypatch):
    from api.routes import baselines, ingest, upload
    from pipeline.baseline_stix import MAX_BASELINE_BYTES

    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "true")
    on = (upload.body_budget(), ingest.text_body_budget(), ingest.url_body_budget(), baselines.body_budget())
    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "false")
    assert upload.body_budget() == on[0] - MAX_BASELINE_BYTES == upload._MAX_BYTES + ENVELOPE_BYTES
    assert ingest.text_body_budget() == on[1] - 2 * MAX_BASELINE_BYTES == 6 * ingest._MAX_TEXT_CHARS + ENVELOPE_BYTES
    assert ingest.url_body_budget() == on[2] - 2 * MAX_BASELINE_BYTES == ENVELOPE_BYTES
    assert baselines.body_budget() == on[3] == MAX_BASELINE_BYTES + ENVELOPE_BYTES    # the route answers 400


def test_every_route_that_takes_a_file_or_a_baseline_has_a_budget():
    """A route taking a form gets it spooled to disk before its handler runs: a new
    one needs a budget too.  Read from the OpenAPI schema, which lists every route."""
    import api.main

    takes_a_file = {
        (method.upper(), path)
        for path, operations in api.main.app.openapi()["paths"].items()
        for method, operation in operations.items()
        if "multipart/form-data" in operation.get("requestBody", {}).get("content", {})
    }
    assert takes_a_file == {("POST", "/api/upload"), ("POST", "/api/baselines/inspect")}
    assert set(_budgets()) == takes_a_file | {("POST", "/api/ingest/text"), ("POST", "/api/ingest/url"),
                                              ("POST", "/api/jobs/{job_id}/detections/export")}
    assert set(_budgets()) <= {(method.upper(), path) for path, operations in api.main.app.openapi()["paths"].items()
                               for method in operations}            # each written as its route declares it
    assert _middleware_kwargs()["default"]() == DEFAULT_BUDGET_BYTES


def test_nginx_lets_through_whatever_the_api_accepts(monkeypatch):
    """Behind the `proxy` profile, nginx must not cut a request the API takes: its
    413 is an HTML page the UI cannot read."""
    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "true")
    conf = (_ROOT / "docker" / "nginx" / "default.conf").read_text(encoding="utf-8")
    (limit,) = [line.split()[1] for line in conf.splitlines() if line.strip().startswith("client_max_body_size")]
    assert limit.endswith("m;")
    budgets = [*_budgets().values(), _middleware_kwargs()["default"]]
    assert max(budget() for budget in budgets) <= int(limit.removesuffix("m;")) * 1024 * 1024
