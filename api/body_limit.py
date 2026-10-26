"""
The most a request body may weigh, enforced while it arrives.

FastAPI reads a multipart form, files included, before the handler runs: a size
check in the handler comes after the whole body has been spooled to disk, and a
body sent without `Content-Length` (chunked) is bounded by nothing.  This
middleware sits in front.  On a route with a budget, a `Content-Length` over it
is answered 413 before a byte is read; otherwise the bytes are counted as they
arrive, and the request is answered 413 as soon as they pass the budget — the
application never receives the rest.

Pure ASGI rather than `BaseHTTPMiddleware`: only the request body is wrapped, and
a streamed response (the SSE progress stream) passes as it is.  The budgets are
declared next to the limits they add up (api/routes/upload.py, ingest.py,
baselines.py, coverage.py) and listed in api/main.py.  Every other request is
held to `DEFAULT_BUDGET_BYTES`, since `request.json()` and pydantic read a JSON
body whole; a path the table misses gets that default, not nothing.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from urllib.parse import quote

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.routing import compile_path
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from api.logging_config import get_logger

logger = get_logger(__name__)

# What a form or a JSON object adds around the file or the text it carries: the
# multipart boundaries and part headers, the small fields (markings, a report id,
# a URL).  Every budget counts it once.
ENVELOPE_BYTES = 64 * 1024

# A request whose route has no budget of its own: a decision, a setting, the
# relationship policy.  The largest the UI can send is the policy with a rule for
# every pair of the 37 STIX types the PUT accepts, 1,369 rules in 177 KB; a review
# group's 500 relationship ids weigh 19 KB, a rule lookup's 500 ids 28 KB.
DEFAULT_BUDGET_BYTES = 1024 * 1024

Budget = Callable[[], int]


def _route_path(scope: Scope) -> str:
    """The path the router matches: without the `root_path` a server started with
    `--root-path` puts in front of it, or a prefix would slip past the budgets."""
    path, root = scope["path"], scope.get("root_path", "")
    return path[len(root):] if root and path.startswith(root + "/") else path


def _size(n: int) -> str:
    """A budget for a message, rounded down: anything under it is accepted."""
    return f"{n // (1024 * 1024)} MB" if n >= 1024 * 1024 else f"{n // 1024} KB"


async def _answer(status: int, detail: str, scope: Scope, receive: Receive, send: Send) -> None:
    # The same shape as an HTTPException's answer, so the UI shows `detail` as usual
    await JSONResponse({"detail": detail}, status_code=status)(scope, receive, send)


class BodyLimitMiddleware:
    """413 for a request body over its route's budget, or over `default` on any other.

    `budgets` maps `(method, path)` to a function giving the budget in bytes.  It
    is called on each request: a budget may follow a setting read per request
    (`STIX_ENRICHMENT_ENABLED`).  A path is written as its route declares it,
    `{job_id}` included, and matched by the router's own pattern: a regex that
    ends in `$` also takes `/api/upload` followed by a newline (`%0A`), and so
    does the route.  Without a `default`, a request no budget matches passes
    untouched."""

    def __init__(self, app: ASGIApp, budgets: Mapping[tuple[str, str], Budget],
                 default: Budget | None = None) -> None:
        self.app = app
        self.routes = [(method, compile_path(path)[0], budget) for (method, path), budget in budgets.items()]
        self.default = default

    def _budget_of(self, method: str, path: str) -> Budget | None:
        for route_method, pattern, budget in self.routes:
            if route_method == method and pattern.match(path):
                return budget
        return self.default

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = _route_path(scope) if scope["type"] == "http" else ""
        budget_of = self._budget_of(scope["method"], path) if path else None
        if budget_of is None:
            await self.app(scope, receive, send)
            return
        budget = budget_of()
        # Quoted as uvicorn's access log quotes it: a `%0A` in the path is not a new log line
        path = quote(path)
        too_large = f"Request too large. {path} accepts at most {_size(budget)}."

        declared = Headers(scope=scope).get("content-length")
        if declared is not None:
            digits = declared.strip()
            if not (digits.isascii() and digits.isdigit()):
                await _answer(400, "Invalid Content-Length header.", scope, receive, send)
                return
            # Leading zeros dropped and the length compared first: `int()` refuses
            # a string of more than 4,300 digits.
            digits = digits.lstrip("0") or "0"
            if len(digits) > len(str(budget)) or int(digits) > budget:
                logger.info("[body-limit] %s %s refused: Content-Length over a %d-byte budget",
                            scope["method"], path, budget)
                await _answer(413, too_large, scope, receive, send)
                return

        received = 0
        cut = False           # the body passed the budget: the application gets no more of it
        answered = False      # ...and the client got the 413 from here
        started = False       # the application had begun its response

        async def counted_receive() -> Message:
            nonlocal received, cut, answered
            if cut:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > budget:
                    cut = True
                    logger.info("[body-limit] %s %s cut off: past its %d-byte budget",
                                scope["method"], path, budget)
                    if not started:
                        answered = True
                        await _answer(413, too_large, scope, receive, send)
                    # To the application the client has gone: Starlette raises
                    # ClientDisconnect, and FastAPI's answer to it is dropped below.
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if answered:
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counted_receive, guarded_send)
        except Exception:
            if not answered:
                raise
            # The application failed on a body it never got whole; the client has its 413
            logger.debug("[body-limit] %s %s: error after the 413", scope["method"], path, exc_info=True)
