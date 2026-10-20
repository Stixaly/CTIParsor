"""The ATT&CK index of the release this API runs (ADR-0087).

The interface reads technique names and tactics from here: the selected
track's `mitre_index.json`, the file Stages 3c and 4 read, served as it is.
It used to read a static copy, `frontend/public/mitre_index.json`, that
stayed on the default track (and lacked two mobile tactics) whatever
ATTACK_RELEASE said.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, Response

from pipeline import attack_data

router = APIRouter(prefix="/api/attack", tags=["attack"])

# The default track's file; attack_data.resolve() maps it to the selected one.
_INDEX = attack_data.DATA_DIR / "mitre_index.json"


def _matches(if_none_match: str | None, etag: str) -> bool:
    """Whether an If-None-Match header names `etag`, or is `*`."""
    tags = {t.strip().removeprefix("W/") for t in (if_none_match or "").split(",")}
    return etag in tags or "*" in tags


@router.get(
    "/index",
    responses={
        200: {
            "description": "The selected track's mitre_index.json, unmodified",
            "headers": {
                "X-Attack-Release": {"description": "Its release: 19.2, 20.0", "schema": {"type": "string"}},
                "ETag": {"description": "Its sha256, quoted", "schema": {"type": "string"}},
            },
        },
        304: {"description": "The index the browser holds (If-None-Match) is the one served"},
        404: {"description": "The selected track has no mitre_index.json"},
    },
)
def attack_index(request: Request):
    """The selected track's `mitre_index.json`, its release in `X-Attack-Release`.

    The ETag is the file's sha256 and `Cache-Control` is `no-cache`: a browser
    asks again on each load and gets a 304 while the file is unchanged.  Left
    to heuristic caching (Last-Modified), it would keep the index of the last
    track after a restart on another ATTACK_RELEASE.  A track without the file
    answers 404, never with the default track's.
    """
    rel = attack_data.current()
    path = attack_data.resolve(_INDEX)
    digest = attack_data.sha256(path)
    if digest is None:
        raise HTTPException(404, f"ATT&CK {rel.version} has no mitre_index.json")
    headers = {"X-Attack-Release": rel.version, "ETag": f'"{digest}"', "Cache-Control": "no-cache"}
    if _matches(request.headers.get("if-none-match"), headers["ETag"]):
        return Response(status_code=304, headers=headers)
    return FileResponse(path, media_type="application/json", headers=headers)
