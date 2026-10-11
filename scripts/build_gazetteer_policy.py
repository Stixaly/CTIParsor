"""Build pipeline/data/gazetteer_policy.json from the reviewed document.

    python scripts/build_gazetteer_policy.py

`docs/gazetteer-ordinary-words.md` is the source: each inventory row gives a
gazetteer form and its decision (RETAIN, CASE, CONTEXT).  The JSON keeps the
form -> decision map and the document's SHA-256 prefix as the policy version
(over LF line endings, as git stores it, so a Windows checkout agrees), so a
run records which review it applied.  tests/test_gazetteer_policy.py
fails when the two disagree.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOC = REPO / "docs" / "gazetteer-ordinary-words.md"
OUT = REPO / "pipeline" / "data" / "gazetteer_policy.json"
ROW = re.compile(r"^\| `([^`]+)` \| [^|]* \| [^|]* \| \*\*(RETAIN|CASE|CONTEXT)\*\* \|", re.M)


def parse(text: str) -> dict[str, str]:
    forms: dict[str, str] = {}
    for form, decision in ROW.findall(text):
        if form in forms and forms[form] != decision:
            raise ValueError(f"{form!r} has two decisions")
        forms[form] = decision
    return dict(sorted(forms.items()))


def build() -> dict:
    raw = DOC.read_bytes().replace(b"\r\n", b"\n")
    return {"version": hashlib.sha256(raw).hexdigest()[:12],
            "source": "docs/gazetteer-ordinary-words.md",
            "forms": parse(raw.decode("utf-8"))}


def main() -> None:
    data = build()
    OUT.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    counts: dict[str, int] = {}
    for decision in data["forms"].values():
        counts[decision] = counts.get(decision, 0) + 1
    print(f"written {OUT}: {len(data['forms'])} forms {counts}, version {data['version']}")


if __name__ == "__main__":
    main()
