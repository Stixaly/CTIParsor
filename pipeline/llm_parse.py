"""Helpers shared by the verification stages: prompt sizing and response parsing."""
from __future__ import annotations

import json
import math


def fit_text(template: str, text: str, max_chars: int | None, **fields: str) -> str:
    """Format `template` with `text`, cutting the TEXT, never the rest, so the
    prompt fits in `max_chars` (None: no limit).

    Every verification prompt puts the source text first and the claims and
    answer format after it.  Truncating the finished prompt, as `_call_llm`
    does, cuts the claims off: the model gets text and no question.
    """
    prompt = template.format(text=text, **fields)
    if max_chars is None or len(prompt) <= max_chars:
        return prompt
    keep = max(0, len(text) - (len(prompt) - max_chars))
    return template.format(text=text[:keep], **fields)


def parse_numbered_claims(raw: str, count: int) -> dict[int, dict] | None:
    """Parse an LLM verification response into {claim_num -> verification}.

    The expected format is a JSON array:
      [{"n": 1, "verified": true, "quote": "..."}, ...]

    Returns None if no valid JSON array can be found in the response.
    """
    decoder = json.JSONDecoder()

    # Scan for the first valid JSON array in the response
    for i, ch in enumerate(raw):
        if ch == "[":
            try:
                arr, _ = decoder.raw_decode(raw, i)
                if not isinstance(arr, list):
                    continue

                result: dict[int, dict] = {}
                for item in arr:
                    if not isinstance(item, dict):
                        continue
                    n = item.get("n")
                    # Accept both int and float (e.g. 1.0) — LLMs occasionally
                    # serialise integers as JSON floats.  Exclude bool (a subclass
                    # of int) and non-finite floats: json's default decoder accepts
                    # NaN/Infinity, and int(nan) would raise and crash the chunk.
                    if (isinstance(n, (int, float))
                            and not isinstance(n, bool)
                            and math.isfinite(n)
                            and n == int(n)
                            and 1 <= int(n) <= count):
                        result[int(n)] = item

                # Return even if partial (some claims missing — handled by caller)
                return result if result else None

            except json.JSONDecodeError:
                continue

    return None
