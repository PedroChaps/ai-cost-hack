"""Cheap-model verification of locally detected candidates.

Each call confirms or rejects a single localized candidate instead of
generating a whole review, which is a much narrower task and stays
reliable on a small, cheap model. Severity, next_action, and the test
description are all decided deterministically by the detector (see
detectors.py) from the actual matched code - not by the model. The model
is given the detector's test_hint as context (it explains *why* the
pattern is suspicious, which the snippet alone often doesn't convey) but
its own output is only a confirm/reject decision plus an explanation. All
calls run through Merge Gateway per the challenge rule.
"""

from __future__ import annotations

import json
import os
import time
from typing import TypedDict

from openai import OpenAI

VERIFY_MODEL = "amazon/nova-lite"
_MAX_ATTEMPTS = 3
_RETRY_DELAY_SECONDS = 0.5

_SYSTEM_PROMPT = (
    "You verify one suspected software defect found by static pattern matching for a "
    "release-gate reviewer. You are given the suspected category, the file, a short code "
    "or context snippet, and a hint describing why this pattern is normally a problem. "
    "Decide whether this is a genuine, exploitable or harmful defect rather than a false "
    "positive (for example: a placeholder value, dead code, or a check that is actually "
    "present nearby but outside the snippet). Respond with exactly one compact JSON "
    'object and nothing else, no trailing characters: {"confirmed": bool, "explanation": '
    '"one sentence grounded in the snippet"}. No prose, no markdown fences.'
)


class Verdict(TypedDict):
    confirmed: bool
    explanation: str


def make_client() -> OpenAI:
    return OpenAI(
        api_key=os.environ["MERGE_GATEWAY_API_KEY"],
        base_url="https://api-gateway.merge.dev/v1/openai",
    )


def _parse(content: str) -> dict[str, object] | None:
    cleaned = content.strip()
    if cleaned.startswith("```"):
        first_newline = cleaned.find("\n")
        if first_newline == -1:
            return None
        cleaned = cleaned[first_newline + 1 :]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
    cleaned = cleaned.strip()
    start = cleaned.find("{")
    if start == -1:
        return None
    # Some small models tack on stray trailing characters after a valid JSON
    # object (e.g. an extra "]"). raw_decode parses just the object and
    # ignores whatever comes after it, instead of rejecting the whole reply.
    try:
        data, _ = json.JSONDecoder().raw_decode(cleaned[start:])
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def verify(
    client: OpenAI, category: str, file: str, snippet: str, case_brief: str, test_hint: str
) -> Verdict | None:
    user_content = (
        f"case brief: {case_brief}\nsuspected category: {category}\nfile: {file}\n"
        f"why this is normally a problem: {test_hint}\nsnippet:\n{snippet}"
    )
    data = None
    for attempt in range(_MAX_ATTEMPTS):
        try:
            response = client.chat.completions.create(
                model=VERIFY_MODEL,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                max_completion_tokens=120,
                temperature=0,
                extra_body={"project_id": os.environ["MERGE_GATEWAY_PROJECT_ID"]},
            )
            content = response.choices[0].message.content or ""
        except Exception:
            content = None
        data = _parse(content) if content else None
        if data is not None:
            break
        if attempt < _MAX_ATTEMPTS - 1:
            time.sleep(_RETRY_DELAY_SECONDS * (attempt + 1))
    if data is None:
        return None
    return {
        "confirmed": bool(data.get("confirmed")),
        "explanation": str(data.get("explanation") or "Confirmed by verification model.").strip(),
    }
