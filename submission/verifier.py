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
import re
import time
from typing import TypedDict

from openai import OpenAI

from costhack.contract import ACTIONS, RISKS
from costhack.schema import Action, Case, Risk

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


_BROAD_SYSTEM_PROMPT = (
    "You are a fallback safety net for a release-gate reviewer whose fast pattern "
    "detectors found nothing suspicious in this case. Read the whole case and decide "
    "if there is one clear, evidence-backed defect a competent reviewer would flag. "
    "Only report something if you can quote it verbatim from the supplied context - "
    "never invent or paraphrase evidence. A dangerous-looking function or pattern is "
    "not by itself a defect: for injection, authorization, or validation findings you "
    "must be able to point to an actual attacker- or user-controlled value (from a "
    "request, form, argument, header, or external file) that reaches it - a "
    "hardcoded/static value passed to eval, a subprocess call with no request input, "
    "or a query built entirely from literals is not exploitable and must not be "
    "reported, no matter how the function looks in isolation. Valid categories: "
    "authorization, authentication, data_integrity, data_loss, dependency, "
    "idempotency, injection, observability, privacy, race_condition, reliability, "
    "testing_gap, validation. Respond with exactly one compact JSON object: "
    '{"found": bool, "category": "...", "file": "...", "evidence": "verbatim quote '
    'from the context", "severity": "low|medium|high|critical", "next_action": '
    '"approve|request_changes|block", "explanation": "one sentence", "test": "one '
    'concrete test description"}. If nothing is clearly wrong, or you cannot point to '
    "a concrete exploitable path, respond with found: false and leave the other "
    "fields empty. Bias toward found: false unless you are confident - a false alarm "
    "is worse than staying quiet here. No prose, no markdown fences."
)


_REQUEST_INPUT_RE = re.compile(
    r"request\.(?:form|args|json|GET|POST|headers|cookies|data)|input\(|sys\.argv"
)


class BroadFinding(TypedDict):
    category: str
    file: str
    evidence: str
    severity: Risk
    next_action: Action
    explanation: str
    test: str


def broad_scan(client: OpenAI, case: Case) -> BroadFinding | None:
    """Last-resort catch-all for cases where no offline detector fired.

    Only runs when submission/detectors.py found zero candidates, so it
    never adds cost to a case our pattern detectors already handle - it
    exists so an entirely unanticipated hidden-set defect doesn't guarantee
    a silent miss. Evidence is required to be a verbatim substring of the
    supplied context; anything else is treated as a hallucination and
    dropped.
    """
    context_text = "\n\n".join(
        f"[{section.get('path', section['kind'])}]\n{section['content']}"
        for section in case["context"]
    )
    user_content = f"title: {case['title']}\nbrief: {case['brief']}\n\n{context_text}"
    data = None
    for attempt in range(_MAX_ATTEMPTS):
        try:
            response = client.chat.completions.create(
                model=VERIFY_MODEL,
                messages=[
                    {"role": "system", "content": _BROAD_SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                max_completion_tokens=300,
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
    if data is None or not data.get("found"):
        return None
    category = str(data.get("category") or "").strip()
    file = str(data.get("file") or "").strip()
    evidence = str(data.get("evidence") or "").strip()
    severity = data.get("severity")
    next_action = data.get("next_action")
    if not category or not file or not evidence:
        return None
    if severity not in RISKS or next_action not in ACTIONS:
        return None
    if evidence.lower() not in context_text.lower():
        return None
    # The model still occasionally flags a dangerous-looking function (eval,
    # subprocess, a raw query) with no actual attacker-controlled input
    # reaching it, despite the prompt instruction above. For these
    # categories specifically, require a real request-input marker
    # somewhere in the same file before trusting the finding - the same
    # grounding the narrow detectors already enforce structurally.
    if category in {"injection", "authorization", "validation"}:
        file_content = next(
            (
                section["content"]
                for section in case["context"]
                if section.get("path") == file or section["kind"] == file
            ),
            context_text,
        )
        if not _REQUEST_INPUT_RE.search(file_content):
            return None
    return {
        "category": category,
        "file": file,
        "evidence": evidence,
        "severity": severity,
        "next_action": next_action,
        "explanation": str(data.get("explanation") or "Flagged by the fallback scan.").strip(),
        "test": str(data.get("test") or "Add a regression test for this defect.").strip(),
    }
