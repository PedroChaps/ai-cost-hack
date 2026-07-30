"""Offline pattern detection, escalated to a cheap model for verification.

Zero-cost regex/structural detectors (detectors.py) scan case context for
suspicious patterns and emit candidates, each already carrying its
severity, next_action, and test description, all derived from the actual
matched code. Each candidate's matched line plus neighboring context is
then passed to a single cheap Merge Gateway model call (verifier.py) that
only rules out false positives and writes the explanation. This keeps
model usage scoped to short, grounded snippets instead of the whole case,
and keeps unconfirmed pattern matches out of the review.
"""

from __future__ import annotations

import os

from costhack.contract import ACTIONS, RISKS
from costhack.schema import Action, Case, Finding, Review, Risk

from . import detectors
from .verifier import make_client, verify

MAX_FINDINGS = 8


def review(case: Case) -> Review:
    candidates = detectors.find_candidates(case)
    findings: list[Finding] = []
    tests: list[str] = []
    risk: Risk = "low"
    action: Action = "approve"

    if candidates and os.environ.get("MERGE_GATEWAY_API_KEY"):
        client = make_client()
        for candidate in candidates:
            if len(findings) >= MAX_FINDINGS:
                break
            verdict = verify(
                client,
                candidate.category,
                candidate.file,
                candidate.snippet,
                case["brief"],
                candidate.test_hint,
            )
            if verdict is None or not verdict["confirmed"]:
                continue
            findings.append(
                {
                    "category": candidate.category,
                    "severity": candidate.default_severity,
                    "file": candidate.file,
                    "evidence": candidate.evidence,
                    "explanation": verdict["explanation"],
                }
            )
            tests.append(candidate.test_hint)
            if RISKS.index(candidate.default_severity) > RISKS.index(risk):
                risk = candidate.default_severity
            if ACTIONS.index(candidate.default_action) > ACTIONS.index(action):
                action = candidate.default_action

    return {
        "risk": risk,
        "findings": findings,
        "tests": tests,
        "next_action": action,
    }
