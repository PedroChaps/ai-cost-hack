"""Run submission/strategy.py against our own harder, self-authored cases.

This is NOT part of the official challenge benchmark - data/public_cases.json
and the costhack CLI are untouched. data/stress_cases.json is a separate set
we wrote ourselves, modeled on the failure modes CHALLENGE.md says the hidden
set actually tests (race conditions, reliability gaps, sneaky auth bypasses,
mocked-out tests, prompt injection embedded in case content, plus true
negatives to catch false positives). It exists to stress-test generalization
beyond the ten known public patterns, not to certify hidden-set performance.

Usage: uv run python scripts/run_stress_benchmark.py
"""

from __future__ import annotations

import json
from pathlib import Path

from costhack.contract import validate_review
from costhack.scoring import score_review
from submission.strategy import review

ROOT = Path(__file__).resolve().parents[1]
STRESS_DATA = ROOT / "data" / "stress_cases.json"


def main() -> int:
    cases = json.loads(STRESS_DATA.read_text())
    rows = []
    for case in cases:
        try:
            result = score_review(validate_review(review(case)), case["rubric"])
        except Exception as exc:
            result = {"score": 0.0, "passed": False, "missing": [], "error": str(exc)}
        rows.append((case["id"], result))

    print("STRESS BENCHMARK (self-authored, not the official challenge set)")
    print("=" * 72)
    for case_id, result in rows:
        status = "PASS" if result["passed"] else "FAIL"
        detail = f" missing={','.join(result.get('missing', []))}" if result.get("missing") else ""
        if result.get("false_positives"):
            detail += f" false_positives={result['false_positives']}"
        if result.get("error"):
            detail += f" error={result['error']}"
        print(f"{status:4}  {result['score']:5.1f}  {case_id}{detail}")
    mean = sum(row[1]["score"] for row in rows) / max(1, len(rows))
    passed = sum(row[1]["passed"] for row in rows)
    print("-" * 72)
    print(f"{passed}/{len(rows)} passed  mean_quality={mean:.1f}")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
