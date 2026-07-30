from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from costhack.schema import Case
from submission.detectors import find_candidates

PUBLIC_CASES = json.loads(
    (Path(__file__).resolve().parents[1] / "data" / "public_cases.json").read_text()
)


def _candidate_pairs(case_id: str) -> set[tuple[str, str]]:
    case = next(c for c in PUBLIC_CASES if c["id"] == case_id)
    return {(c.category, c.file) for c in find_candidates(case)}


def test_detects_missing_owner_check() -> None:
    assert ("authorization", "api/delete_project.py") in _candidate_pairs("public-auth-delete")


def test_detects_unsafe_migration() -> None:
    assert ("data_integrity", "migrations/042_account_region.sql") in _candidate_pairs(
        "public-migration-null"
    )


def test_detects_shell_injection() -> None:
    assert ("injection", "preview/convert.py") in _candidate_pairs("public-shell-injection")


def test_detects_hardcoded_secret() -> None:
    assert ("privacy", "config/payments.py") in _candidate_pairs("public-hardcoded-secret")


def test_detects_disabled_tls() -> None:
    assert ("validation", "integrations/client.py") in _candidate_pairs("public-disabled-tls")


def test_detects_idempotency_gap() -> None:
    assert ("idempotency", "payments/webhook.py") in _candidate_pairs(
        "public-payment-idempotency"
    )


def test_detects_tenant_missing_from_cache_key() -> None:
    assert ("privacy", "dashboard/cache.py") in _candidate_pairs("public-tenant-cache-key")


def test_detects_ci_filter_gap() -> None:
    assert ("testing_gap", ".github/workflows/ci.yml") in _candidate_pairs(
        "public-ci-filter-gap"
    )


def test_detects_vulnerable_transitive_dependency() -> None:
    assert ("dependency", "requirements.lock") in _candidate_pairs("public-transitive-archive")


def test_detects_naive_timezone_migration() -> None:
    assert ("data_loss", "migrations/077_appointments_utc.sql") in _candidate_pairs(
        "public-timezone-migration"
    )


def test_clean_case_has_no_candidates() -> None:
    clean_case = cast(
        Case,
        {
            "id": "clean",
            "title": "Clean change",
            "brief": "Rename a helper function.",
            "context": [
                {
                    "kind": "diff",
                    "path": "app/helpers.py",
                    "content": "def format_name(user):\n    return user.name.strip()\n",
                }
            ],
            "rubric": {
                "risk": "low",
                "next_action": "approve",
                "pass_score": 80,
                "must_find": [],
                "required_test_terms": [],
                "required_findings": [],
            },
        },
    )
    assert find_candidates(clean_case) == []
