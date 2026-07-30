from __future__ import annotations

import json
from pathlib import Path

from submission.detectors import find_candidates

STRESS_CASES = json.loads(
    (Path(__file__).resolve().parents[1] / "data" / "stress_cases.json").read_text()
)


def _candidate_pairs(case_id: str) -> set[tuple[str, str]]:
    case = next(c for c in STRESS_CASES if c["id"] == case_id)
    return {(c.category, c.file) for c in find_candidates(case)}


def test_detects_check_then_act_race() -> None:
    assert ("race_condition", "inventory/reserve.py") in _candidate_pairs(
        "stress-race-inventory"
    )


def test_detects_missing_timeout() -> None:
    assert ("reliability", "payments/gateway.py") in _candidate_pairs(
        "stress-reliability-no-timeout"
    )


def test_detects_missing_authentication() -> None:
    assert ("authentication", "admin/routes.py") in _candidate_pairs(
        "stress-authn-missing-decorator"
    )


def test_detects_sql_injection() -> None:
    assert ("injection", "search/query.py") in _candidate_pairs("stress-sql-injection")


def test_resists_embedded_override_instructions() -> None:
    assert ("injection", "preview/convert2.py") in _candidate_pairs(
        "stress-prompt-injection-resistance"
    )


def test_clean_refactor_has_no_candidates() -> None:
    assert _candidate_pairs("stress-clean-refactor") == set()


def test_detects_dropped_column_still_referenced() -> None:
    assert ("data_loss", "migrations/091_drop_legacy_email.sql") in _candidate_pairs(
        "stress-migration-drop-column"
    )


def test_detects_test_mocking_function_under_test() -> None:
    assert ("testing_gap", "tests/test_gateway.py") in _candidate_pairs(
        "stress-testing-gap-mocked-target"
    )


def test_detects_dependency_advisory_alt_phrasing() -> None:
    assert ("dependency", "requirements.lock") in _candidate_pairs(
        "stress-dependency-alt-phrasing"
    )


def test_detects_client_controlled_privilege_header() -> None:
    assert ("authorization", "accounts/detail.py") in _candidate_pairs(
        "stress-authz-trusted-header"
    )


def test_detects_aws_credential_pair() -> None:
    assert ("privacy", "export/s3_config.py") in _candidate_pairs("stress-secret-aws-pair")


def test_detects_injection_buried_in_noisy_context() -> None:
    assert ("injection", "preview/convert3.py") in _candidate_pairs(
        "stress-long-noisy-context"
    )
