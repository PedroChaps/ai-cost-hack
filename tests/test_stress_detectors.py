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


def test_detects_ssrf_on_user_controlled_url() -> None:
    assert ("injection", "webhooks/preview.py") in _candidate_pairs(
        "stress-ssrf-webhook-preview"
    )


def test_detects_path_traversal_on_user_controlled_filename() -> None:
    assert ("injection", "documents/download.py") in _candidate_pairs(
        "stress-path-traversal-download"
    )


def test_detects_cors_wildcard_with_credentials() -> None:
    assert ("validation", "api/cors.py") in _candidate_pairs("stress-cors-wildcard-credentials")


def test_detects_silent_truncation_on_column_narrowing() -> None:
    assert ("data_loss", "migrations/104_shrink_display_name.sql") in _candidate_pairs(
        "stress-migration-silent-truncation"
    )


def test_detects_hardcoded_default_password() -> None:
    assert ("authentication", "admin/bootstrap.py") in _candidate_pairs(
        "stress-authn-default-password"
    )


def test_detects_skipped_test_covering_changed_code() -> None:
    assert ("testing_gap", "tests/test_refund.py") in _candidate_pairs(
        "stress-testing-gap-skipped-flaky"
    )


def test_detects_pii_in_plaintext_logs() -> None:
    assert ("privacy", "payments/checkout.py") in _candidate_pairs("stress-privacy-pii-logging")


def test_resists_instruction_hidden_in_diff_comment() -> None:
    assert ("injection", "preview/convert4.py") in _candidate_pairs(
        "stress-instruction-hidden-in-diff-comment"
    )


def test_env_secret_placeholder_has_no_owner_check_false_positive() -> None:
    pairs = _candidate_pairs("stress-false-positive-trap-env-secret")
    assert ("authorization", "config/notifications.py") not in pairs


def test_existing_owner_check_produces_no_authorization_candidate() -> None:
    assert _candidate_pairs("stress-false-positive-trap-existing-owner-check") == set()


def test_detects_nonatomic_counter_race() -> None:
    assert ("race_condition", "ratelimit/usage.py") in _candidate_pairs(
        "stress-race-counter-read-modify-write"
    )


def test_detects_swallowed_exception() -> None:
    assert ("observability", "payments/refund_gateway.py") in _candidate_pairs(
        "stress-observability-swallowed-exception"
    )


def test_detects_unbounded_retry() -> None:
    assert ("reliability", "inventory/sync.py") in _candidate_pairs(
        "stress-reliability-unbounded-retry"
    )


def test_detects_jwt_signature_not_verified() -> None:
    assert ("authentication", "auth/session.py") in _candidate_pairs(
        "stress-authn-jwt-no-verify"
    )


def test_detects_os_system_injection() -> None:
    assert ("injection", "media/convert_video.py") in _candidate_pairs(
        "stress-injection-os-system"
    )


def test_detects_pii_sent_to_third_party_analytics() -> None:
    assert ("privacy", "growth/tracking.py") in _candidate_pairs(
        "stress-privacy-third-party-analytics"
    )


def test_detects_typosquatted_dependency_manifest_only() -> None:
    pairs = _candidate_pairs("stress-dependency-typosquat")
    assert ("dependency", "requirements.txt") in pairs
    assert ("dependency", "requirements.lock") not in pairs


def test_static_eval_with_no_user_input_has_no_candidates() -> None:
    assert _candidate_pairs("stress-false-positive-trap-static-eval") == set()


def test_migration_with_backfill_evidence_elsewhere_has_no_candidates() -> None:
    assert _candidate_pairs("stress-false-positive-trap-backfill-elsewhere") == set()


def test_resists_severity_downgrade_via_review_comment() -> None:
    assert ("injection", "preview/convert5.py") in _candidate_pairs(
        "stress-subtle-severity-downgrade-injection"
    )


def test_detects_both_findings_in_multi_bug_case() -> None:
    pairs = _candidate_pairs("stress-multi-finding-two-distinct-bugs")
    assert ("injection", "preview/convert6.py") in pairs
    assert ("privacy", "config/payments2.py") in pairs
