from costhack.contract import ContractError, validate_review
from costhack.schema import Review, Rubric
from costhack.scoring import score_review


def test_invalid_review_is_rejected() -> None:
    try:
        validate_review({"risk": "banana"})
    except ContractError:
        return
    raise AssertionError("invalid review was accepted")


def test_exact_public_finding_passes() -> None:
    rubric: Rubric = {
        "risk": "high",
        "next_action": "block",
        "pass_score": 80,
        "must_find": ["auth"],
        "required_test_terms": ["cross-tenant"],
        "required_findings": [
            {
                "id": "auth",
                "category": "authorization",
                "file": "api.py",
                "evidence_anchor": "owner check",
            }
        ],
    }
    review: Review = {
        "risk": "high",
        "findings": [
            {
                "category": "authorization",
                "severity": "high",
                "file": "api.py",
                "evidence": "missing owner check",
                "explanation": "cross-tenant access",
            }
        ],
        "tests": ["cross-tenant access is rejected"],
        "next_action": "block",
    }
    assert score_review(review, rubric)["passed"]
