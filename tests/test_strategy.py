from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from costhack.contract import validate_review
from costhack.schema import Case, Review
from costhack.scoring import score_review
from submission.strategy import review

PUBLIC_CASES = cast(
    "list[Case]",
    json.loads((Path(__file__).resolve().parents[1] / "data" / "public_cases.json").read_text()),
)


class ConfirmingCompletions:
    def create(self, **kwargs: object) -> object:
        messages = cast("list[dict[str, str]]", kwargs["messages"])
        user_content = messages[-1]["content"]
        assert kwargs["model"] == "amazon/nova-lite"
        assert kwargs["extra_body"] == {"project_id": "event-project"}
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=json.dumps(
                            {
                                "confirmed": True,
                                "explanation": "Confirmed against the supplied snippet.",
                                "test": user_content.splitlines()[3].removeprefix(
                                    "verification test hint: "
                                ),
                            }
                        )
                    )
                )
            ]
        )


class ConfirmingOpenAI:
    completions = ConfirmingCompletions()

    def __init__(self, **kwargs: object) -> None:
        assert kwargs["api_key"] == "mg_test"
        assert kwargs["base_url"] == "https://api-gateway.merge.dev/v1/openai"
        self.chat = SimpleNamespace(completions=self.completions)


def test_review_has_no_findings_without_credentials() -> None:
    expected: Review = {"risk": "low", "findings": [], "tests": [], "next_action": "approve"}
    with patch.dict("os.environ", {}, clear=True):
        for case in PUBLIC_CASES:
            assert review(case) == expected


def test_confirmed_candidates_reach_full_recall_on_public_cases() -> None:
    with (
        patch.dict(
            "os.environ",
            {
                "MERGE_GATEWAY_API_KEY": "mg_test",
                "MERGE_GATEWAY_PROJECT_ID": "event-project",
            },
        ),
        patch("submission.verifier.OpenAI", ConfirmingOpenAI),
    ):
        for case in PUBLIC_CASES:
            result = validate_review(review(case))
            scored = score_review(result, case["rubric"])
            assert not scored["missing"], f"{case['id']} missed a required finding"
            assert scored["false_positives"] == 0, f"{case['id']} produced a false positive"
