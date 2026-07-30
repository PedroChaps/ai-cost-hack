"""Zero-cost candidate detection.

Scans case context for suspicious patterns and emits Candidate objects. A
candidate is not a finding yet: the cheap-model verifier in verifier.py
confirms or rejects each one (and writes the explanation and test) before
it is allowed into the final review. This keeps the expensive part (model
judgement) scoped to a short, grounded snippet instead of the whole case,
and keeps false positives out of the review by requiring model
confirmation.

Severity and next_action are set here, not by the model: each detector
targets a structurally distinct bug class (exploitable bypass vs. a fixable
config defect vs. silent data corruption), and that classification is a
property of the pattern, not something a small verification model can
reliably re-derive from an isolated snippet.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from costhack.schema import Action, Case, ContextSection, Risk

MAX_CANDIDATES = 8
_CONTEXT_LINES = 2


@dataclass(frozen=True)
class Candidate:
    category: str
    file: str
    evidence: str
    snippet: str
    default_severity: Risk
    default_action: Action
    test_hint: str


def _snippet(lines: list[str], index: int, span: int = _CONTEXT_LINES) -> str:
    start = max(0, index - span)
    end = min(len(lines), index + span + 1)
    return "\n".join(lines[start:end])


def _path(section: ContextSection) -> str:
    return section.get("path", section["kind"])


_SECRET_PATTERNS = [
    re.compile(r"sk_live_[A-Za-z0-9_]+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*"
        r"['\"]([A-Za-z0-9+/_\-]{16,}={0,2})['\"]"
    ),
]


def _find_secrets(section: ContextSection) -> list[Candidate]:
    lines = section["content"].splitlines()
    found = []
    for i, line in enumerate(lines):
        for pattern in _SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                found.append(
                    Candidate(
                        category="privacy",
                        file=_path(section),
                        evidence=line.strip(),
                        snippet=_snippet(lines, i),
                        default_severity="high",
                        default_action="request_changes",
                        test_hint=(
                            "secret scanning must reject this committed production "
                            "credential before merge, and the exposed credential must "
                            "be rotated"
                        ),
                    )
                )
                break
    return found


_FETCH_RE = re.compile(r"(\w+)\s*=\s*[\w.]+\.get\(([^)]*)\)")
# Scoped to delete/remove only: update/save catch too many legitimate
# write-backs (e.g. a race-condition fix-up) and turn into false positives.
_MUTATE_RE = re.compile(r"\.(delete|remove)\(")
_OWNER_HINT_RE = re.compile(
    r"(?i)owner|authoriz|permission|tenant_id|require_owner|current_user\.id\s*=="
)


def _find_missing_owner_check(section: ContextSection) -> Candidate | None:
    lines = section["content"].splitlines()
    for i, line in enumerate(lines):
        match = _FETCH_RE.search(line)
        if not match:
            continue
        var = match.group(1)
        window = lines[i : i + 6]
        window_text = "\n".join(window)
        if var in window_text and _MUTATE_RE.search(window_text) and not _OWNER_HINT_RE.search(
            window_text
        ):
            return Candidate(
                category="authorization",
                file=_path(section),
                evidence=line.strip(),
                snippet=_snippet(lines, i, span=4),
                default_severity="high",
                default_action="block",
                test_hint=(
                    "a cross-tenant or non-owner request against this endpoint must be "
                    "rejected with 403, not performed"
                ),
            )
    return None


_ROUTE_RE = re.compile(r"@\w+\.route\(")
_AUTH_DECORATOR_RE = re.compile(r"@(?:require_auth|login_required|requires_auth|auth_required)\b")
_AUTH_CALL_RE = re.compile(r"require_user\(|current_user\b|request\.user\b")
_SENSITIVE_MUTATION_RE = re.compile(
    r"\.role\s*=|is_admin\s*=|is_staff\s*=|\.password\s*=|\.permission\w*\s*="
)


def _find_missing_authentication(section: ContextSection) -> Candidate | None:
    lines = section["content"].splitlines()
    for i, line in enumerate(lines):
        if not _ROUTE_RE.search(line):
            continue
        j = i
        while j < len(lines) and not lines[j].lstrip().startswith("def "):
            j += 1
        if j >= len(lines):
            continue
        decorator_text = "\n".join(lines[i:j])
        body_lines = []
        k = j + 1
        while k < len(lines) and lines[k].strip() and not lines[k].lstrip().startswith(("@", "def ")):
            body_lines.append(lines[k])
            k += 1
        body_text = "\n".join(body_lines)
        if _AUTH_DECORATOR_RE.search(decorator_text) or _AUTH_CALL_RE.search(body_text):
            continue
        if not _SENSITIVE_MUTATION_RE.search(body_text):
            continue
        return Candidate(
            category="authentication",
            file=_path(section),
            evidence=lines[j].strip(),
            snippet=_snippet(lines, j, span=4),
            default_severity="critical",
            default_action="block",
            test_hint=(
                "an unauthenticated request must be rejected with 401 before this "
                "handler runs, not processed"
            ),
        )
    return None


_NOT_NULL_RE = re.compile(
    r"(?i)ALTER\s+(?:TABLE\s+\w+\s+)?(?:ALTER|MODIFY)\s+COLUMN\s+(\w+)[^;]*SET\s+NOT\s+NULL"
    r"|ADD\s+COLUMN\s+(\w+)\s+\w+.*NOT\s+NULL"
)


def _mentions_backfill_for(text: str, column: str) -> bool:
    for match in re.finditer(r"(?i)backfill", text):
        window = text[max(0, match.start() - 80) : match.end() + 80]
        if column.lower() in window.lower():
            return True
    return False


def _find_unsafe_migration(case: Case, section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _NOT_NULL_RE.search(content)
    if not match:
        return None
    if re.search(r"(?i)\bUPDATE\b", content) or re.search(r"(?i)\bDEFAULT\b", content):
        return None
    column = match.group(1) or match.group(2) or "the column"
    other_text = "\n".join(other["content"] for other in case["context"] if other is not section)
    if _mentions_backfill_for(content + "\n" + other_text, column):
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="data_integrity",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=3),
        default_severity="high",
        default_action="request_changes",
        test_hint=(
            f"run this migration against an existing row where {column} is NULL and "
            f"confirm it is backfilled first, not just rejected by the constraint"
        ),
    )


_DROP_COLUMN_RE = re.compile(r"(?i)ALTER\s+TABLE\s+\w+\s+DROP\s+COLUMN\s+(\w+)")
_BACKUP_HINT_RE = re.compile(r"(?i)backup|archive|export(?:ed)?\s+first|backfill")


def _find_dropped_column_still_in_use(case: Case, section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _DROP_COLUMN_RE.search(content)
    if not match:
        return None
    column = match.group(1)
    other_text = "\n".join(other["content"] for other in case["context"] if other is not section)
    # Only flag when something elsewhere in the case actually references the
    # dropped column - otherwise this is an ordinary, safe cleanup.
    if column.lower() not in other_text.lower():
        return None
    if _BACKUP_HINT_RE.search(content + other_text):
        return None
    sentences = re.split(r"(?<=[.!?])\s+", other_text)
    fragment = next(
        (s.strip() for s in sentences if column.lower() in s.lower()), other_text.strip()
    )
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="data_loss",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=f"{_snippet(lines, line_index, span=2)}\n---\n{other_text}",
        default_severity="critical",
        default_action="block",
        test_hint=(
            f"confirm nothing still reads {column} before dropping it - context: "
            f'"{fragment}"'
        ),
    )


def _find_shell_injection(section: ContextSection) -> Candidate | None:
    content = section["content"]
    if "shell=True" not in content:
        return None
    if not re.search(r"request\.(form|args|GET|POST|json|data)", content):
        return None
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if "shell=True" in line:
            return Candidate(
                category="injection",
                file=_path(section),
                evidence=line.strip(),
                snippet=_snippet(lines, i, span=4),
                default_severity="critical",
                default_action="block",
                test_hint=(
                    "an input containing shell metacharacters must be rejected, not "
                    "passed to the shell"
                ),
            )
    return None


_SQL_FSTRING_RE = re.compile(r"f['\"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\b.*\{", re.IGNORECASE)
_DB_EXECUTE_RE = re.compile(r"\.(execute|execute_query|raw)\(")


def _find_sql_injection(section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _SQL_FSTRING_RE.search(content)
    if not match:
        return None
    if not _DB_EXECUTE_RE.search(content):
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="injection",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=4),
        default_severity="critical",
        default_action="block",
        test_hint=(
            "an input containing SQL metacharacters must be rejected, not concatenated "
            "into the query"
        ),
    )


_HTTP_CALL_RE = re.compile(r"requests\.(?:get|post|put|patch|delete)\(")


def _find_missing_timeout(section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _HTTP_CALL_RE.search(content)
    if not match:
        return None
    depth = 0
    end = match.start()
    for idx in range(match.start(), len(content)):
        if content[idx] == "(":
            depth += 1
        elif content[idx] == ")":
            depth -= 1
            if depth == 0:
                end = idx + 1
                break
    call_text = content[match.start() : end]
    if re.search(r"\btimeout\s*=", call_text):
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="reliability",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=3),
        default_severity="high",
        default_action="request_changes",
        test_hint=(
            "simulate the gateway is slow to respond and confirm this call still "
            "returns via its own timeout, not hanging the worker indefinitely"
        ),
    )


_PRIV_HEADER_RE = re.compile(
    r"request\.(?:headers|cookies|args|form)\.get\(\s*['\"]"
    r"([^'\"]*(?:admin|role|permission|is_staff|superuser|privilege)[^'\"]*)['\"]",
    re.IGNORECASE,
)


def _find_client_controlled_privilege_flag(section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _PRIV_HEADER_RE.search(content)
    if not match:
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="authorization",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=4),
        default_severity="critical",
        default_action="block",
        test_hint=(
            "a forged header must not grant the full account or privileged response, "
            "since the client fully controls this value"
        ),
    )


_CHECK_RE = re.compile(r"if\s+(\w+)\.(\w+)\s*[<>=!]+\s*\w+\s*:")
_LOCK_HINT_RE = re.compile(r"(?i)lock|for update|atomic|transaction|compare_and_swap|\bCAS\b")


def _find_check_then_act_race(section: ContextSection) -> Candidate | None:
    content = section["content"]
    lines = content.splitlines()
    for i, line in enumerate(lines):
        match = _CHECK_RE.search(line)
        if not match:
            continue
        var, field = match.group(1), match.group(2)
        window = lines[i : i + 5]
        window_text = "\n".join(window)
        mutate_match = re.search(rf"{re.escape(var)}\.{re.escape(field)}\s*[+\-]=", window_text)
        if not mutate_match:
            continue
        if _LOCK_HINT_RE.search(window_text):
            continue
        idx = i + window_text[: mutate_match.start()].count("\n")
        return Candidate(
            category="race_condition",
            file=_path(section),
            evidence=lines[idx].strip(),
            snippet=_snippet(lines, idx, span=4),
            default_severity="high",
            default_action="block",
            test_hint=(
                f"issue two concurrent requests against this check-then-act path and "
                f"confirm {field} cannot go negative - a race here is exactly how you "
                f"oversell inventory or double-spend a limited resource"
            ),
        )
    return None


_PATCH_RE = re.compile(r"@(?:mock\.)?patch\(['\"]([\w.]+)['\"]\)")


def _find_test_mocks_function_under_test(section: ContextSection) -> Candidate | None:
    lines = section["content"].splitlines()
    for i, line in enumerate(lines):
        patch_match = _PATCH_RE.search(line)
        if not patch_match:
            continue
        target_name = patch_match.group(1).rsplit(".", 1)[-1]
        j = i + 1
        while j < len(lines) and not lines[j].lstrip().startswith("def "):
            j += 1
        if j >= len(lines):
            continue
        body = "\n".join(lines[j : j + 6])
        if not re.search(rf"\b{re.escape(target_name)}\s*\(", body):
            continue
        return Candidate(
            category="testing_gap",
            file=_path(section),
            evidence=line.strip(),
            snippet=_snippet(lines, i, span=5),
            default_severity="high",
            default_action="request_changes",
            test_hint=(
                f"run this test against the real {target_name}, without mocking it, "
                f"since mocking the function under test means the real implementation "
                f"never executes"
            ),
        )
    return None


_USER_INPUT_ASSIGN_RE = re.compile(r"(\w+)\s*=\s*request\.(?:json|form|args|GET|POST)\[")
_OUTBOUND_HTTP_RE = re.compile(r"requests\.(?:get|post|put|patch)\(\s*(\w+)")
_URL_VALIDATION_HINT_RE = re.compile(
    r"(?i)allowlist|whitelist|is_internal|private_ip|validate_url|ipaddress\."
)


def _find_ssrf(section: ContextSection) -> Candidate | None:
    content = section["content"]
    lines = content.splitlines()
    for i, line in enumerate(lines):
        assign_match = _USER_INPUT_ASSIGN_RE.search(line)
        if not assign_match:
            continue
        var = assign_match.group(1)
        window = "\n".join(lines[i : i + 5])
        http_match = _OUTBOUND_HTTP_RE.search(window)
        if not http_match or http_match.group(1) != var:
            continue
        if _URL_VALIDATION_HINT_RE.search(window):
            continue
        idx = i + window[: http_match.start()].count("\n")
        return Candidate(
            category="injection",
            file=_path(section),
            evidence=lines[idx].strip(),
            snippet=_snippet(lines, idx, span=4),
            default_severity="critical",
            default_action="block",
            test_hint=(
                "a URL pointing at an internal metadata endpoint or private IP range "
                "must be rejected, not fetched"
            ),
        )
    return None


_PATH_JOIN_RE = re.compile(r"os\.path\.join\(\s*\w+\s*,\s*(\w+)\)")
_SANITIZE_HINT_RE = re.compile(r"(?i)secure_filename|sanitiz|normpath|realpath|basename")


def _find_path_traversal(section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _PATH_JOIN_RE.search(content)
    if not match:
        return None
    var = match.group(1)
    if not re.search(rf"{re.escape(var)}\s*=\s*request\.", content):
        return None
    if _SANITIZE_HINT_RE.search(content):
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="injection",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=3),
        default_severity="critical",
        default_action="block",
        test_hint="a filename containing ../ must be rejected, not used to build the file path",
    )


_CORS_WILDCARD_RE = re.compile(r"Access-Control-Allow-Origin'?\]?\s*=\s*['\"]\*['\"]")
_CORS_CREDENTIALS_RE = re.compile(
    r"Access-Control-Allow-Credentials'?\]?\s*=\s*['\"]true['\"]", re.IGNORECASE
)


def _find_cors_wildcard_with_credentials(section: ContextSection) -> Candidate | None:
    content = section["content"]
    wildcard_match = _CORS_WILDCARD_RE.search(content)
    if not wildcard_match or not _CORS_CREDENTIALS_RE.search(content):
        return None
    lines = content.splitlines()
    line_index = content[: wildcard_match.start()].count("\n")
    return Candidate(
        category="validation",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=content,
        default_severity="high",
        default_action="block",
        test_hint=(
            "a cross-origin request from any origin must not be able to use an "
            "authenticated session cookie against this API"
        ),
    )


_NARROW_TYPE_RE = re.compile(
    r"(?i)ALTER\s+(?:TABLE\s+\w+\s+)?ALTER\s+COLUMN\s+(\w+)\s+TYPE\s+varchar\((\d+)\)"
)
_ORIGINAL_LENGTH_RE = re.compile(r"(?i)(\w+)\s+varchar\((\d+)\)")


def _find_silent_truncation(case: Case, section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _NARROW_TYPE_RE.search(content)
    if not match:
        return None
    column, new_length = match.group(1), int(match.group(2))
    other_text = "\n".join(other["content"] for other in case["context"] if other is not section)
    orig_match = next(
        (m for m in _ORIGINAL_LENGTH_RE.finditer(other_text) if m.group(1) == column), None
    )
    if orig_match is None or int(orig_match.group(2)) <= new_length:
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="data_loss",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=f"{_snippet(lines, line_index, span=2)}\n---\n{other_text}",
        default_severity="critical",
        default_action="block",
        test_hint=(
            f"confirm no existing {column} value is longer than {new_length} "
            f"characters before narrowing the column, since a longer value would be "
            f"truncated silently, not rejected"
        ),
    )


_DEFAULT_PASSWORD_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token)\w*\s*=\s*os\.environ\.get\(\s*['\"]\w+['\"]\s*,\s*"
    r"['\"]([^'\"]{4,})['\"]\s*\)"
)
_WEAK_PLACEHOLDER_RE = re.compile(r"(?i)change ?me|default|admin|password|12345|test")


def _find_hardcoded_default_password(section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _DEFAULT_PASSWORD_RE.search(content)
    if not match:
        return None
    default_value = match.group(1)
    if not _WEAK_PLACEHOLDER_RE.search(default_value):
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="authentication",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=2),
        default_severity="critical",
        default_action="block",
        test_hint=(
            f"boot with the environment variable unset and confirm the default "
            f"password '{default_value}' does not grant access from the public "
            f"internet"
        ),
    )


_SKIP_DECORATOR_RE = re.compile(r"@pytest\.mark\.skip\([^)]*\)")
_TEST_DEF_RE = re.compile(r"def (test_\w+)\(")


def _find_skipped_test_covering_changed_code(case: Case, section: ContextSection) -> Candidate | None:
    content = section["content"]
    skip_match = _SKIP_DECORATOR_RE.search(content)
    if not skip_match:
        return None
    lines = content.splitlines()
    line_index = content[: skip_match.start()].count("\n")
    def_line = next(
        (lines[j] for j in range(line_index, min(line_index + 3, len(lines))) if _TEST_DEF_RE.search(lines[j])),
        None,
    )
    if def_line is None:
        return None
    body = "\n".join(lines[line_index : line_index + 6])
    called_names = set(re.findall(r"\b(\w+)\(", body))
    covers_change = any(
        re.search(rf"\bdef {re.escape(name)}\(", other["content"])
        for other in case["context"]
        if other is not section and other.get("kind") == "diff"
        for name in called_names
    )
    if not covers_change:
        return None
    return Candidate(
        category="testing_gap",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=5),
        default_severity="high",
        default_action="request_changes",
        test_hint=(
            f'unskip this test before merging - the change itself says: '
            f'"{case["brief"]}"'
        ),
    )


_LOG_CALL_RE = re.compile(r"(?:logger|log)\.(?:info|debug|warning|error)\(")
_PII_VAR_HINT_RE = re.compile(r"(?i)card_number|credit_card|ssn|social_security|cvv|password\b")


def _find_pii_in_logs(section: ContextSection) -> Candidate | None:
    lines = section["content"].splitlines()
    for i, line in enumerate(lines):
        if not _LOG_CALL_RE.search(line):
            continue
        if not _PII_VAR_HINT_RE.search(line):
            continue
        return Candidate(
            category="privacy",
            file=_path(section),
            evidence=line.strip(),
            snippet=_snippet(lines, i, span=3),
            default_severity="critical",
            default_action="block",
            test_hint=(
                "check the emitted log output and confirm the sensitive value is "
                "masked, not printed in plaintext"
            ),
        )
    return None


_COUNTER_GET_RE = re.compile(r"(\w+)\s*=\s*redis\.get\(")
_COUNTER_SET_RE = re.compile(r"redis\.set\(")
_ATOMIC_HINT_RE = re.compile(r"(?i)incr|pipeline|watch|lua|atomic")


def _find_nonatomic_counter(case: Case, section: ContextSection) -> Candidate | None:
    content = section["content"]
    if not _COUNTER_GET_RE.search(content):
        return None
    set_match = _COUNTER_SET_RE.search(content)
    if not set_match:
        return None
    if _ATOMIC_HINT_RE.search(content):
        return None
    other_text = "\n".join(other["content"] for other in case["context"] if other is not section)
    if not re.search(r"(?i)concurrent|multiple worker|many worker|race", content + other_text):
        return None
    lines = content.splitlines()
    line_index = content[: set_match.start()].count("\n")
    return Candidate(
        category="race_condition",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=4),
        default_severity="high",
        default_action="request_changes",
        test_hint=(
            "run this handler from concurrent workers and confirm the counter is not "
            "undercounted, since a non-atomic get-then-set can lose increments to a "
            "lost update"
        ),
    )


_SWALLOWED_EXCEPTION_RE = re.compile(
    r"except\s+(?:\([\w.,\s]+\)|\w+)?\s*(?:as\s+\w+)?\s*:\s*\n\s*pass\b"
)


def _find_swallowed_exception(section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _SWALLOWED_EXCEPTION_RE.search(content)
    if not match:
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="observability",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=3),
        default_severity="high",
        default_action="request_changes",
        test_hint=(
            "confirm that when this call raises an exception, the failure is logged "
            "or re-raised, not silently swallowed"
        ),
    )


_WHILE_TRUE_RE = re.compile(r"while\s+True\s*:")
_RETRY_BOUND_HINT_RE = re.compile(r"(?i)max_attempts|max_retries|backoff|time\.sleep")


def _find_unbounded_retry(section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _WHILE_TRUE_RE.search(content)
    if not match:
        return None
    if not re.search(r"(?i)requests\.|\bhttp\b|\bapi\b", content):
        return None
    body_after = content[match.end() : match.end() + 400]
    if _RETRY_BOUND_HINT_RE.search(body_after):
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="reliability",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=6),
        default_severity="high",
        default_action="request_changes",
        test_hint=(
            "simulate that the remote provider is down and confirm this loop gives up "
            "after a bounded number of attempts with backoff, instead of retrying forever"
        ),
    )


_JWT_NO_VERIFY_RE = re.compile(
    r"jwt\.decode\([^)]*(?:verify_signature['\"]?\s*:\s*False|algorithms\s*=\s*\[\s*['\"]none['\"])",
    re.IGNORECASE,
)


def _find_jwt_signature_not_verified(section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _JWT_NO_VERIFY_RE.search(content)
    if not match:
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="authentication",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=3),
        default_severity="critical",
        default_action="block",
        test_hint=(
            "a forged token with an invalid signature must be rejected, not decoded "
            "and trusted"
        ),
    )


_OS_SYSTEM_CONCAT_RE = re.compile(r"os\.system\(\s*['\"][^'\"]*['\"]\s*\+\s*\w+")


def _find_os_system_injection(section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _OS_SYSTEM_CONCAT_RE.search(content)
    if not match:
        return None
    if not re.search(r"request\.(form|args|GET|POST|json|data)", content):
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="injection",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=3),
        default_severity="critical",
        default_action="block",
        test_hint=(
            "an input containing shell metacharacters must be rejected, not "
            "concatenated into the command string"
        ),
    )


_ANALYTICS_CALL_RE = re.compile(r"analytics\.(?:track|identify|capture)\(")
_PII_FIELD_RE = re.compile(
    r"['\"](?:ssn|card_number|credit_card|cvv|password)['\"]\s*:", re.IGNORECASE
)


def _find_pii_to_third_party(section: ContextSection) -> Candidate | None:
    content = section["content"]
    if not _ANALYTICS_CALL_RE.search(content):
        return None
    match = _PII_FIELD_RE.search(content)
    if not match:
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="privacy",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=2),
        default_severity="critical",
        default_action="block",
        test_hint=(
            "check the payload actually sent to the third-party analytics provider "
            "and confirm the sensitive field is redacted, not included"
        ),
    )


_PKG_LINE_RE = re.compile(r"^([\w.\-]+)==([\d.]+)")
_KNOWN_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django", "boto3", "pyyaml",
    "cryptography", "urllib3", "click", "sqlalchemy", "pillow", "jinja2",
    "pytest", "aiohttp", "fastapi", "pydantic", "redis", "celery", "gunicorn",
]


def _find_typosquatted_dependency(section: ContextSection) -> Candidate | None:
    # Flag only the primary manifest, not every derived lockfile entry for the
    # same package - otherwise one typo produces one finding per file it's
    # pinned in.
    if "lock" in _path(section).lower():
        return None
    content = section["content"]
    for line in content.splitlines():
        pkg_match = _PKG_LINE_RE.match(line.strip())
        if not pkg_match:
            continue
        name = pkg_match.group(1)
        if name.lower() in _KNOWN_PACKAGES:
            continue
        close = difflib.get_close_matches(name.lower(), _KNOWN_PACKAGES, n=1, cutoff=0.82)
        if not close:
            continue
        return Candidate(
            category="dependency",
            file=_path(section),
            evidence=line.strip(),
            snippet=content,
            default_severity="high",
            default_action="block",
            test_hint=(
                f"confirm this is really '{close[0]}' and not a typosquatted package - "
                f"'{name}' is one edit away from the popular package '{close[0]}'"
            ),
        )
    return None


def _find_disabled_tls(section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = re.search(r"verify\s*=\s*False", content)
    if not match:
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    return Candidate(
        category="validation",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=3),
        default_severity="high",
        default_action="request_changes",
        test_hint=(
            "a connection presenting a self-signed certificate must be rejected, not "
            "accepted"
        ),
    )


_EFFECT_RE = re.compile(r"\.(charge|capture|send|notify|deduct|transfer)\(")
_DEDUPE_RE = re.compile(
    r"(?i)processed_events|seen_events|idempot|already_processed|on\s+conflict\s+do\s+nothing"
)


def _find_idempotency_gap(section: ContextSection) -> Candidate | None:
    content = section["content"]
    effect_match = _EFFECT_RE.search(content)
    if not effect_match:
        return None
    dedupe_match = _DEDUPE_RE.search(content)
    if dedupe_match and dedupe_match.start() < effect_match.start():
        return None
    lines = content.splitlines()
    line_index = content[: effect_match.start()].count("\n")
    return Candidate(
        category="idempotency",
        file=_path(section),
        evidence=lines[line_index].strip(),
        snippet=_snippet(lines, line_index, span=4),
        default_severity="high",
        default_action="block",
        test_hint=(
            "deliver the same event twice and confirm exactly one effect happens - one "
            "charge, one message, or one transfer, depending on what this handler does - "
            "not one per delivery"
        ),
    )


_CACHE_KEY_RE = re.compile(r"key\s*=\s*f?['\"][^'\"]*\{(\w+)\.(\w*id\w*)\}")


def _find_tenant_missing_from_cache_key(case: Case, section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _CACHE_KEY_RE.search(content)
    if not match:
        return None
    lines = content.splitlines()
    line_index = content[: match.start()].count("\n")
    key_line = lines[line_index]
    if "tenant" in key_line.lower():
        return None
    other_text = "\n".join(
        other["content"] for other in case["context"] if other is not section
    )
    if "tenant" not in other_text.lower():
        return None
    id_field = match.group(2)
    return Candidate(
        category="privacy",
        file=_path(section),
        evidence=key_line.strip(),
        snippet=_snippet(lines, line_index, span=3),
        default_severity="high",
        default_action="block",
        test_hint=(
            f"two tenants with the same {id_field} must not be able to read each "
            f"other's cached data through this key"
        ),
    )


_WORKFLOW_PATH_RE = re.compile(r"\.ya?ml$")


def _find_testing_gap(case: Case, section: ContextSection) -> Candidate | None:
    content = section["content"]
    if not re.search(r"\b0 selected\b|collected 0 items", content, re.IGNORECASE):
        return None
    if not re.search(r"(?i)passed", content):
        return None
    lines = content.splitlines()
    evidence_line = next(
        (line for line in lines if re.search(r"\b0 selected\b|collected 0 items", line, re.IGNORECASE)),
        None,
    )
    if evidence_line is None:
        return None
    workflow = next(
        (
            other
            for other in case["context"]
            if other is not section
            and (_WORKFLOW_PATH_RE.search(other.get("path", "")) or "jobs:" in other["content"])
        ),
        None,
    )
    target = workflow or section
    return Candidate(
        category="testing_gap",
        file=_path(target),
        evidence=evidence_line.strip(),
        snippet=f"{content}\n---\n{target['content']}" if workflow else content,
        default_severity="high",
        default_action="request_changes",
        test_hint=(
            "fix the job filter so at least one test actually runs, since zero "
            "selected tests means this job cannot fail"
        ),
    )


_ADVISORY_RE = re.compile(
    r"([\w.\-]+)\s+(?:versions?\s+below|prior\s+to|before)\s+([\d.]+)", re.IGNORECASE
)
_LOCKFILE_PKG_RE = re.compile(r"([\w.\-]+)==([\d.]+)")


def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split(".") if part.isdigit())


def _find_vulnerable_transitive_dependency(case: Case) -> Candidate | None:
    advisory_text = None
    advisory_section = None
    for section in case["context"]:
        match = _ADVISORY_RE.search(section["content"])
        if match:
            advisory_text = match
            advisory_section = section
            break
    if advisory_text is None or advisory_section is None:
        return None
    package, threshold = advisory_text.group(1), advisory_text.group(2)
    for section in case["context"]:
        for line in section["content"].splitlines():
            pkg_match = _LOCKFILE_PKG_RE.search(line)
            if not pkg_match or pkg_match.group(1) != package:
                continue
            if _version_tuple(pkg_match.group(2)) < _version_tuple(threshold):
                return Candidate(
                    category="dependency",
                    file=_path(section),
                    evidence=line.strip(),
                    snippet=f"advisory: {advisory_section['content']}\nlockfile: {section['content']}",
                    default_severity="high",
                    default_action="request_changes",
                    test_hint=(
                        f"exercise the vulnerable code path described in the advisory "
                        f"({advisory_section['content'].strip()}) and confirm it is "
                        f"blocked, or that the dependency is upgraded past the advisory"
                    ),
                )
    return None


_TIMEZONE_OWNER_RE = re.compile(r"(\w+)_timezone", re.IGNORECASE)


def _find_naive_timezone_migration(case: Case, section: ContextSection) -> Candidate | None:
    content = section["content"]
    if not re.search(r"AT TIME ZONE\s*'UTC'", content, re.IGNORECASE):
        return None
    if not re.search(r"(?i)\bUSING\b", content):
        return None
    other_text = "\n".join(
        other["content"] for other in case["context"] if other is not section
    )
    if "timezone" not in other_text.lower():
        return None
    owner_match = _TIMEZONE_OWNER_RE.search(other_text) or _TIMEZONE_OWNER_RE.search(content)
    owner = owner_match.group(1) if owner_match else "record"
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if "TIME ZONE" in line.upper():
            return Candidate(
                category="data_loss",
                file=_path(section),
                evidence=line.strip(),
                snippet=_snippet(lines, i, span=3),
                default_severity="critical",
                default_action="block",
                test_hint=(
                    f"convert a non-UTC {owner} and confirm the migration continues to "
                    f"preserve instant equality with the original timestamp, not shift "
                    f"it as if it were already UTC"
                ),
            )
    return None


def find_candidates(case: Case) -> list[Candidate]:
    candidates: list[Candidate] = []
    for section in case["context"]:
        candidates.extend(_find_secrets(section))
        owner_check = _find_missing_owner_check(section)
        if owner_check:
            candidates.append(owner_check)
        authentication = _find_missing_authentication(section)
        if authentication:
            candidates.append(authentication)
        migration = _find_unsafe_migration(case, section)
        if migration:
            candidates.append(migration)
        dropped_column = _find_dropped_column_still_in_use(case, section)
        if dropped_column:
            candidates.append(dropped_column)
        injection = _find_shell_injection(section)
        if injection:
            candidates.append(injection)
        sql_injection = _find_sql_injection(section)
        if sql_injection:
            candidates.append(sql_injection)
        ssrf = _find_ssrf(section)
        if ssrf:
            candidates.append(ssrf)
        path_traversal = _find_path_traversal(section)
        if path_traversal:
            candidates.append(path_traversal)
        cors = _find_cors_wildcard_with_credentials(section)
        if cors:
            candidates.append(cors)
        timeout = _find_missing_timeout(section)
        if timeout:
            candidates.append(timeout)
        privilege_header = _find_client_controlled_privilege_flag(section)
        if privilege_header:
            candidates.append(privilege_header)
        race = _find_check_then_act_race(section)
        if race:
            candidates.append(race)
        nonatomic_counter = _find_nonatomic_counter(case, section)
        if nonatomic_counter:
            candidates.append(nonatomic_counter)
        tls = _find_disabled_tls(section)
        if tls:
            candidates.append(tls)
        idempotency = _find_idempotency_gap(section)
        if idempotency:
            candidates.append(idempotency)
        cache_key = _find_tenant_missing_from_cache_key(case, section)
        if cache_key:
            candidates.append(cache_key)
        testing_gap = _find_testing_gap(case, section)
        if testing_gap:
            candidates.append(testing_gap)
        mocked_test = _find_test_mocks_function_under_test(section)
        if mocked_test:
            candidates.append(mocked_test)
        skipped_test = _find_skipped_test_covering_changed_code(case, section)
        if skipped_test:
            candidates.append(skipped_test)
        pii_logging = _find_pii_in_logs(section)
        if pii_logging:
            candidates.append(pii_logging)
        default_password = _find_hardcoded_default_password(section)
        if default_password:
            candidates.append(default_password)
        silent_truncation = _find_silent_truncation(case, section)
        if silent_truncation:
            candidates.append(silent_truncation)
        swallowed_exception = _find_swallowed_exception(section)
        if swallowed_exception:
            candidates.append(swallowed_exception)
        unbounded_retry = _find_unbounded_retry(section)
        if unbounded_retry:
            candidates.append(unbounded_retry)
        jwt_no_verify = _find_jwt_signature_not_verified(section)
        if jwt_no_verify:
            candidates.append(jwt_no_verify)
        os_system_injection = _find_os_system_injection(section)
        if os_system_injection:
            candidates.append(os_system_injection)
        pii_third_party = _find_pii_to_third_party(section)
        if pii_third_party:
            candidates.append(pii_third_party)
        typosquat = _find_typosquatted_dependency(section)
        if typosquat:
            candidates.append(typosquat)
        timezone = _find_naive_timezone_migration(case, section)
        if timezone:
            candidates.append(timezone)
    dependency = _find_vulnerable_transitive_dependency(case)
    if dependency:
        candidates.append(dependency)
    return candidates[:MAX_CANDIDATES]
