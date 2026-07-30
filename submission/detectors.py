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
                            "credential before merge"
                        ),
                    )
                )
                break
    return found


_FETCH_RE = re.compile(r"(\w+)\s*=\s*[\w.]+\.get\(([^)]*)\)")
_MUTATE_RE = re.compile(r"\.(delete|update|save|remove)\(")
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


_NOT_NULL_RE = re.compile(
    r"(?i)ALTER\s+(?:TABLE\s+\w+\s+)?(?:ALTER|MODIFY)\s+COLUMN\s+\w+[^;]*SET\s+NOT\s+NULL"
    r"|ADD\s+COLUMN\s+\w+\s+\w+.*NOT\s+NULL"
)


def _find_unsafe_migration(section: ContextSection) -> Candidate | None:
    content = section["content"]
    match = _NOT_NULL_RE.search(content)
    if not match:
        return None
    if re.search(r"(?i)\bUPDATE\b", content) or re.search(r"(?i)\bDEFAULT\b", content):
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
            "run this migration against an existing row that violates the new "
            "constraint and confirm it is backfilled first, not just rejected"
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
        test_hint="a self-signed or untrusted certificate must be rejected, not accepted",
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
            "deliver the same event twice and confirm the effect happens exactly once, "
            "not once per delivery"
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
    return Candidate(
        category="privacy",
        file=_path(section),
        evidence=key_line.strip(),
        snippet=_snippet(lines, line_index, span=3),
        default_severity="high",
        default_action="block",
        test_hint=(
            "two different tenants with the same underlying id must not be able to "
            "read each other's cached data through this key"
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


_ADVISORY_RE = re.compile(r"([\w.\-]+)\s+versions?\s+below\s+([\d.]+)", re.IGNORECASE)
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
                        "exercise the vulnerable transitive code path (e.g. a nested "
                        "archive attempting path traversal) and confirm it is blocked "
                        "or the dependency is upgraded past the advisory"
                    ),
                )
    return None


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
                    "convert a record from a non-UTC zone and confirm the absolute "
                    "instant is preserved, not shifted as if it were already UTC"
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
        migration = _find_unsafe_migration(section)
        if migration:
            candidates.append(migration)
        injection = _find_shell_injection(section)
        if injection:
            candidates.append(injection)
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
        timezone = _find_naive_timezone_migration(case, section)
        if timezone:
            candidates.append(timezone)
    dependency = _find_vulnerable_transitive_dependency(case)
    if dependency:
        candidates.append(dependency)
    return candidates[:MAX_CANDIDATES]
