"""
Unit tests for the KQL (Kusto Query Language) format adapter.

The adapter mirrors the contract documented in
`app/features/rule/rule_format/abstract_rule_type/rule_type_abstract.py`
and is structured to match the existing `atr_format` tests for consistency.

KQL rules ship as raw .kql files (one query per file, no YAML wrapper), so
metadata comes from an optional leading `// Key: Value` comment header and
otherwise falls back to the filename / defaults.
"""
from __future__ import annotations

import json
from textwrap import dedent

import pytest

from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import ValidationResult
from app.features.rule.rule_format.available_format.kql_format import KQLRule


# -------------------------------------------------------------------------
#                           Sample rule fixtures
# -------------------------------------------------------------------------

_VALID_KQL_RULE = dedent(
    """\
    // Title: Suspicious sign-in spike
    // Description: Detects a spike in failed sign-ins for a single user
    // Author: Contoso SOC
    // License: MIT
    // Severity: Medium
    // Tags: initial-access, credential-access
    SigninLogs
    | where ResultType != 0
    | summarize FailedCount = count() by UserPrincipalName
    | where FailedCount > 5
    """
)

_VALID_KQL_RULE_WITH_CVE = dedent(
    """\
    // Title: SmartScreen bypass exploitation
    // Description: Detects exploitation attempts for CVE-2024-21412 in SmartScreen bypass campaigns
    DeviceProcessEvents
    | where ProcessCommandLine has ".url"
    """
)

_VALID_KQL_NO_HEADER = dedent(
    """\
    SecurityEvent
    | where EventID == 4625
    """
)

# The convention actually used by most public KQL rule repos (e.g.
# reprise99/Sentinel-Queries, 460+ files): a plain-English `//` comment with
# no `Key: Value` structure at all, sometimes followed by a second
# comment paragraph noting a prerequisite (data connector, permissions...).
_REAL_WORLD_NO_HEADER = dedent(
    """\
    //Detect when the 'account is sensitive and cannot be delegated' flag on an account is changed

    //Data connector required for this query - Windows Security Events via AMA or Security Events via Legacy Agent

    SecurityEvent
    | project TimeGenerated, EventID, TargetAccount
    | where EventID == "4738"
    """
)

# A trailing inline comment containing an apostrophe — this must not be
# mistaken for an unterminated string literal.
_VALID_KQL_WITH_INLINE_COMMENT = dedent(
    """\
    SigninLogs
    | where ResultType != 0 // don't count successful sign-ins
    | summarize FailedCount = count() by UserPrincipalName
    """
)

# An ordinary sentence containing a colon that is NOT metadata and must not
# be misread as a `Key: Value` header line.
_VALID_KQL_WITH_COLON_IN_PROSE = dedent(
    """\
    //Note: this query requires the AMA data connector
    SecurityEvent
    | where EventID == 4625
    """
)

_BARE_TABLE_REFERENCE = "SecurityEvent"

_INVALID_STARTS_WITH_PIPE = "| where 1 == 1"

_INVALID_UNBALANCED_BRACKET = dedent(
    """\
    SigninLogs
    | where (ResultType != 0
    """
)

_INVALID_MGMT_COMMAND = ".show tables"

_INVALID_COMMENT_ONLY = dedent(
    """\
    // Title: Nothing here
    // just comments, no query body
    """
)


# -------------------------------------------------------------------------
#                                Tests
# -------------------------------------------------------------------------


@pytest.fixture(scope="module")
def kql() -> KQLRule:
    return KQLRule()


def test_format_identifier(kql: KQLRule) -> None:
    assert kql.format == "kql"
    assert kql.get_class() == "KQLRule"


# ---- validate() ------------------------------------------------------------


def test_validate_accepts_canonical_kql_rule(kql: KQLRule) -> None:
    result = kql.validate(_VALID_KQL_RULE)
    assert isinstance(result, ValidationResult)
    assert result.ok is True, result.errors
    assert result.errors == []
    assert result.normalized_content == _VALID_KQL_RULE


def test_validate_accepts_rule_without_header(kql: KQLRule) -> None:
    result = kql.validate(_VALID_KQL_NO_HEADER)
    assert result.ok is True, result.errors


def test_validate_warns_on_bare_table_reference(kql: KQLRule) -> None:
    result = kql.validate(_BARE_TABLE_REFERENCE)
    assert result.ok is True
    assert any("pipe" in w for w in result.warnings)


def test_validate_accepts_inline_comment_with_apostrophe(kql: KQLRule) -> None:
    """A trailing `// don't ...` comment must not be read as an unterminated string."""
    result = kql.validate(_VALID_KQL_WITH_INLINE_COMMENT)
    assert result.ok is True, result.errors
    assert not any("string literal" in e.lower() for e in result.errors)


def test_validate_rejects_empty_content(kql: KQLRule) -> None:
    result = kql.validate("")
    assert result.ok is False
    assert any("empty" in e.lower() for e in result.errors)


def test_validate_rejects_comment_only_content(kql: KQLRule) -> None:
    result = kql.validate(_INVALID_COMMENT_ONLY)
    assert result.ok is False
    assert any("comments" in e.lower() for e in result.errors)


def test_validate_rejects_query_starting_with_pipe(kql: KQLRule) -> None:
    result = kql.validate(_INVALID_STARTS_WITH_PIPE)
    assert result.ok is False
    assert any("pipe" in e.lower() for e in result.errors)


def test_validate_rejects_unbalanced_bracket(kql: KQLRule) -> None:
    result = kql.validate(_INVALID_UNBALANCED_BRACKET)
    assert result.ok is False
    assert any("unclosed" in e.lower() for e in result.errors)


def test_validate_rejects_management_command(kql: KQLRule) -> None:
    result = kql.validate(_INVALID_MGMT_COMMAND)
    assert result.ok is False
    assert any("control command" in e.lower() for e in result.errors)


# ---- parse_metadata() ----------------------------------------------------


def test_parse_metadata_reads_header_fields(kql: KQLRule) -> None:
    validation_result = kql.validate(_VALID_KQL_RULE)
    meta = kql.parse_metadata(_VALID_KQL_RULE, {}, validation_result)
    assert meta["format"] == "kql"
    assert meta["title"] == "Suspicious sign-in spike"
    assert meta["description"] == "Detects a spike in failed sign-ins for a single user"
    assert meta["author"] == "Contoso SOC"
    assert meta["license"] == "MIT"
    assert meta["severity"] == "Medium"
    assert meta["tags"] == ["initial-access", "credential-access"]
    assert meta["to_string"] == _VALID_KQL_RULE


def test_parse_metadata_falls_back_to_filename_title(kql: KQLRule) -> None:
    validation_result = kql.validate(_VALID_KQL_NO_HEADER)
    meta = kql.parse_metadata(
        _VALID_KQL_NO_HEADER, {"filepath": "failed-logon-burst.kql"}, validation_result
    )
    assert meta["title"] == "Failed Logon Burst"
    assert meta["description"] == "No description provided"


def test_parse_metadata_falls_back_to_default_title_without_filepath(kql: KQLRule) -> None:
    validation_result = kql.validate(_VALID_KQL_NO_HEADER)
    meta = kql.parse_metadata(_VALID_KQL_NO_HEADER, {}, validation_result)
    assert meta["title"] == "Untitled KQL Query"


def test_parse_metadata_falls_back_to_filename_title_via_github_path(kql: KQLRule) -> None:
    """The real import pipeline (session_class.py / update_class.py) passes the
    file's path under "github_path", not "filepath" — this is the key the
    GitHub/zip import flow actually uses, so the filename fallback must work
    from it or every imported rule ends up titled "Untitled KQL Query"."""
    validation_result = kql.validate(_VALID_KQL_NO_HEADER)
    meta = kql.parse_metadata(
        _VALID_KQL_NO_HEADER, {"github_path": "Active Directory/failed-logon-burst.kql"}, validation_result
    )
    assert meta["title"] == "Failed Logon Burst"


def test_parse_metadata_uses_freeform_comment_as_description(kql: KQLRule) -> None:
    """Most public KQL rule repos have no `Key: Value` header at all — just a
    plain-English comment. That first paragraph should become the
    description instead of the generic "No description provided"."""
    validation_result = kql.validate(_REAL_WORLD_NO_HEADER)
    meta = kql.parse_metadata(
        _REAL_WORLD_NO_HEADER, {"github_path": "AccountSensitivityChanged.kql"}, validation_result
    )
    assert meta["description"] == (
        "Detect when the 'account is sensitive and cannot be delegated' flag on an account is changed"
    )
    assert meta["title"] == "Accountsensitivitychanged"


def test_parse_metadata_ignores_colon_in_ordinary_prose(kql: KQLRule) -> None:
    """A comment like "Note: this requires X" is prose, not a `Key: Value`
    metadata line — "note" is not a recognized header key, so it must be
    treated as free-form description text, not silently dropped or split."""
    validation_result = kql.validate(_VALID_KQL_WITH_COLON_IN_PROSE)
    meta = kql.parse_metadata(_VALID_KQL_WITH_COLON_IN_PROSE, {}, validation_result)
    assert meta["description"] == "Note: this query requires the AMA data connector"


def test_parse_metadata_detects_cve_in_description(kql: KQLRule) -> None:
    validation_result = kql.validate(_VALID_KQL_RULE_WITH_CVE)
    meta = kql.parse_metadata(_VALID_KQL_RULE_WITH_CVE, {}, validation_result)
    cves = json.loads(meta["cve_id"])
    assert "CVE-2024-21412" in cves


def test_parse_metadata_uses_info_defaults(kql: KQLRule) -> None:
    validation_result = kql.validate(_VALID_KQL_NO_HEADER)
    meta = kql.parse_metadata(
        _VALID_KQL_NO_HEADER,
        {"license": "Apache-2.0", "author": "Jane Doe", "repo_url": "https://example/repo"},
        validation_result,
    )
    assert meta["license"] == "Apache-2.0"
    assert meta["author"] == "Jane Doe"
    assert meta["source"] == "https://example/repo"


# ---- get_rule_files() ----------------------------------------------------


def test_get_rule_files_accepts_kql_extension(kql: KQLRule) -> None:
    assert kql.get_rule_files("rules/foo.kql") is True


def test_get_rule_files_rejects_other_extensions(kql: KQLRule) -> None:
    assert kql.get_rule_files("rules/foo.txt") is False
    assert kql.get_rule_files("rules/foo.yaml") is False


# ---- extract_rules_from_file() -------------------------------------------


def test_extract_rules_from_single_rule_file(kql: KQLRule, tmp_path) -> None:
    p = tmp_path / "rule.kql"
    p.write_text(_VALID_KQL_RULE, encoding="utf-8")
    rules = kql.extract_rules_from_file(str(p))
    assert len(rules) == 1
    assert rules[0] == _VALID_KQL_RULE.strip()


def test_extract_rules_from_comment_only_file_is_empty(kql: KQLRule, tmp_path) -> None:
    p = tmp_path / "empty.kql"
    p.write_text(_INVALID_COMMENT_ONLY, encoding="utf-8")
    rules = kql.extract_rules_from_file(str(p))
    assert rules == []


def test_extract_rules_from_missing_file_is_empty(kql: KQLRule, tmp_path) -> None:
    missing = tmp_path / "does-not-exist.kql"
    rules = kql.extract_rules_from_file(str(missing))
    assert rules == []
