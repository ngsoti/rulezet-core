"""
Unit tests for the ATR (Agent Threat Rules) format adapter.

The adapter mirrors the contract documented in
`app/features/rule/rule_format/abstract_rule_type/rule_type_abstract.py`
and is structured to match the existing `sigma_format` adapter for
consistency.
"""
from __future__ import annotations

import json
import os
import tempfile
from textwrap import dedent

import pytest

from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import ValidationResult
from app.features.rule.rule_format.available_format.atr_format import ATRRule


# -------------------------------------------------------------------------
#                           Sample rule fixtures
# -------------------------------------------------------------------------

_VALID_ATR_RULE = dedent(
    """\
    id: ATR-2026-00001
    title: "Direct Prompt Injection via User Input"
    description: "Detects classic instruction-override prompt injection attempts in user input."
    severity: high
    author: "ATR Community"
    rule_version: 1
    tags:
      category: prompt-injection
      confidence: high
    agent_source:
      type: llm_io
    detection:
      condition: any
      conditions:
        - field: user_input
          operator: regex
          value: '(?i)\\bignore\\s+(?:all\\s+)?previous\\s+instructions?\\b'
          description: "Instruction-override verb + target noun"
    references:
      owasp_llm:
        - "LLM01:2025 - Prompt Injection"
      cve:
        - CVE-2024-5184
        - CVE-2024-3402
    """
)

_VALID_ATR_RULE_CVE_VIA_DESCRIPTION = dedent(
    """\
    id: ATR-2026-00432
    title: "SuperAGI Output Handler eval() RCE"
    description: "Detects CVE-2024-21552 (CVSS 9.8) eval-based RCE in SuperAGI output_handler.py."
    severity: critical
    tags:
      category: agent-manipulation
    agent_source:
      type: llm_io
    detection:
      condition: any
      conditions:
        - field: content
          operator: regex
          value: "eval\\\\("
    """
)

_INVALID_ATR_BAD_ID = dedent(
    """\
    id: NOT-AN-ATR-ID
    title: "Bad ID"
    severity: high
    tags:
      category: prompt-injection
    agent_source:
      type: llm_io
    detection:
      condition: any
      conditions:
        - field: content
          operator: regex
          value: "x"
    """
)

_INVALID_ATR_BAD_CATEGORY = dedent(
    """\
    id: ATR-2026-99999
    title: "Bad category"
    severity: high
    tags:
      category: not-a-real-category
    agent_source:
      type: llm_io
    detection:
      condition: any
      conditions:
        - field: content
          operator: regex
          value: "x"
    """
)

_INVALID_ATR_BAD_SEVERITY = dedent(
    """\
    id: ATR-2026-99999
    title: "Bad severity"
    severity: catastrophic
    tags:
      category: prompt-injection
    agent_source:
      type: llm_io
    detection:
      condition: any
      conditions:
        - field: content
          operator: regex
          value: "x"
    """
)

_INVALID_ATR_MISSING_DETECTION = dedent(
    """\
    id: ATR-2026-99999
    title: "Missing detection block"
    severity: high
    tags:
      category: prompt-injection
    agent_source:
      type: llm_io
    """
)

_INVALID_ATR_EMPTY_CONDITIONS = dedent(
    """\
    id: ATR-2026-99999
    title: "Empty conditions"
    severity: high
    tags:
      category: prompt-injection
    agent_source:
      type: llm_io
    detection:
      condition: any
      conditions: []
    """
)

_SIGMA_LOOKALIKE_NOT_ATR = dedent(
    """\
    title: "A Sigma rule that should not match ATR"
    id: 0c5a0e07-4f80-4cf3-b1c3-7e8a9f12345
    status: stable
    logsource:
      category: process_creation
      product: linux
    detection:
      selection:
        Image|endswith: '/cat'
      condition: selection
    """
)


# -------------------------------------------------------------------------
#                                Tests
# -------------------------------------------------------------------------


@pytest.fixture(scope="module")
def atr() -> ATRRule:
    return ATRRule()


def test_format_identifier(atr: ATRRule) -> None:
    assert atr.format == "atr"
    assert atr.get_class() == "ATRRule"


# ---- detect() ------------------------------------------------------------


def test_detect_matches_canonical_atr_rule(atr: ATRRule) -> None:
    assert atr.detect(_VALID_ATR_RULE) is True


def test_detect_matches_when_only_agent_source_present(atr: ATRRule) -> None:
    sample = dedent(
        """\
        title: "Some rule"
        agent_source:
          type: tool_call
        """
    )
    assert atr.detect(sample) is True


def test_detect_matches_when_only_category_present(atr: ATRRule) -> None:
    sample = dedent(
        """\
        title: "Some rule"
        tags:
          category: prompt-injection
        """
    )
    assert atr.detect(sample) is True


def test_detect_rejects_sigma_lookalike(atr: ATRRule) -> None:
    assert atr.detect(_SIGMA_LOOKALIKE_NOT_ATR) is False


def test_detect_rejects_non_yaml(atr: ATRRule) -> None:
    assert atr.detect("not: : yaml: :") is False


def test_detect_rejects_non_mapping_yaml(atr: ATRRule) -> None:
    assert atr.detect("- just\n- a\n- list\n") is False


# ---- validate() ----------------------------------------------------------


def test_validate_accepts_canonical_atr_rule(atr: ATRRule) -> None:
    result = atr.validate(_VALID_ATR_RULE)
    assert isinstance(result, ValidationResult)
    assert result.ok is True, result.errors
    assert result.errors == []
    assert result.normalized_content == _VALID_ATR_RULE


def test_validate_accepts_current_agent_source_types(atr: ATRRule) -> None:
    # These agent_source.type values are all in the current ATR schema enum.
    # mcp_exchange in particular backs the largest share of upstream rules,
    # so rejecting it here silently dropped most of the ruleset on import.
    for source_type in ("mcp_exchange", "multi_agent_comm", "agent_trace", "memory_access"):
        rule = _VALID_ATR_RULE.replace("type: llm_io", f"type: {source_type}")
        result = atr.validate(rule)
        assert result.ok is True, (source_type, result.errors)


def test_validate_rejects_bad_id(atr: ATRRule) -> None:
    result = atr.validate(_INVALID_ATR_BAD_ID)
    assert result.ok is False
    assert any("ATR-YYYY-NNNNN" in e for e in result.errors)


def test_validate_rejects_unknown_category(atr: ATRRule) -> None:
    result = atr.validate(_INVALID_ATR_BAD_CATEGORY)
    assert result.ok is False
    assert any("not-a-real-category" in e for e in result.errors)


def test_validate_rejects_unknown_severity(atr: ATRRule) -> None:
    result = atr.validate(_INVALID_ATR_BAD_SEVERITY)
    assert result.ok is False
    assert any("catastrophic" in e for e in result.errors)


def test_validate_rejects_missing_detection(atr: ATRRule) -> None:
    result = atr.validate(_INVALID_ATR_MISSING_DETECTION)
    assert result.ok is False
    assert any("detection" in e for e in result.errors)


def test_validate_rejects_empty_conditions(atr: ATRRule) -> None:
    result = atr.validate(_INVALID_ATR_EMPTY_CONDITIONS)
    assert result.ok is False
    assert any("non-empty" in e for e in result.errors)


def test_validate_rejects_empty_yaml(atr: ATRRule) -> None:
    result = atr.validate("")
    assert result.ok is False
    assert any("Empty" in e for e in result.errors)


def test_validate_rejects_yaml_parse_error(atr: ATRRule) -> None:
    result = atr.validate("title: : :\n: :")
    assert result.ok is False
    assert any("YAML parse" in e for e in result.errors)


# ---- parse_metadata() ----------------------------------------------------


def test_parse_metadata_prefers_explicit_cve_list(atr: ATRRule) -> None:
    meta = atr.parse_metadata(_VALID_ATR_RULE, info={"repo_url": "https://example/repo"})
    assert meta["format"] == "atr"
    assert meta["title"] == "Direct Prompt Injection via User Input"
    assert meta["severity"] == "high"
    assert meta["original_uuid"] == "ATR-2026-00001"
    assert meta["author"] == "ATR Community"
    assert meta["license"] == "MIT"
    assert meta["source"] == "https://example/repo"
    cves = json.loads(meta["cve_id"])
    assert "CVE-2024-5184" in cves
    assert "CVE-2024-3402" in cves


def test_parse_metadata_falls_back_to_description_scan(atr: ATRRule) -> None:
    meta = atr.parse_metadata(_VALID_ATR_RULE_CVE_VIA_DESCRIPTION)
    cves = json.loads(meta["cve_id"])
    assert "CVE-2024-21552" in cves


def test_parse_metadata_flattens_tags(atr: ATRRule) -> None:
    meta = atr.parse_metadata(_VALID_ATR_RULE)
    assert "category:prompt-injection" in meta["tags"]
    assert "confidence:high" in meta["tags"]


def test_parse_metadata_returns_safe_shape_on_parse_error(atr: ATRRule) -> None:
    meta = atr.parse_metadata("title: : :\n: :", info={"repo_url": "x"})
    assert meta["format"] == "atr"
    assert "Metadata Error" in meta["title"]
    assert meta["cve_id"] == []
    assert meta["to_string"]  # always preserves raw input


# ---- get_rule_files() ----------------------------------------------------


def test_get_rule_files_accepts_yaml_extensions(atr: ATRRule) -> None:
    assert atr.get_rule_files("rules/foo.yaml") is True
    assert atr.get_rule_files("rules/foo.yml") is True


def test_get_rule_files_rejects_other_extensions(atr: ATRRule) -> None:
    assert atr.get_rule_files("rules/foo.txt") is False
    assert atr.get_rule_files("rules/foo.json") is False


# ---- extract_rules_from_file() -------------------------------------------


def test_extract_rules_from_single_rule_file(atr: ATRRule, tmp_path) -> None:
    p = tmp_path / "rule.yaml"
    p.write_text(_VALID_ATR_RULE, encoding="utf-8")
    rules = atr.extract_rules_from_file(str(p))
    assert len(rules) == 1
    # Single-rule files return raw content verbatim — quoting preserved.
    assert rules[0] == _VALID_ATR_RULE


def test_extract_rules_from_non_atr_yaml_is_empty(atr: ATRRule, tmp_path) -> None:
    p = tmp_path / "sigma.yaml"
    p.write_text(_SIGMA_LOOKALIKE_NOT_ATR, encoding="utf-8")
    rules = atr.extract_rules_from_file(str(p))
    assert rules == []


def test_extract_rules_from_multi_doc_yaml(atr: ATRRule, tmp_path) -> None:
    p = tmp_path / "multi.yaml"
    p.write_text(f"{_VALID_ATR_RULE}\n---\n{_VALID_ATR_RULE_CVE_VIA_DESCRIPTION}\n", encoding="utf-8")
    rules = atr.extract_rules_from_file(str(p))
    assert len(rules) == 2
