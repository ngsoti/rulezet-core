"""
Unit tests for the Splunk Security Content ("ESCU") format adapter.

The adapter mirrors the contract documented in
`app/features/rule/rule_format/abstract_rule_type/rule_type_abstract.py`
and is structured to match the existing `atr_format`/`sigma_format`
adapters for consistency.
"""
from __future__ import annotations

import json
from textwrap import dedent

import pytest

from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import ValidationResult
from app.features.rule.rule_format.available_format.splunk_format import SplunkRule


# -------------------------------------------------------------------------
#                           Sample rule fixtures
# -------------------------------------------------------------------------

_VALID_TTP_RULE = dedent(
    """\
    name: TOR Traffic
    id: ea688274-9c06-4473-b951-e4cb7a5d7a45
    version: 17
    creation_date: '2019-10-16'
    modification_date: '2026-05-13'
    author: David Dorsey, Bhavin Patel, Splunk
    status: production
    type: TTP
    description: The following analytic identifies allowed network traffic to The Onion Router (TOR).
    data_source:
        - Palo Alto Network Traffic
    search: |-
        | tstats `security_content_summariesonly` count FROM datamodel=Network_Traffic WHERE All_Traffic.app=tor
        | `tor_traffic_filter`
    how_to_implement: Splunk needs to ingest data from Next Generation Firewalls.
    known_false_positives: No false positives have been identified at this time.
    references:
        - https://unit42.paloaltonetworks.com/tor-traffic-enterprise-networks/
    finding:
        title: Suspicious network traffic allowed using TOR has been detected from $src_ip$ to $dest_ip$
        entity:
            field: src_ip
            type: system
            score: 50
    analytic_story:
        - Command And Control
    asset_type: Endpoint
    mitre_attack_id:
        - T1090.003
    product:
        - Splunk Enterprise
        - Splunk Enterprise Security
        - Splunk Cloud
    category: network
    security_domain: network
    """
)

_VALID_ANOMALY_RULE = dedent(
    """\
    name: Detect S3 access from a new IP
    id: e6f1bb1b-f441-492b-9126-902acda217da
    version: 8
    status: experimental
    type: Anomaly
    description: Detects S3 bucket access from an IP address not previously seen.
    data_source: []
    search: |-
        `aws_s3_accesslogs` http_status=200 | `detect_s3_access_from_a_new_ip_filter`
    how_to_implement: Requires AWS S3 access logs.
    known_false_positives: A new IP address may be legitimate.
    intermediate_findings:
        entities:
            - field: bucketName
              type: other
              score: 20
              message: New S3 access from a new IP - $src_ip$
    analytic_story:
        - Suspicious AWS S3 Activities
    asset_type: S3 Bucket
    mitre_attack_id:
        - T1530
    category: cloud
    security_domain: network
    """
)

_INVALID_MISSING_SEARCH = dedent(
    """\
    name: Broken rule
    id: 11111111-1111-1111-1111-111111111111
    status: production
    type: TTP
    description: Missing the search field entirely.
    how_to_implement: n/a
    known_false_positives: n/a
    analytic_story:
        - Some Story
    mitre_attack_id:
        - T1003
    category: endpoint
    security_domain: endpoint
    """
)

_INVALID_BAD_STATUS = dedent(
    """\
    name: Bad status
    id: 22222222-2222-2222-2222-222222222222
    status: retired
    type: TTP
    description: d
    search: index=foo
    how_to_implement: n/a
    known_false_positives: n/a
    analytic_story:
        - Some Story
    category: endpoint
    security_domain: endpoint
    """
)

_INVALID_BAD_TYPE_AND_CATEGORY = dedent(
    """\
    name: Bad type and category
    id: 33333333-3333-3333-3333-333333333333
    status: production
    type: NotARealType
    description: d
    search: index=foo
    how_to_implement: n/a
    known_false_positives: n/a
    category: not-a-real-category
    security_domain: endpoint
    """
)

_SIGMA_LOOKALIKE_NOT_SPLUNK = dedent(
    """\
    title: "A Sigma rule that should not match Splunk"
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

_ATR_LOOKALIKE_NOT_SPLUNK = dedent(
    """\
    id: ATR-2026-00001
    title: "Direct Prompt Injection via User Input"
    severity: high
    tags:
      category: prompt-injection
    agent_source:
      type: llm_io
    detection:
      condition: any
      conditions:
        - field: user_input
          operator: regex
          value: 'ignore previous instructions'
    """
)


# -------------------------------------------------------------------------
#                                Tests
# -------------------------------------------------------------------------


@pytest.fixture(scope="module")
def splunk() -> SplunkRule:
    return SplunkRule()


def test_format_identifier(splunk: SplunkRule) -> None:
    assert splunk.format == "splunk"
    assert splunk.get_class() == "SplunkRule"


# ---- detect() --------------------------------------------------------------


def test_detect_matches_ttp_rule(splunk: SplunkRule) -> None:
    assert splunk.detect(_VALID_TTP_RULE) is True


def test_detect_matches_anomaly_rule(splunk: SplunkRule) -> None:
    assert splunk.detect(_VALID_ANOMALY_RULE) is True


def test_detect_rejects_sigma_lookalike(splunk: SplunkRule) -> None:
    assert splunk.detect(_SIGMA_LOOKALIKE_NOT_SPLUNK) is False


def test_detect_rejects_atr_lookalike(splunk: SplunkRule) -> None:
    assert splunk.detect(_ATR_LOOKALIKE_NOT_SPLUNK) is False


def test_detect_rejects_non_yaml(splunk: SplunkRule) -> None:
    assert splunk.detect("not: : yaml: :") is False


def test_detect_rejects_non_mapping_yaml(splunk: SplunkRule) -> None:
    assert splunk.detect("- just\n- a\n- list\n") is False


# ---- cross-format isolation (the whole point of sharing .yml/.yaml) --------


def test_sigma_does_not_detect_splunk_rule() -> None:
    from app.features.rule.rule_format.available_format.sigma_format import SigmaRule
    assert SigmaRule().detect(_VALID_TTP_RULE) is False


def test_atr_does_not_detect_splunk_rule() -> None:
    from app.features.rule.rule_format.available_format.atr_format import ATRRule
    assert ATRRule().detect(_VALID_TTP_RULE) is False


# ---- validate() -------------------------------------------------------------


def test_validate_accepts_ttp_rule(splunk: SplunkRule) -> None:
    result = splunk.validate(_VALID_TTP_RULE)
    assert isinstance(result, ValidationResult)
    assert result.ok is True, result.errors
    assert result.errors == []
    assert result.normalized_content == _VALID_TTP_RULE


def test_validate_accepts_anomaly_rule(splunk: SplunkRule) -> None:
    result = splunk.validate(_VALID_ANOMALY_RULE)
    assert result.ok is True, result.errors


def test_validate_rejects_missing_search(splunk: SplunkRule) -> None:
    result = splunk.validate(_INVALID_MISSING_SEARCH)
    assert result.ok is False
    assert any("search" in e for e in result.errors)


def test_validate_rejects_unknown_status(splunk: SplunkRule) -> None:
    result = splunk.validate(_INVALID_BAD_STATUS)
    assert result.ok is False
    assert any("retired" in e for e in result.errors)


def test_validate_rejects_unknown_type_and_category(splunk: SplunkRule) -> None:
    result = splunk.validate(_INVALID_BAD_TYPE_AND_CATEGORY)
    assert result.ok is False
    assert any("NotARealType" in e for e in result.errors)
    assert any("not-a-real-category" in e for e in result.errors)


def test_validate_rejects_empty_yaml(splunk: SplunkRule) -> None:
    result = splunk.validate("")
    assert result.ok is False
    assert any("Empty" in e for e in result.errors)


def test_validate_rejects_yaml_parse_error(splunk: SplunkRule) -> None:
    result = splunk.validate("name: : :\n: :")
    assert result.ok is False
    assert any("YAML parse" in e for e in result.errors)


def test_validate_warns_but_accepts_missing_analytic_story_and_mitre(splunk: SplunkRule) -> None:
    """analytic_story/mitre_attack_id are Splunk's own dynamic content
    catalog, not part of the generic SPL-detection shape — missing them is
    a warning, not a hard failure (see module docstring)."""
    minimal = dedent(
        """\
        name: Minimal valid rule
        id: 44444444-4444-4444-4444-444444444444
        status: production
        type: Hunting
        description: d
        search: index=foo | stats count
        how_to_implement: n/a
        known_false_positives: n/a
        category: endpoint
        security_domain: endpoint
        """
    )
    result = splunk.validate(minimal)
    assert result.ok is True
    assert any("analytic_story" in w for w in result.warnings)
    assert any("mitre_attack_id" in w for w in result.warnings)


def test_validate_warns_when_ttp_missing_finding_block(splunk: SplunkRule) -> None:
    no_finding = dedent(
        """\
        name: TTP rule with no finding block
        id: 55555555-5555-5555-5555-555555555555
        status: production
        type: TTP
        description: d
        search: index=foo | stats count
        how_to_implement: n/a
        known_false_positives: n/a
        analytic_story:
            - Some Story
        mitre_attack_id:
            - T1003
        category: endpoint
        security_domain: endpoint
        """
    )
    result = splunk.validate(no_finding)
    assert result.ok is True
    assert any("finding" in w for w in result.warnings)


# ---- parse_metadata() -------------------------------------------------------


def test_parse_metadata_basic_fields(splunk: SplunkRule) -> None:
    meta = splunk.parse_metadata(_VALID_TTP_RULE, info={"repo_url": "https://example/repo"})
    assert meta["format"] == "splunk"
    assert meta["title"] == "TOR Traffic"
    assert meta["original_uuid"] == "ea688274-9c06-4473-b951-e4cb7a5d7a45"
    assert meta["author"] == "David Dorsey, Bhavin Patel, Splunk"
    assert meta["version"] == "17"
    assert meta["source"] == "https://example/repo"


def test_parse_metadata_severity_from_finding_score(splunk: SplunkRule) -> None:
    meta = splunk.parse_metadata(_VALID_TTP_RULE)
    assert meta["severity"] == "high"  # score 50 -> high bucket (>=50)


def test_parse_metadata_severity_from_intermediate_findings(splunk: SplunkRule) -> None:
    meta = splunk.parse_metadata(_VALID_ANOMALY_RULE)
    assert meta["severity"] == "medium"  # score 20 -> medium bucket (>=20)


def test_parse_metadata_flattens_tags(splunk: SplunkRule) -> None:
    meta = splunk.parse_metadata(_VALID_TTP_RULE)
    assert "T1090.003" in meta["tags"]
    assert "analytic_story:Command And Control" in meta["tags"]
    assert "asset_type:Endpoint" in meta["tags"]
    assert "security_domain:network" in meta["tags"]
    assert "category:network" in meta["tags"]


def test_parse_metadata_prefers_explicit_cve_list(splunk: SplunkRule) -> None:
    with_cve = _VALID_TTP_RULE + "cve:\n    - CVE-2020-5902\n"
    meta = splunk.parse_metadata(with_cve)
    cves = json.loads(meta["cve_id"])
    assert "CVE-2020-5902" in cves


def test_parse_metadata_falls_back_to_description_scan(splunk: SplunkRule) -> None:
    rule = _VALID_TTP_RULE.replace(
        "description: The following analytic identifies allowed network traffic to The Onion Router (TOR).",
        "description: Detects CVE-2020-5902 exploitation attempts.",
    )
    meta = splunk.parse_metadata(rule)
    cves = json.loads(meta["cve_id"])
    assert "CVE-2020-5902" in cves


def test_parse_metadata_returns_safe_shape_on_parse_error(splunk: SplunkRule) -> None:
    meta = splunk.parse_metadata("name: : :\n: :", info={"repo_url": "x"})
    assert meta["format"] == "splunk"
    assert "Metadata Error" in meta["title"]
    assert meta["cve_id"] == []
    assert meta["to_string"]  # always preserves raw input


# ---- get_rule_files() -------------------------------------------------------


def test_get_rule_files_accepts_yaml_extensions(splunk: SplunkRule) -> None:
    assert splunk.get_rule_files("detections/endpoint/foo.yml") is True
    assert splunk.get_rule_files("detections/endpoint/foo.yaml") is True


def test_get_rule_files_rejects_other_extensions(splunk: SplunkRule) -> None:
    assert splunk.get_rule_files("rules/foo.txt") is False
    assert splunk.get_rule_files("rules/foo.conf") is False


# ---- extract_rules_from_file() ---------------------------------------------


def test_extract_rules_from_single_rule_file(splunk: SplunkRule, tmp_path) -> None:
    p = tmp_path / "tor_traffic.yml"
    p.write_text(_VALID_TTP_RULE, encoding="utf-8")
    rules = splunk.extract_rules_from_file(str(p))
    assert len(rules) == 1
    # Single-rule files return raw content verbatim — quoting/formatting preserved.
    assert rules[0] == _VALID_TTP_RULE


def test_extract_rules_from_non_splunk_yaml_is_empty(splunk: SplunkRule, tmp_path) -> None:
    p = tmp_path / "sigma.yml"
    p.write_text(_SIGMA_LOOKALIKE_NOT_SPLUNK, encoding="utf-8")
    rules = splunk.extract_rules_from_file(str(p))
    assert rules == []


def test_extract_rules_from_multi_doc_yaml(splunk: SplunkRule, tmp_path) -> None:
    p = tmp_path / "multi.yml"
    p.write_text(f"{_VALID_TTP_RULE}\n---\n{_VALID_ANOMALY_RULE}\n", encoding="utf-8")
    rules = splunk.extract_rules_from_file(str(p))
    assert len(rules) == 2
