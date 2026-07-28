"""
Unit tests for the Velociraptor artifact exporter
(app/features/rule/exporters/velociraptor_exporter.py).

Pure-function module — no Flask/DB context needed, so rules are represented
by lightweight fakes rather than the real SQLAlchemy model.
"""
from __future__ import annotations

import yaml
import pytest

from app.features.rule.exporters.velociraptor_exporter import (
    generate_velociraptor_artifact,
    SUPPORTED_FORMATS,
)


class _FakeTag:
    def __init__(self, name):
        self.name = name


class _FakeTagAssoc:
    def __init__(self, name):
        self.tag = _FakeTag(name)


class _FakeRule:
    def __init__(self, format, to_string, title="Test Rule", uuid="abc-123",
                 author="Alice", tags=None):
        self.format = format
        self.to_string = to_string
        self.title = title
        self.uuid = uuid
        self.author = author
        self.rule_tags_assocs = [_FakeTagAssoc(t) for t in (tags or [])]


def test_unsupported_format_raises_value_error():
    rule = _FakeRule("suricata", 'alert tcp any any -> any any (msg:"x"; sid:1;)')
    with pytest.raises(ValueError):
        generate_velociraptor_artifact(rule)


def test_supported_formats_are_yara_and_sigma():
    assert set(SUPPORTED_FORMATS) == {"yara", "sigma"}


def test_yara_artifact_has_no_double_from_clause():
    """Regression test: ProcessScan used to chain two FROMs on one SELECT,
    which Velociraptor's VQL parser rejects outright."""
    rule = _FakeRule("yara", "rule test { condition: true }")
    parsed = yaml.safe_load(generate_velociraptor_artifact(rule))

    process_query = next(s["query"] for s in parsed["sources"] if s["name"] == "ProcessScan")
    assert process_query.count("SELECT") == process_query.count("FROM")
    assert "foreach(" in process_query


def test_yara_disk_scan_uses_configurable_target_glob():
    rule = _FakeRule("yara", "rule test { condition: true }")
    parsed = yaml.safe_load(generate_velociraptor_artifact(rule))

    disk_query = next(s["query"] for s in parsed["sources"] if s["name"] == "DiskScan")
    assert "TargetGlob" in disk_query
    assert "C:/**" not in disk_query
    assert any(p["name"] == "TargetGlob" for p in parsed["parameters"])


def test_yara_artifact_name_and_metadata():
    rule = _FakeRule("yara", "rule test { condition: true }", title="Win Backdoor",
                      tags=["tlp:clear", "malware"])
    parsed = yaml.safe_load(generate_velociraptor_artifact(rule))

    assert parsed["name"] == "Rulezet.Detection.YARA.WinBackdoor"
    assert parsed["type"] == "CLIENT"
    assert "abc-123" in parsed["description"]
    assert "tlp:clear, malware" in parsed["description"]


def test_sigma_process_creation_maps_to_known_etw_source():
    rule = _FakeRule("sigma", "title: t\nlogsource:\n  category: process_creation\n"
                               "detection:\n  condition: true\n")
    parsed = yaml.safe_load(generate_velociraptor_artifact(rule))

    assert "windows/process_creation" in parsed["sources"][0]["query"]
    assert "⚠" not in parsed["description"]


def test_sigma_unmapped_category_is_flagged_not_silently_wrong():
    """Regression test: every Sigma rule used to get the process_creation ETW
    source regardless of its actual logsource — a network/file/registry rule
    would get an artifact that structurally can't match its own events."""
    rule = _FakeRule("sigma", "title: t\nlogsource:\n  category: network_connection\n"
                               "detection:\n  condition: true\n")
    parsed = yaml.safe_load(generate_velociraptor_artifact(rule))

    assert "⚠" in parsed["description"]
    assert "network_connection" in parsed["description"]
    assert "network_connection" in parsed["sources"][0]["query"]
    assert "REPLACE_WITH_CORRECT_ETW_GUID" in parsed["sources"][0]["query"]


def test_sigma_artifact_type_is_client_event():
    rule = _FakeRule("sigma", "title: t\nlogsource:\n  category: process_creation\n"
                               "detection:\n  condition: true\n")
    parsed = yaml.safe_load(generate_velociraptor_artifact(rule))
    assert parsed["type"] == "CLIENT_EVENT"


def test_sigma_malicious_category_cannot_inject_vql():
    """Security regression test: logsource.category is parsed straight out of
    the rule's own (attacker-controlled) content. A category crafted with a
    backtick + `={...}` sequence used to splice arbitrary VQL — including
    exec-capable plugins — into the generated artifact's real query, to be
    run against every endpoint the artifact is later deployed to."""
    payload = 'x`={SELECT execve(argv=["id"]) FROM scope() WHERE 1} fake'
    rule = _FakeRule("sigma", f'title: t\nlogsource:\n  category: |-\n    {payload}\n'
                               "detection:\n  condition: true\n")
    parsed = yaml.safe_load(generate_velociraptor_artifact(rule))
    query = parsed["sources"][0]["query"]

    assert "execve(" not in query  # the identifier may still contain the slugified word "execve", that's fine — it's inert text now, not a call
    assert query.count("`={") == 1  # exactly the one legitimate `windows/<cat>`={ opener, no breakout
    # the raw payload is still visible in the (inert, non-VQL) description for the admin's info
    assert payload in parsed["description"]
