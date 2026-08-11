"""
Unit tests for the Wazuh format validator's overwrite="yes" detection
(app/features/rule/rule_format/available_format/wazuh_format.py).

Internal ref A7: a Wazuh rule with overwrite="yes" replaces another rule
with the same id in the ruleset instead of adding a new one, which can
silently take over a rule that belongs to a different source.
"""
from __future__ import annotations

from app.features.rule.rule_format.available_format.wazuh_format import (
    WazuhRule,
    detect_overwrite_risk,
)


def test_a7_overwrite_yes_is_flagged():
    """A <rule> with overwrite="yes" is flagged."""
    rule = '<rule id="100001" level="5" overwrite="yes"><description>test</description></rule>'
    risk = detect_overwrite_risk(rule)
    assert risk['flagged'] is True
    assert any('overwrite="yes"' in reason for reason in risk['reasons'])

    result = WazuhRule().validate(rule)
    assert result.ok is True
    assert any('overwrite="yes"' in w for w in result.warnings)


def test_a7_normal_rule_is_not_flagged():
    """An ordinary Wazuh rule with no overwrite attribute is not flagged (regression check)."""
    rule = '<rule id="100002" level="5"><description>normal</description></rule>'
    risk = detect_overwrite_risk(rule)
    assert risk['flagged'] is False
    assert risk['reasons'] == []

    result = WazuhRule().validate(rule)
    assert result.ok is True
    assert result.warnings == []


def test_a7_overwrite_no_is_not_flagged():
    """overwrite="no" is the explicit non-risky value and must not be flagged."""
    rule = '<rule id="100003" level="5" overwrite="no"><description>normal</description></rule>'
    risk = detect_overwrite_risk(rule)
    assert risk['flagged'] is False
