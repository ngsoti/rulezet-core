"""
Unit tests for the CRS/ModSecurity format validator's engine-wide
suppression detection
(app/features/rule/rule_format/available_format/crs_format.py).

Internal ref A5: 'ctl:ruleEngine=Off' disables the ModSecurity engine
entirely for the matching request, silencing every other rule. 'SecMarker'
and 'skipAfter' work together to jump over rules placed between them,
which can bypass rules from other authors — the same engine-wide
suppression power as Suricata's 'pass'/'bypass' (ref A3).
"""
from __future__ import annotations

from app.features.rule.rule_format.available_format.crs_format import (
    CRSRule,
    detect_suppression_risk,
)


def test_a5_ctl_ruleengine_off_is_flagged():
    """A rule using 'ctl:ruleEngine=Off' is flagged."""
    rule = 'SecRule REQUEST_URI "@rx /admin" "id:1001,phase:1,ctl:ruleEngine=Off"'
    risk = detect_suppression_risk(rule)
    assert risk['flagged'] is True
    assert any('ruleEngine=Off' in reason for reason in risk['reasons'])

    result = CRSRule().validate(rule)
    assert result.ok is True
    assert any('ruleEngine=Off' in w for w in result.warnings)


def test_a5_secmarker_skipafter_is_flagged():
    """A 'SecMarker' directive and a 'skipAfter' action are each flagged."""
    marker_risk = detect_suppression_risk('SecMarker "BEGIN-MYMARKER"')
    assert marker_risk['flagged'] is True
    assert any('SecMarker' in reason for reason in marker_risk['reasons'])

    skip_rule = 'SecRule REQUEST_URI "@rx /x" "id:1002,phase:1,skipAfter:BEGIN-MYMARKER"'
    skip_risk = detect_suppression_risk(skip_rule)
    assert skip_risk['flagged'] is True
    assert any('skipAfter' in reason for reason in skip_risk['reasons'])


def test_a5_normal_rule_is_not_flagged():
    """An ordinary CRS rule with none of these directives is not flagged (regression check)."""
    rule = 'SecRule REQUEST_URI "@rx /x" "id:1003,phase:1,deny"'
    risk = detect_suppression_risk(rule)
    assert risk['flagged'] is False
    assert risk['reasons'] == []

    result = CRSRule().validate(rule)
    assert result.ok is True
    assert result.warnings == []
