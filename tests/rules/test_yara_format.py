"""
Unit tests for the YARA format validator's 'global rule' detection
(app/features/rule/rule_format/available_format/yara_format.py).

Internal ref A6: a 'global rule' declaration has its condition implicitly
ANDed into every other rule compiled in the same YARA namespace, so a
'global rule { condition: false }' can silently suppress every other
rule compiled alongside it. It compiles fine on its own (no syntax
error), so this can only be caught by an explicit content check, not by
yara.compile() alone.
"""
from __future__ import annotations

from app.features.rule.rule_format.available_format.yara_format import (
    YaraRule,
    detect_global_rule_risk,
)


def test_a6_global_rule_is_flagged():
    """A plain 'global rule' declaration is flagged."""
    risk = detect_global_rule_risk('global rule test { condition: false }')
    assert risk['flagged'] is True
    assert any('global rule' in reason for reason in risk['reasons'])

    result = YaraRule().validate('global rule test { condition: false }')
    assert result.ok is True
    assert any('global rule' in w for w in result.warnings)


def test_a6_private_global_rule_is_flagged():
    """'global' combined with the unrelated 'private' modifier is still flagged."""
    risk = detect_global_rule_risk('private global rule test { condition: false }')
    assert risk['flagged'] is True


def test_a6_normal_rule_is_not_flagged():
    """An ordinary rule with no 'global' modifier is not flagged (regression check)."""
    risk = detect_global_rule_risk('rule test { condition: true }')
    assert risk['flagged'] is False
    assert risk['reasons'] == []

    result = YaraRule().validate('rule test { condition: true }')
    assert result.ok is True
    assert result.warnings == []


def test_a6_private_rule_without_global_is_not_flagged():
    """'private' alone (no 'global') has no cross-namespace suppression risk — not flagged."""
    risk = detect_global_rule_risk('private rule test { condition: false }')
    assert risk['flagged'] is False
