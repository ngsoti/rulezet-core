"""
Unit tests for the Suricata format validator's suppression-risk detection
(app/features/rule/rule_format/available_format/suricata_format.py).

Internal ref A3: a Suricata rule using the 'pass' action or the 'bypass'
keyword silences the engine for matching traffic without referencing the
rule it overrides. Combined with a hash transform (to_sha256/to_md5/
to_sha1) on a pass/drop/bypass rule, it can be used to silently suppress
detection for one specific hashed value — that combination is rejected
outright rather than just flagged.

Internal ref A2 (single-rule part): flowbits/xbits/hostbits exist purely
for cross-rule signalling, so a rule that unsets a bit it never sets
itself has no legitimate single-source justification.
"""
from __future__ import annotations

from app.features.rule.rule_format.available_format.suricata_format import (
    SuricataRule,
    detect_suppression_risk,
    detect_unset_without_set_risk,
)


def test_a3_pass_action_is_flagged():
    """A plain 'pass' rule is flagged as a suppression risk but not rejected."""
    rule = 'pass tcp any any -> any any (msg:"t"; sid:1; rev:1;)'
    risk = detect_suppression_risk(rule)
    assert risk['flagged'] is True
    assert risk['rejected'] is False
    assert any('pass' in reason for reason in risk['reasons'])


def test_a3_bypass_keyword_is_flagged():
    """A rule using the 'bypass' keyword is flagged as a suppression risk but not rejected."""
    rule = 'alert tcp any any -> any any (msg:"t"; bypass; sid:2; rev:1;)'
    risk = detect_suppression_risk(rule)
    assert risk['flagged'] is True
    assert risk['rejected'] is False
    assert any('bypass' in reason for reason in risk['reasons'])


def test_a3_hashed_target_in_pass_rule_is_rejected():
    """A hash transform combined with a 'pass' rule is rejected, not just flagged."""
    rule = (
        'pass tcp any any -> any any '
        '(msg:"t"; content:"x"; to_sha256; dataset:isset,d,type string; sid:3; rev:1;)'
    )
    risk = detect_suppression_risk(rule)
    assert risk['rejected'] is True
    assert any('hash transform' in reason for reason in risk['reasons'])

    result = SuricataRule().validate(rule)
    assert result.ok is False
    assert any('hash transform' in e for e in result.errors)


def test_a3_hashed_target_in_bypass_rule_is_rejected():
    """A hash transform combined with the 'bypass' keyword is rejected too."""
    rule = (
        'alert tcp any any -> any any '
        '(msg:"t"; content:"x"; to_md5; bypass; dataset:isset,d,type string; sid:4; rev:1;)'
    )
    risk = detect_suppression_risk(rule)
    assert risk['rejected'] is True


def test_a3_normal_alert_rule_is_not_flagged():
    """An ordinary alert rule with no suppression keywords is not flagged (regression check)."""
    rule = 'alert tcp any any -> any any (msg:"t"; content:"x"; sid:5; rev:1;)'
    risk = detect_suppression_risk(rule)
    assert risk['flagged'] is False
    assert risk['rejected'] is False
    assert risk['reasons'] == []

    result = SuricataRule().validate(rule)
    assert result.ok is True
    assert result.warnings == []


def test_a3_hash_transform_without_suppressing_action_is_not_rejected():
    """A hash transform on an ordinary 'alert' rule is not the suppression pattern — not rejected."""
    rule = 'alert tcp any any -> any any (msg:"t"; content:"x"; to_sha256; sid:6; rev:1;)'
    risk = detect_suppression_risk(rule)
    assert risk['rejected'] is False


def test_a2_unset_without_set_is_flagged():
    """A flowbit/xbit/hostbit 'unset' with no matching 'set' in the same rule is flagged."""
    flowbit_rule = 'alert tcp any any -> any any (msg:"t"; flowbits:unset,bar; sid:7; rev:1;)'
    risk = detect_unset_without_set_risk(flowbit_rule)
    assert risk['flagged'] is True
    assert any('flowbits:unset,bar' in reason for reason in risk['reasons'])

    xbit_rule = 'alert tcp any any -> any any (msg:"t"; xbits:unset,otherx,track ip_src; sid:8; rev:1;)'
    assert detect_unset_without_set_risk(xbit_rule)['flagged'] is True

    hostbit_rule = 'alert tcp any any -> any any (msg:"t"; hostbits:unset,otherh; sid:9; rev:1;)'
    assert detect_unset_without_set_risk(hostbit_rule)['flagged'] is True

    result = SuricataRule().validate(flowbit_rule)
    assert result.ok is True
    assert any('flowbits:unset,bar' in w for w in result.warnings)


def test_a2_unset_with_matching_set_is_not_flagged():
    """A rule that sets and unsets its own bit is legitimate self-management — not flagged."""
    rule = 'alert tcp any any -> any any (msg:"t"; flowbits:set,bar; flowbits:unset,bar; sid:10; rev:1;)'
    risk = detect_unset_without_set_risk(rule)
    assert risk['flagged'] is False
    assert risk['reasons'] == []

    result = SuricataRule().validate(rule)
    assert result.ok is True
    assert result.warnings == []
