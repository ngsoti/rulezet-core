"""
Unit tests for the rule quality score engine
(app/features/rule/rule_quality/quality_score_core.py).

Each test builds its own Rule row directly (not the shared create_rule_test()
seed) so criteria can be exercised in isolation.
"""
import datetime
import uuid

from app import db
from app.core.db_class.db import (
    AttackTechnique,
    Rule,
    RuleAttackAssociation,
    RuleTagAssociation,
    RuleUpdateHistory,
    Tag,
    User,
)
from app.features.rule.rule_quality.quality_score_core import (
    compute_engagement_boost,
    compute_quality_score,
    recompute_rule_quality_score,
    refresh_engagement_boost,
)

_VALID_SIGMA = """title: Test Rule
id: 12345678-1234-1234-1234-123456789012
status: test
description: A sufficiently long description explaining what this rule detects and why.
author: Test Author
license: MIT
references:
    - https://example.com
falsepositives:
    - Unlikely
level: medium
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\cmd.exe'
    condition: selection
"""

_INVALID_SIGMA = "not: a valid sigma rule\njust: some yaml\n"


def _make_rule(**overrides):
    editor = User.query.filter_by(email="t@t.t").first()
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    defaults = dict(
        format="yara",
        title=f"quality-test-{uuid.uuid4().hex[:8]}",
        license="unknown",
        description="",
        uuid=str(uuid.uuid4()),
        original_uuid=None,
        source=None,
        author="Unknown",
        version="1.0",
        user_id=editor.id,
        creation_date=now,
        last_modif=now,
        vote_up=0,
        vote_down=0,
        to_string="",
        github_path=None,
    )
    defaults.update(overrides)
    rule = Rule(**defaults)
    db.session.add(rule)
    db.session.commit()
    return rule


def test_bare_rule_scores_low_and_reports_missing_criteria(app):
    with app.app_context():
        rule = _make_rule()
        score, breakdown = compute_quality_score(rule)

        assert score < 30
        cats = breakdown["categories"]
        assert cats["traceability"]["checks"]["has_original_uuid"] is False
        assert cats["traceability"]["checks"]["has_source"] is False
        assert cats["authorship"]["checks"]["has_description"] is False
        assert cats["authorship"]["checks"]["has_author"] is False
        # engagement is reported separately, never folded into the base score
        assert breakdown["base_score"] == score
        assert "engagement_boost" in breakdown


def test_well_documented_sigma_rule_scores_high(app):
    with app.app_context():
        rule = _make_rule(
            format="sigma",
            description="A sufficiently long description explaining what this rule detects and why.",
            author="Test Author",
            license="MIT",
            original_uuid="12345678-1234-1234-1234-123456789012",
            source="https://github.com/example/rules",
            github_path="rules/test.yml",
            to_string=_VALID_SIGMA,
        )
        # meaningful tag (not tlp:/pap:)
        editor = User.query.filter_by(email="t@t.t").first()
        tag = Tag(uuid=str(uuid.uuid4()), name="test-tag", is_active=True, visibility="public", created_by=editor.id)
        db.session.add(tag)
        db.session.commit()
        db.session.add(RuleTagAssociation(uuid=str(uuid.uuid4()), rule_id=rule.id, tag_id=tag.id,
                                           user_id=editor.id,
                                           added_at=datetime.datetime.now(tz=datetime.timezone.utc)))
        # ATT&CK mapping (sigma is in _ATTACK_APPLICABLE_FORMATS)
        tech = AttackTechnique(technique_id="T1059", name="Command and Scripting Interpreter")
        db.session.add(tech)
        db.session.commit()
        db.session.add(RuleAttackAssociation(uuid=str(uuid.uuid4()), rule_id=rule.id,
                                              technique_id="T1059", source="manual"))
        db.session.commit()

        score, breakdown = compute_quality_score(rule)

        assert score >= 85
        cats = breakdown["categories"]
        assert cats["metadata"]["checks"]["has_attack_mapping"] is True
        assert cats["metadata"]["checks"]["has_meaningful_tags"] is True
        assert cats["metadata"]["checks"]["format:documents_falsepositives"] is True
        assert cats["validity"]["checks"]["passes_validation"] is True


def test_attack_mapping_not_penalized_for_formats_where_it_is_not_idiomatic(app):
    with app.app_context():
        rule = _make_rule(format="yara", to_string="rule t { condition: true }")
        _, breakdown = compute_quality_score(rule)
        assert "has_attack_mapping" not in breakdown["categories"]["metadata"]["checks"]


def test_invalid_rule_content_fails_validity_criterion(app):
    with app.app_context():
        rule = _make_rule(format="sigma", to_string=_INVALID_SIGMA)
        _, breakdown = compute_quality_score(rule)
        assert breakdown["categories"]["validity"]["checks"]["passes_validation"] is False


def test_pending_failed_github_update_penalizes_validity(app):
    with app.app_context():
        rule = _make_rule(format="sigma", to_string=_VALID_SIGMA)
        editor = User.query.filter_by(email="t@t.t").first()
        db.session.add(RuleUpdateHistory(
            rule_id=rule.id, rule_title=rule.title, success=False, message="rejected",
            analyzed_by_user_id=editor.id,
            analyzed_at=datetime.datetime.now(tz=datetime.timezone.utc),
        ))
        db.session.commit()
        _, breakdown = compute_quality_score(rule)
        assert breakdown["categories"]["validity"]["checks"]["no_pending_failed_update"] is False


def test_sigma_documentation_signals():
    from app.features.rule.rule_format.available_format.sigma_format import SigmaRule
    signals = SigmaRule().documentation_signals(_VALID_SIGMA)
    assert signals["documents_references"] is True
    assert signals["documents_falsepositives"] is True
    assert signals["documents_severity_level"] is True
    assert signals["documents_taxonomy_tags"] is True


def test_yara_documentation_signals():
    from app.features.rule.rule_format.available_format.yara_format import YaraRule
    content = '''
rule test {
    meta:
        author = "someone"
        date = "2024-01-01"
        description = "does a thing"
    condition:
        true
}
'''
    signals = YaraRule().documentation_signals(content)
    assert signals["has_date"] is True
    assert signals["has_reference"] is False
    assert signals["has_description"] is True


def test_suricata_documentation_signals():
    from app.features.rule.rule_format.available_format.suricata_format import SuricataRule
    content = 'alert tcp any any -> any any (msg:"test"; classtype:trojan-activity; reference:url,example.com; sid:1; rev:1;)'
    signals = SuricataRule().documentation_signals(content)
    assert signals["has_reference"] is True
    assert signals["has_classtype"] is True
    assert signals["has_metadata"] is False


def test_format_without_override_returns_empty_and_does_not_crash(app):
    with app.app_context():
        # nova/crs/etc don't override documentation_signals -> base class {} default
        rule = _make_rule(format="crs", to_string="SecRule ARGS \"@rx test\" \"id:1\"")
        score, breakdown = compute_quality_score(rule)
        assert isinstance(score, float)
        # no format: keys added since the format returned no signals
        assert not any(k.startswith("format:") for k in breakdown["categories"]["metadata"]["checks"])


def test_recompute_rule_quality_score_persists_fields(app):
    with app.app_context():
        rule = _make_rule()
        assert rule.quality_score is None
        score = recompute_rule_quality_score(rule)
        assert rule.quality_score == score
        assert rule.quality_score_breakdown is not None
        assert rule.quality_score_computed_at is not None


def test_refresh_engagement_boost_only_touches_boost(app):
    with app.app_context():
        rule = _make_rule(format="sigma", to_string=_VALID_SIGMA)
        recompute_rule_quality_score(rule)
        base_before = rule.quality_score
        checks_before = rule.quality_score_breakdown["categories"]["authorship"]["checks"]

        rule.vote_up = 10
        db.session.commit()
        refresh_engagement_boost(rule)

        assert rule.quality_score == base_before  # base score untouched by votes
        assert rule.quality_score_breakdown["categories"]["authorship"]["checks"] == checks_before
        assert rule.quality_score_breakdown["engagement_boost"] > 0


def test_engagement_boost_capped_and_never_negative(app):
    with app.app_context():
        rule = _make_rule()
        rule.vote_up = 100000
        db.session.commit()
        boost = compute_engagement_boost(rule)
        assert 0 <= boost <= 10
