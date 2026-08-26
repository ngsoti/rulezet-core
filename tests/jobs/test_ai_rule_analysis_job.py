"""
Tests for the 'ai_generate' background job (AI_02_RULE_ANALYSIS.md Phase 1:
Markdown summary generation only, via RuleAnalysisAgent). OllamaClient.chat
is mocked throughout — no real Ollama instance needed.
"""

import json
import uuid
from unittest.mock import patch

from app import db
from app.core.db_class.db import AIGeneration, BackgroundJob, Rule, User
from app.features.jobs.job_handlers import handle_rule_analysis

CHAT = 'app.features.ai.ai_core.OllamaClient.chat'


def _make_job(payload, created_by):
    job = BackgroundJob(
        uuid=str(uuid.uuid4()), created_by=created_by, job_type='ai_generate',
        status='running', payload=payload,
    )
    db.session.add(job)
    db.session.commit()
    return job


def _make_rule(title, user_id, fmt="yara"):
    rule = Rule(
        format=fmt, title=title, license="test", description="test",
        uuid=str(uuid.uuid4()), source="test", author="test", version=1,
        user_id=user_id, to_string="rule test { condition: true }",
    )
    db.session.add(rule)
    db.session.commit()
    return rule


def _envelope(summary):
    return json.dumps({"summary": summary})


def test_generates_analysis_for_targeted_rules(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Rule A", admin.id)
        r2 = _make_rule("Rule B", admin.id)
        # A model that differs from config.py's OLLAMA_MODEL default
        # ('qwen2.5:1.5b') — proves the payload's model actually reaches
        # the agent, not just the log line (AIAgent.run() previously
        # ignored it and always used the config-derived default).
        job = _make_job({'rule_ids': [r1.id, r2.id], 'model': 'qwen2.5:7b'}, admin.id)

        with patch(CHAT, return_value=_envelope("## Overview\nDoes a thing.")):
            handle_rule_analysis(job, app)

        db.session.refresh(job)
        assert job.status != 'failed'
        assert job.done == 2

        gens = AIGeneration.query.filter(AIGeneration.rule_id.in_([r1.id, r2.id])).all()
        assert len(gens) == 2
        assert all(g.content == "## Overview\nDoes a thing." for g in gens)
        assert all(g.agent_key == 'rule_analysis' for g in gens)
        assert all(g.model == 'qwen2.5:7b' for g in gens)


def test_skips_rules_with_existing_analysis_by_default(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Already analyzed", admin.id)
        r2 = _make_rule("Needs analysis", admin.id)
        db.session.add(AIGeneration(
            uuid=str(uuid.uuid4()), agent_key='rule_analysis', rule_id=r1.id,
            user_id=admin.id, content="pre-existing", model="qwen2.5:1.5b",
        ))
        db.session.commit()

        job = _make_job({'rule_ids': [r1.id, r2.id], 'regenerate_existing': False}, admin.id)

        with patch(CHAT, return_value=_envelope("new summary")) as mock_chat:
            handle_rule_analysis(job, app)
            assert mock_chat.call_count == 1

        assert AIGeneration.query.filter_by(rule_id=r1.id).one().content == "pre-existing"
        assert AIGeneration.query.filter_by(rule_id=r2.id).one().content == "new summary"


def test_regenerate_existing_adds_a_new_entry_without_deleting_the_old_one(app):
    # regenerate_existing includes already-analyzed rules in the target set
    # — it must never delete prior AIGeneration rows, since those are the
    # browsable history the rule-detail page's History card shows.
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Rule A", admin.id)
        db.session.add(AIGeneration(
            uuid=str(uuid.uuid4()), agent_key='rule_analysis', rule_id=r1.id,
            user_id=admin.id, content="older analysis", model="qwen2.5:1.5b",
        ))
        db.session.commit()

        job = _make_job({'rule_ids': [r1.id], 'regenerate_existing': True}, admin.id)

        with patch(CHAT, return_value=_envelope("fresh summary")):
            handle_rule_analysis(job, app)

        rows = AIGeneration.query.filter_by(rule_id=r1.id).order_by(AIGeneration.id).all()
        assert len(rows) == 2
        assert rows[0].content == "older analysis"
        assert rows[1].content == "fresh summary"


def test_accepts_filters_shape_from_task_scheduler_rule_list_picker(app):
    # The Admin Task Scheduler's <rule-list mode="select"> target picker
    # (same convention as compute_rule_quality_score) nests rule_ids/format
    # under 'filters' instead of at the payload's top level.
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Rule A", admin.id, fmt="sigma")
        r2 = _make_rule("Rule B", admin.id, fmt="yara")
        job = _make_job({'filters': {'rule_ids': [r1.id, r2.id]}}, admin.id)

        with patch(CHAT, return_value=_envelope("summary")):
            handle_rule_analysis(job, app)

        assert AIGeneration.query.filter(AIGeneration.rule_id.in_([r1.id, r2.id])).count() == 2


def test_accepts_format_filter_from_task_scheduler_filters(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        sigma_rule = _make_rule("Sigma rule", admin.id, fmt="sigma")
        yara_rule  = _make_rule("Yara rule", admin.id, fmt="yara")
        job = _make_job({'filters': {'format': 'sigma'}}, admin.id)

        with patch(CHAT, return_value=_envelope("summary")):
            handle_rule_analysis(job, app)

        assert AIGeneration.query.filter_by(rule_id=sigma_rule.id).count() == 1
        assert AIGeneration.query.filter_by(rule_id=yara_rule.id).count() == 0


def test_batch_size_caps_rules_processed_this_run(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        rules = [_make_rule(f"Rule {i}", admin.id) for i in range(5)]
        job = _make_job({'rule_ids': [r.id for r in rules], 'batch_size': 2}, admin.id)

        with patch(CHAT, return_value=_envelope("summary")):
            handle_rule_analysis(job, app)

        assert job.total == 2
        assert AIGeneration.query.filter(AIGeneration.rule_id.in_([r.id for r in rules])).count() == 2


def test_max_seconds_stops_early_without_failing_the_job(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        rules = [_make_rule(f"Rule {i}", admin.id) for i in range(3)]
        job = _make_job({'rule_ids': [r.id for r in rules], 'max_seconds': 0}, admin.id)

        with patch(CHAT, return_value=_envelope("summary")) as mock_chat:
            handle_rule_analysis(job, app)
            mock_chat.assert_not_called()

        db.session.refresh(job)
        assert job.status != 'failed'
        assert AIGeneration.query.filter(AIGeneration.rule_id.in_([r.id for r in rules])).count() == 0


def test_stops_the_whole_job_on_systemic_failure(app):
    from app.core.db_class.db import AIAgentConfig

    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Rule A", admin.id)
        r2 = _make_rule("Rule B", admin.id)
        db.session.add(AIAgentConfig(agent_key='rule_analysis', enabled=False))
        db.session.commit()

        job = _make_job({'rule_ids': [r1.id, r2.id]}, admin.id)

        with patch(CHAT) as mock_chat:
            handle_rule_analysis(job, app)
            mock_chat.assert_not_called()

        db.session.refresh(job)
        assert job.status == 'failed'
        assert AIGeneration.query.filter(AIGeneration.rule_id.in_([r1.id, r2.id])).count() == 0


def test_per_rule_failure_does_not_stop_the_job(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Rule A", admin.id)
        r2 = _make_rule("Rule B", admin.id)
        job = _make_job({'rule_ids': [r1.id, r2.id]}, admin.id)

        with patch(CHAT, side_effect=["not valid json", _envelope("ok summary")]):
            handle_rule_analysis(job, app)

        db.session.refresh(job)
        assert job.status != 'failed'
        assert AIGeneration.query.filter_by(rule_id=r1.id).count() == 0
        assert AIGeneration.query.filter_by(rule_id=r2.id).one().content == "ok summary"


def test_uses_tags_and_attack_context_in_prompt(app):
    from app.core.db_class.db import AttackTechnique, RuleAttackAssociation, RuleTagAssociation, Tag

    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Rule A", admin.id)

        tag = Tag.query.filter_by(name="tlp:clear").first()
        if tag:
            db.session.add(RuleTagAssociation(rule_id=r1.id, tag_id=tag.id))

        technique = AttackTechnique.query.first()
        if technique:
            db.session.add(RuleAttackAssociation(
                rule_id=r1.id, technique_id=technique.technique_id, source='auto',
            ))
        db.session.commit()

        job = _make_job({'rule_ids': [r1.id]}, admin.id)

        with patch(CHAT, return_value=_envelope("ok")) as mock_chat:
            handle_rule_analysis(job, app)
            sent_messages = mock_chat.call_args[0][0]
            user_content = sent_messages[1]['content']
            if tag:
                assert "tlp:clear" in user_content
            if technique:
                assert technique.technique_id in user_content
