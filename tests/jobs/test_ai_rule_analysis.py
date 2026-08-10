"""
Tests for the ai_rule_analysis background job (Phase 1 of
AI_RULE_ANALYSIS_PLAN.md — Markdown summary generation only) and its
supporting core module.
"""

import uuid
from unittest.mock import patch

from app import db
from app.core.db_class.db import BackgroundJob, Rule, User
from app.features.jobs.job_handlers import handle_ai_rule_analysis
from app.features.rule.utils.ai_rule_analysis.ai_rule_analysis_core import (
    is_local_ollama_url,
    AIAnalysisTimeout,
    AIAnalysisConnectionError,
    AIAnalysisInvalidResponse,
)

CORE = 'app.features.rule.utils.ai_rule_analysis.ai_rule_analysis_core'


def _make_job(payload, created_by):
    job = BackgroundJob(
        uuid=str(uuid.uuid4()),
        created_by=created_by,
        job_type='ai_rule_analysis',
        status='running',
        payload=payload,
    )
    db.session.add(job)
    db.session.commit()
    return job


def _make_rule(title, user_id, ai_summary=None):
    rule = Rule(
        format="yara",
        title=title,
        license="test",
        description="test",
        uuid=str(uuid.uuid4()),
        source="test",
        author="test",
        version=1,
        user_id=user_id,
        to_string="rule test { condition: true }",
        ai_summary=ai_summary,
    )
    db.session.add(rule)
    db.session.commit()
    return rule


# ── is_local_ollama_url ──────────────────────────────────────────────────────

def test_is_local_ollama_url_accepts_localhost():
    assert is_local_ollama_url('http://localhost:11434') is True
    assert is_local_ollama_url('http://127.0.0.1:11434') is True


def test_is_local_ollama_url_accepts_private_ranges():
    assert is_local_ollama_url('http://10.0.5.3:11434') is True
    assert is_local_ollama_url('http://192.168.1.50:11434') is True
    assert is_local_ollama_url('http://172.16.0.1:11434') is True
    assert is_local_ollama_url('http://172.31.255.255:11434') is True


def test_is_local_ollama_url_rejects_public_addresses():
    assert is_local_ollama_url('http://api.openai.com') is False
    assert is_local_ollama_url('http://8.8.8.8:11434') is False
    assert is_local_ollama_url('http://172.32.0.1:11434') is False  # just outside the private range
    assert is_local_ollama_url('') is False


# ── handle_ai_rule_analysis ──────────────────────────────────────────────────

def test_ai_rule_analysis_generates_summary_for_targeted_rules(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Rule A", admin.id)
        r2 = _make_rule("Rule B", admin.id)

        job = _make_job({'rule_ids': [r1.id, r2.id]}, admin.id)

        with patch(f'{CORE}.call_ollama_for_summary', return_value=("## Purpose\nDoes a thing.", "qwen2.5:1.5b")):
            handle_ai_rule_analysis(job, app)

        db.session.refresh(job)
        assert job.total == 2
        assert job.done == 2
        assert job.status != 'failed'

        r1_after = Rule.query.get(r1.id)
        r2_after = Rule.query.get(r2.id)
        assert r1_after.ai_summary == "## Purpose\nDoes a thing."
        assert r1_after.ai_summary_model == "qwen2.5:1.5b"
        assert r1_after.ai_summary_generated_at is not None
        assert r2_after.ai_summary == "## Purpose\nDoes a thing."


def test_ai_rule_analysis_skips_rules_with_existing_summary_by_default(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Already analyzed", admin.id, ai_summary="pre-existing")
        r2 = _make_rule("Needs analysis", admin.id)

        job = _make_job({'rule_ids': [r1.id, r2.id], 'overwrite_existing_summary': False}, admin.id)

        with patch(f'{CORE}.call_ollama_for_summary', return_value=("new summary", "qwen2.5:1.5b")) as mock_call:
            handle_ai_rule_analysis(job, app)
            # Only the rule without an existing summary should ever reach Ollama.
            assert mock_call.call_count == 1

        r1_after = Rule.query.get(r1.id)
        r2_after = Rule.query.get(r2.id)
        assert r1_after.ai_summary == "pre-existing"   # untouched
        assert r2_after.ai_summary == "new summary"


def test_ai_rule_analysis_overwrite_existing_summary(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Already analyzed", admin.id, ai_summary="stale")

        job = _make_job({'rule_ids': [r1.id], 'overwrite_existing_summary': True}, admin.id)

        with patch(f'{CORE}.call_ollama_for_summary', return_value=("fresh summary", "qwen2.5:1.5b")):
            handle_ai_rule_analysis(job, app)

        assert Rule.query.get(r1.id).ai_summary == "fresh summary"


def test_ai_rule_analysis_per_rule_failure_does_not_stop_the_job(app):
    """A timeout or invalid response on one rule must not prevent later rules
    in the same run from being processed."""
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Times out", admin.id)
        r2 = _make_rule("Succeeds", admin.id)

        job = _make_job({'rule_ids': [r1.id, r2.id]}, admin.id)

        def side_effect(rule_stub):
            if rule_stub.id == r1.id:
                raise AIAnalysisTimeout("took too long")
            return ("ok", "qwen2.5:1.5b")

        with patch(f'{CORE}.call_ollama_for_summary', side_effect=side_effect):
            handle_ai_rule_analysis(job, app)

        db.session.refresh(job)
        assert job.status != 'failed'
        assert job.done == 2   # both rules were iterated past, one just failed
        assert Rule.query.get(r1.id).ai_summary is None
        assert Rule.query.get(r2.id).ai_summary == "ok"


def test_ai_rule_analysis_invalid_response_is_skipped_not_stored(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Bad output", admin.id)
        job = _make_job({'rule_ids': [r1.id]}, admin.id)

        with patch(f'{CORE}.call_ollama_for_summary', side_effect=AIAnalysisInvalidResponse("not json")):
            handle_ai_rule_analysis(job, app)

        assert Rule.query.get(r1.id).ai_summary is None
        db.session.refresh(job)
        assert job.status != 'failed'


def test_ai_rule_analysis_connection_error_stops_job_and_is_resumable(app):
    """Ollama being unreachable is systemic, not per-rule — the whole job
    should stop (not silently mark every remaining rule as attempted), and
    the resume offset must point back at the rule that failed."""
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("First", admin.id)
        r2 = _make_rule("Never reached", admin.id)

        job = _make_job({'rule_ids': [r1.id, r2.id]}, admin.id)

        with patch(f'{CORE}.call_ollama_for_summary', side_effect=AIAnalysisConnectionError("down")):
            handle_ai_rule_analysis(job, app)

        db.session.refresh(job)
        assert job.status == 'failed'
        assert Rule.query.get(r1.id).ai_summary is None
        assert Rule.query.get(r2.id).ai_summary is None
        # Resume offset rewound to retry the rule that failed, not skip past it.
        assert job.payload.get('_resume_offset') == 0


def test_ai_rule_analysis_refuses_non_local_ollama_url(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Should not be touched", admin.id)
        job = _make_job({'rule_ids': [r1.id]}, admin.id)

        original_url = app.config.get('OLLAMA_URL')
        app.config['OLLAMA_URL'] = 'http://public-model-host.example.com'
        try:
            with patch(f'{CORE}.call_ollama_for_summary') as mock_call:
                handle_ai_rule_analysis(job, app)
                mock_call.assert_not_called()
        finally:
            app.config['OLLAMA_URL'] = original_url

        db.session.refresh(job)
        assert job.status == 'failed'
        assert Rule.query.get(r1.id).ai_summary is None


def test_ai_rule_analysis_pagination_does_not_skip_rules(app):
    """The query must never filter by ai_summary IS NULL directly — see the
    correctness note in job_handlers.py. Verify against a small fetch batch
    that every targeted rule is actually reached, not just the ones fitting
    in the first page."""
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        rule_ids = [_make_rule(f"Rule {i}", admin.id).id for i in range(5)]

        job = _make_job({'rule_ids': rule_ids}, admin.id)

        with patch('app.features.jobs.job_handlers.AI_ANALYSIS_FETCH_BATCH', 2), \
             patch(f'{CORE}.call_ollama_for_summary', return_value=("ok", "qwen2.5:1.5b")):
            handle_ai_rule_analysis(job, app)

        for rid in rule_ids:
            assert Rule.query.get(rid).ai_summary == "ok"


# ── trigger route ────────────────────────────────────────────────────────────

def test_trigger_ai_analysis_requires_admin(client, app):
    with app.app_context():
        user = User.query.filter_by(email="t@t.t").first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True
    res = client.post('/account/admin/bulk_parse_fields/trigger_ai_analysis',
                      json={'rule_ids': 'ALL'})
    assert res.status_code == 403


def test_trigger_ai_analysis_queues_job_for_admin(client, app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        r1 = _make_rule("Trigger target", admin.id)
        rid = r1.id
        admin_id = admin.id
    with client.session_transaction() as sess:
        sess['_user_id'] = str(admin_id)
        sess['_fresh'] = True
    res = client.post('/account/admin/bulk_parse_fields/trigger_ai_analysis',
                      json={'rule_ids': [rid]})
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    with app.app_context():
        job = BackgroundJob.query.filter_by(uuid=data['job']['uuid']).first()
        assert job is not None
        assert job.job_type == 'ai_rule_analysis'
        assert job.payload['rule_ids'] == [rid]
