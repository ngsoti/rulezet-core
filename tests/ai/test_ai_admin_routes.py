"""
Tests for the unified AI admin section (AI_05_UI_UX_SPEC.md): the 4 agent
pages, the shared config/model/execution-log APIs, and the
/chatbot/admin/conversations -> /ai/admin/chatbot relocation.
"""

import uuid

from app import db
from app.core.db_class.db import AIAgentConfig, AIExecutionLog, AIGeneration, AIModelConfig, Rule, User


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _admin(app):
    with app.app_context():
        return User.query.filter_by(email="admin@admin.admin").first()


def _non_admin(app):
    with app.app_context():
        return User.query.filter_by(email="neo@admin.admin").first()


def _seed_agent_configs(app):
    """The test app fixture doesn't run init_db.py's insert_default_ai_agent_configs()
    (that's only wired into the CLI init flow) — create the rows these tests need."""
    with app.app_context():
        if not AIAgentConfig.query.filter_by(agent_key='chatbot').first():
            db.session.add(AIAgentConfig(agent_key='chatbot', enabled=True, max_per_hour=60,
                                          timeout_s=120, num_predict=1024))
        if not AIAgentConfig.query.filter_by(agent_key='rule_analysis').first():
            db.session.add(AIAgentConfig(agent_key='rule_analysis', enabled=True, max_per_hour=None,
                                          timeout_s=300, num_predict=4096))
        db.session.commit()


# ── page access control ──────────────────────────────────────────────────────

PAGES = [
    "/ai/admin/chatbot",
    "/ai/admin/rule-analysis",
    "/ai/admin/rule-generator",
    "/ai/admin/rule-fixer",
    "/ai/admin/models",
    "/ai/admin/overview",
]


def test_pages_require_admin(app, client):
    for path in PAGES:
        res = client.get(path)
        assert res.status_code in (302, 401, 403), path


def test_pages_forbidden_for_non_admin(app, client):
    _login(client, _non_admin(app))
    for path in PAGES:
        res = client.get(path)
        assert res.status_code == 403, path


def test_pages_render_for_admin(app, client):
    _login(client, _admin(app))
    for path in PAGES:
        res = client.get(path)
        assert res.status_code == 200, path


def test_old_chatbot_conversations_url_redirects_to_ai_admin(app, client):
    _login(client, _admin(app))
    res = client.get("/chatbot/admin/conversations")
    assert res.status_code == 302
    assert res.headers["Location"].endswith("/ai/admin/chatbot")


# ── config API ───────────────────────────────────────────────────────────────

def test_list_configs_returns_all_known_agents(app, client):
    _seed_agent_configs(app)
    _login(client, _admin(app))
    res = client.get("/ai/admin/config")
    assert res.status_code == 200
    keys = {c['agent_key'] for c in res.get_json()['configs']}
    assert keys == {'chatbot', 'rule_analysis'}  # only the ones seeded in this test


def test_get_config_returns_seeded_row(app, client):
    _seed_agent_configs(app)
    _login(client, _admin(app))
    res = client.get("/ai/admin/config/rule_analysis")
    assert res.status_code == 200
    data = res.get_json()
    assert data['agent_key'] == 'rule_analysis'


def test_get_config_unknown_agent_404s(app, client):
    _seed_agent_configs(app)
    _login(client, _admin(app))
    res = client.get("/ai/admin/config/not_a_real_agent")
    assert res.status_code == 404


def test_save_config_updates_and_persists(app, client):
    _seed_agent_configs(app)
    _login(client, _admin(app))
    res = client.post("/ai/admin/config/rule_analysis", json={
        "enabled": False, "default_model": "qwen2.5:3b", "timeout_s": 200, "num_predict": 1000,
    })
    assert res.status_code == 200
    assert res.get_json()['success'] is True

    with app.app_context():
        cfg = AIAgentConfig.query.filter_by(agent_key='rule_analysis').first()
        assert cfg.enabled is False
        assert cfg.default_model == 'qwen2.5:3b'
        assert cfg.timeout_s == 200
        assert cfg.num_predict == 1000


def test_save_config_cannot_set_rate_limit_on_agent_without_one(app, client):
    _seed_agent_configs(app)
    # rule_analysis is seeded with max_per_hour=None (batch/admin-triggered,
    # no per-user rate limit by design, AI_00 §4.1) — the API must not let a
    # client accidentally turn that on.
    _login(client, _admin(app))
    client.post("/ai/admin/config/rule_analysis", json={"max_per_hour": 30})
    with app.app_context():
        cfg = AIAgentConfig.query.filter_by(agent_key='rule_analysis').first()
        assert cfg.max_per_hour is None


def test_save_config_can_update_rate_limit_on_agent_with_one(app, client):
    _seed_agent_configs(app)
    _login(client, _admin(app))
    res = client.post("/ai/admin/config/chatbot", json={"max_per_hour": 42})
    assert res.status_code == 200
    with app.app_context():
        cfg = AIAgentConfig.query.filter_by(agent_key='chatbot').first()
        assert cfg.max_per_hour == 42


def test_config_api_forbidden_for_non_admin(app, client):
    _seed_agent_configs(app)
    _login(client, _non_admin(app))
    res = client.get("/ai/admin/config/chatbot")
    assert res.status_code == 403


# ── model allowlist ──────────────────────────────────────────────────────────

def test_models_list_never_crashes_without_ollama(app, client):
    _login(client, _admin(app))
    res = client.get("/ai/admin/models/list")
    assert res.status_code == 200
    assert isinstance(res.get_json()['models'], list)


def test_models_toggle(app, client):
    with app.app_context():
        m = AIModelConfig(model_name='test-model:1b', is_enabled=True)
        db.session.add(m)
        db.session.commit()
        model_id = m.id

    _login(client, _admin(app))
    res = client.post(f"/ai/admin/models/{model_id}/toggle", json={"is_enabled": False})
    assert res.status_code == 200
    assert res.get_json()['model']['is_enabled'] is False

    with app.app_context():
        assert AIModelConfig.query.get(model_id).is_enabled is False


def test_models_toggle_not_found(app, client):
    _login(client, _admin(app))
    res = client.post("/ai/admin/models/999999/toggle", json={"is_enabled": True})
    assert res.status_code == 404


# ── per-agent history (rule_analysis) ─────────────────────────────────────────

def _make_rule(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        rule = Rule(
            format="yara", title="Sample", license="test", description="test",
            uuid=str(uuid.uuid4()), source="test", author="test", version=1,
            user_id=admin.id, to_string="rule test { condition: true }",
        )
        db.session.add(rule)
        db.session.commit()
        return rule.id


def _make_generation(app, rule_id, agent_key='rule_analysis'):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        gen = AIGeneration(
            uuid=str(uuid.uuid4()), agent_key=agent_key, rule_id=rule_id,
            user_id=admin.id, content="## Overview\nDoes a thing.", model="qwen2.5:3b",
        )
        db.session.add(gen)
        db.session.commit()
        return gen.id, gen.uuid


def test_history_data_scoped_to_agent(app, client):
    rule_id = _make_rule(app)
    _make_generation(app, rule_id, agent_key='rule_analysis')
    _make_generation(app, rule_id, agent_key='rule_generator')

    _login(client, _admin(app))
    res = client.get("/ai/admin/history/rule_analysis/data")
    items = res.get_json()['items']
    assert len(items) == 1
    assert items[0]['rule_title'] == 'Sample'


def test_history_bulk_delete_specific_ids(app, client):
    rule_id = _make_rule(app)
    gen_id, _ = _make_generation(app, rule_id)

    _login(client, _admin(app))
    res = client.post("/ai/admin/history/rule_analysis/bulk", json={"action": "delete", "ids": [gen_id]})
    assert res.status_code == 200
    assert res.get_json()['deleted'] == 1
    with app.app_context():
        assert AIGeneration.query.get(gen_id) is None


def test_history_bulk_delete_all(app, client):
    rule_id = _make_rule(app)
    _make_generation(app, rule_id)
    _make_generation(app, rule_id)

    _login(client, _admin(app))
    res = client.post("/ai/admin/history/rule_analysis/bulk", json={"action": "delete", "ids": "ALL"})
    assert res.get_json()['deleted'] == 2
    with app.app_context():
        assert AIGeneration.query.filter_by(agent_key='rule_analysis').count() == 0


def test_history_toggle_visibility(app, client):
    rule_id = _make_rule(app)
    gen_id, _ = _make_generation(app, rule_id)

    _login(client, _admin(app))
    res = client.post(f"/ai/admin/history/rule_analysis/toggle_visibility/{gen_id}", json={"is_public": False})
    assert res.status_code == 200
    with app.app_context():
        assert AIGeneration.query.get(gen_id).is_public is False


def test_history_detail_page(app, client):
    rule_id = _make_rule(app)
    _, gen_uuid = _make_generation(app, rule_id)

    _login(client, _admin(app))
    res = client.get(f"/ai/admin/rule_analysis/history/{gen_uuid}")
    assert res.status_code == 200
    assert b"Does a thing" in res.data


def test_history_detail_page_404_for_unknown_uuid(app, client):
    _login(client, _admin(app))
    res = client.get("/ai/admin/rule_analysis/history/does-not-exist")
    assert res.status_code == 404


def test_chatbot_key_rejected_by_generic_history_endpoints(app, client):
    # Chatbot keeps its own existing conversation API (AI_05 §7.4) — the
    # generic AIGeneration-backed endpoints must not pretend to serve it.
    _login(client, _admin(app))
    res = client.get("/ai/admin/history/chatbot/data")
    assert res.status_code == 404


# ── cross-agent execution log ─────────────────────────────────────────────────

def test_execution_log_data_and_agent_filter(app, client):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        db.session.add(AIExecutionLog(uuid=str(uuid.uuid4()), agent_key='chatbot', user_id=admin.id, status='success'))
        db.session.add(AIExecutionLog(uuid=str(uuid.uuid4()), agent_key='rule_analysis', user_id=admin.id, status='failed'))
        db.session.commit()

    _login(client, _admin(app))
    res = client.get("/ai/admin/execution_log/data")
    assert res.get_json()['total'] >= 2

    res = client.get("/ai/admin/execution_log/data?agent_key=chatbot")
    items = res.get_json()['items']
    assert all(i['agent_key'] == 'chatbot' for i in items)
