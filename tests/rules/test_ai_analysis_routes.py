"""
Tests for the AI Analysis rule-detail sub-page routes (AI_02_RULE_ANALYSIS.md
§6): history list, model listing, downloads, and the admin-only
visibility/delete moderation levers.
"""

import uuid

from app import db
from app.core.db_class.db import AIGeneration, Rule, User


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _make_rule(app, title="Sample rule"):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        rule = Rule(
            format="yara", title=title, license="test", description="test",
            uuid=str(uuid.uuid4()), source="test", author="test", version=1,
            user_id=admin.id, to_string="rule test { condition: true }",
        )
        db.session.add(rule)
        db.session.commit()
        return rule.id


def _make_generation(app, rule_id, is_public=True, content="## Overview\nDoes a thing."):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        gen = AIGeneration(
            uuid=str(uuid.uuid4()), agent_key='rule_analysis', rule_id=rule_id,
            user_id=admin.id, content=content, model="qwen2.5:1.5b", is_public=is_public,
        )
        db.session.add(gen)
        db.session.commit()
        return gen.id


# ── page + list ──────────────────────────────────────────────────────────────

def test_ai_analysis_page_renders(app, client):
    rule_id = _make_rule(app)
    res = client.get(f"/rule/detail_rule/{rule_id}/ai_analysis")
    assert res.status_code == 200
    assert b"AI Analysis" in res.data


def test_list_hides_private_from_non_admin(app, client):
    rule_id = _make_rule(app)
    _make_generation(app, rule_id, is_public=True)
    _make_generation(app, rule_id, is_public=False)

    res = client.get(f"/rule/detail_rule/{rule_id}/ai_analysis/list")
    items = res.get_json()['items']
    assert len(items) == 1
    assert items[0]['is_public'] is True


def test_list_shows_everything_to_admin(app, client):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
    rule_id = _make_rule(app)
    _make_generation(app, rule_id, is_public=True)
    _make_generation(app, rule_id, is_public=False)

    _login(client, admin)
    res = client.get(f"/rule/detail_rule/{rule_id}/ai_analysis/list")
    items = res.get_json()['items']
    assert len(items) == 2


# ── models endpoint ────────────────────────────────────────────────────────

def test_models_forbidden_for_non_admin(app, client):
    with app.app_context():
        user = User.query.filter_by(email="neo@admin.admin").first()
    _login(client, user)
    res = client.get("/rule/ai_analysis/models")
    assert res.status_code == 403


def test_models_ok_for_admin_even_when_ollama_unreachable(app, client):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
    _login(client, admin)
    res = client.get("/rule/ai_analysis/models")
    assert res.status_code == 200
    data = res.get_json()
    assert 'enabled' in data
    assert isinstance(data['models'], list)
    assert data['default_model'] is None


def test_models_returns_configured_default_model(app, client):
    from app.core.db_class.db import AIAgentConfig

    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        admin_id = admin.id
        db.session.add(AIAgentConfig(agent_key='rule_analysis', enabled=True, default_model='qwen2.5:32b'))
        db.session.commit()

    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)
        sess["_fresh"] = True
    res = client.get("/rule/ai_analysis/models")
    assert res.get_json()['default_model'] == 'qwen2.5:32b'


# ── downloads ────────────────────────────────────────────────────────────────

def test_download_markdown_public(app, client):
    rule_id = _make_rule(app)
    gen_id = _make_generation(app, rule_id, is_public=True, content="## Overview\nHello.")
    res = client.get(f"/rule/detail_rule/{rule_id}/ai_analysis/{gen_id}/download/markdown")
    assert res.status_code == 200
    assert res.mimetype == 'text/markdown'
    body = res.get_data(as_text=True)
    assert '## Overview' in body
    assert 'title: "AI Analysis' in body


def test_download_markdown_private_is_404_for_non_admin(app, client):
    rule_id = _make_rule(app)
    gen_id = _make_generation(app, rule_id, is_public=False)
    res = client.get(f"/rule/detail_rule/{rule_id}/ai_analysis/{gen_id}/download/markdown")
    assert res.status_code == 404


def test_download_pdf_public(app, client):
    rule_id = _make_rule(app)
    gen_id = _make_generation(app, rule_id, is_public=True)
    res = client.get(f"/rule/detail_rule/{rule_id}/ai_analysis/{gen_id}/download/pdf")
    assert res.status_code == 200
    assert res.mimetype == 'application/pdf'
    assert res.data[:4] == b'%PDF'


# ── visibility / delete ──────────────────────────────────────────────────────

def test_toggle_visibility_forbidden_for_non_admin(app, client):
    rule_id = _make_rule(app)
    gen_id = _make_generation(app, rule_id, is_public=True)
    with app.app_context():
        user = User.query.filter_by(email="neo@admin.admin").first()
    _login(client, user)
    res = client.post(f"/rule/detail_rule/{rule_id}/ai_analysis/{gen_id}/visibility",
                       json={'is_public': False})
    assert res.status_code == 403


def test_toggle_visibility_as_admin(app, client):
    rule_id = _make_rule(app)
    gen_id = _make_generation(app, rule_id, is_public=True)
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
    _login(client, admin)
    res = client.post(f"/rule/detail_rule/{rule_id}/ai_analysis/{gen_id}/visibility",
                       json={'is_public': False})
    assert res.status_code == 200
    assert res.get_json()['analysis']['is_public'] is False

    with app.app_context():
        assert AIGeneration.query.get(gen_id).is_public is False


def test_delete_forbidden_for_non_admin(app, client):
    rule_id = _make_rule(app)
    gen_id = _make_generation(app, rule_id, is_public=True)
    with app.app_context():
        user = User.query.filter_by(email="neo@admin.admin").first()
    _login(client, user)
    res = client.delete(f"/rule/detail_rule/{rule_id}/ai_analysis/{gen_id}")
    assert res.status_code == 403


def test_delete_as_admin(app, client):
    rule_id = _make_rule(app)
    gen_id = _make_generation(app, rule_id, is_public=True)
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
    _login(client, admin)
    res = client.delete(f"/rule/detail_rule/{rule_id}/ai_analysis/{gen_id}")
    assert res.status_code == 200
    assert res.get_json()['success'] is True

    with app.app_context():
        assert AIGeneration.query.get(gen_id) is None


# ── nav count ──────────────────────────────────────────────────────────────

def test_ai_analysis_count_appears_in_nav_badge(app, client):
    rule_id = _make_rule(app)
    _make_generation(app, rule_id, is_public=True)
    _make_generation(app, rule_id, is_public=True)

    res = client.get(f"/rule/detail_rule/{rule_id}/ai_analysis")
    assert res.status_code == 200
    assert b'<span class="dr-nav__badge">2</span>' in res.data
