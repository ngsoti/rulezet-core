import uuid as uuid_mod

from app import db
from app.core.db_class.db import AIGeneration, InstanceConfig, User


def _login(client, user_id):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True


def _seed_instance_config(app, mascot_enabled=True):
    """The test app fixture doesn't run the real boot-time _init_instance_config
    (the table doesn't exist yet when that runs) — seed the singleton row
    ourselves, same pattern as _seed_agent_configs in test_ai_admin_routes.py."""
    with app.app_context():
        cfg = InstanceConfig.query.first()
        if not cfg:
            cfg = InstanceConfig(uuid=str(uuid_mod.uuid4()))
            db.session.add(cfg)
        cfg.mascot_enabled = mascot_enabled
        db.session.commit()


def test_mascot_images_render_on_ai_admin_pages(app, client):
    with app.app_context():
        admin_id = User.query.filter_by(admin=True).first().id
    _login(client, admin_id)

    for path in ['/ai/admin/chatbot', '/ai/admin/rule-analysis',
                 '/ai/admin/rule-generator', '/ai/admin/rule-fixer']:
        res = client.get(path)
        assert res.status_code == 200, path
        body = res.get_data(as_text=True)
        assert 'images/rulezy/' in body, path


def test_mascot_image_renders_on_history_detail_per_agent(app, client):
    with app.app_context():
        admin_id = User.query.filter_by(admin=True).first().id
        gens = {}
        for agent_key in ['rule_analysis', 'rule_generator', 'rule_fixer']:
            gen = AIGeneration(uuid=str(uuid_mod.uuid4()), agent_key=agent_key,
                                user_id=admin_id, content="x", is_public=True)
            db.session.add(gen)
            db.session.flush()
            gens[agent_key] = gen.uuid
        db.session.commit()
    _login(client, admin_id)

    for agent_key, gen_uuid in gens.items():
        res = client.get(f'/ai/admin/{agent_key}/history/{gen_uuid}')
        assert res.status_code == 200, agent_key
        body = res.get_data(as_text=True)
        assert 'images/rulezy/' in body, agent_key


# ── window.__MASCOT_ENABLED__ (base.html -> every page's client-side JS) ─────

def test_window_mascot_enabled_reflects_instance_config(app, client):
    _seed_instance_config(app, mascot_enabled=True)
    body = client.get('/').get_data(as_text=True)
    assert 'window.__MASCOT_ENABLED__ = true;' in body

    _seed_instance_config(app, mascot_enabled=False)
    body = client.get('/').get_data(as_text=True)
    assert 'window.__MASCOT_ENABLED__ = false;' in body


def test_window_mascot_enabled_defaults_true_without_instance_config(app, client):
    # No InstanceConfig row at all (fresh install before first boot) — must
    # not break page rendering, and must default to showing the mascot.
    body = client.get('/').get_data(as_text=True)
    assert 'window.__MASCOT_ENABLED__ = true;' in body


# ── Server-rendered fallback (no image, no "rulezy" wording) when off ────────

def test_ai_admin_pages_fall_back_to_fa_icons_when_mascot_disabled(app, client):
    _seed_instance_config(app, mascot_enabled=False)
    with app.app_context():
        admin_id = User.query.filter_by(admin=True).first().id
    _login(client, admin_id)

    for path in ['/ai/admin/chatbot', '/ai/admin/rule-analysis',
                 '/ai/admin/rule-generator', '/ai/admin/rule-fixer']:
        res = client.get(path)
        assert res.status_code == 200, path
        body = res.get_data(as_text=True)
        assert 'images/rulezy/' not in body, path


def test_history_detail_falls_back_to_fa_icon_when_mascot_disabled(app, client):
    _seed_instance_config(app, mascot_enabled=False)
    with app.app_context():
        admin_id = User.query.filter_by(admin=True).first().id
        gen = AIGeneration(uuid=str(uuid_mod.uuid4()), agent_key='rule_fixer',
                            user_id=admin_id, content="x", is_public=True)
        db.session.add(gen)
        db.session.commit()
        gen_uuid = gen.uuid
    _login(client, admin_id)

    res = client.get(f'/ai/admin/rule_fixer/history/{gen_uuid}')
    assert res.status_code == 200
    assert 'images/rulezy/' not in res.get_data(as_text=True)


def test_404_page_falls_back_when_mascot_disabled(app, client):
    _seed_instance_config(app, mascot_enabled=False)
    res = client.get('/this-page-does-not-exist')
    assert res.status_code == 404
    body = res.get_data(as_text=True)
    assert 'images/rulezy/' not in body
    assert "I'm Rulezy" not in body


def test_404_page_shows_mascot_when_enabled(app, client):
    _seed_instance_config(app, mascot_enabled=True)
    res = client.get('/this-page-does-not-exist')
    body = res.get_data(as_text=True)
    assert 'images/rulezy/lookup.png' in body


def test_home_page_hides_rulezy_bubble_when_mascot_disabled(app, client):
    _seed_instance_config(app, mascot_enabled=False)
    body = client.get('/').get_data(as_text=True)
    assert 'images/rulezy/simple.png' not in body


def test_rule_create_falls_back_when_mascot_disabled(app, client):
    _seed_instance_config(app, mascot_enabled=False)
    with app.app_context():
        admin_id = User.query.filter_by(admin=True).first().id
    _login(client, admin_id)

    res = client.get('/rule/create_rule')
    assert res.status_code == 200
    assert 'images/rulezy/' not in res.get_data(as_text=True)


# ── POST /ai/admin/mascot_toggle ──────────────────────────────────────────────

def test_mascot_toggle_updates_instance_config(app, client):
    _seed_instance_config(app, mascot_enabled=True)
    with app.app_context():
        admin_id = User.query.filter_by(admin=True).first().id
    _login(client, admin_id)

    res = client.post('/ai/admin/mascot_toggle', json={'mascot_enabled': False})
    assert res.status_code == 200
    assert res.get_json() == {'success': True, 'mascot_enabled': False}

    with app.app_context():
        assert InstanceConfig.query.first().mascot_enabled is False


def test_mascot_toggle_requires_admin(app, client):
    _seed_instance_config(app, mascot_enabled=True)
    with app.app_context():
        non_admin_id = User.query.filter_by(admin=False).first().id
    _login(client, non_admin_id)

    res = client.post('/ai/admin/mascot_toggle', json={'mascot_enabled': False})
    assert res.status_code == 403


def test_mascot_toggle_404_without_instance_config(app, client):
    # No InstanceConfig row seeded at all in this test.
    with app.app_context():
        admin_id = User.query.filter_by(admin=True).first().id
    _login(client, admin_id)

    res = client.post('/ai/admin/mascot_toggle', json={'mascot_enabled': False})
    assert res.status_code == 404
