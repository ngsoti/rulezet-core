import uuid as uuid_mod

from app import db
from app.core.db_class.db import AIGeneration, User


def _login(client, user_id):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True


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
