"""
Tests for the chatbot's migration onto ChatbotAgent/AIAgent
(AI_01_CHATBOT.md §3/§9 Phase 1) — the action-dispatch logic in
chatbot_core.py is unchanged, only "call Ollama and parse the envelope"
now goes through the shared agent. OllamaClient.chat() is mocked
throughout so no real Ollama instance is needed.
"""

import json
from unittest.mock import patch

from app.core.db_class.db import User
from app.features.ai.ai_core import get_agent
from app.features.ai.chatbot.chatbot_core import handle_message

CHAT = 'app.features.ai.ai_core.OllamaClient.chat'


def _envelope(action='chat', params=None, reply='hello'):
    return json.dumps({"action": action, "params": params or {}, "reply": reply})


# ── discovery ──────────────────────────────────────────────────────────────

def test_chatbot_agent_is_discoverable(app):
    with app.app_context():
        agent = get_agent('chatbot')
        assert agent is not None
        assert agent.key == 'chatbot'
        assert agent.display_name == 'Chatbot Assistant'


# ── end-to-end dispatch through the agent ────────────────────────────────────

def test_handle_message_plain_chat_reply(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(reply="Rulezet is a rule-sharing platform.")):
            result = handle_message(user, [], "what is rulezet?")
        assert result['action'] == 'chat'
        assert result['reply'] == "Rulezet is a rule-sharing platform."
        assert 'conversation_uuid' in result


def test_handle_message_navigate_action(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(action='navigate', params={'destination': 'my_rules'})):
            result = handle_message(user, [], "take me to my rules")
        assert result['action'] == 'navigate'
        assert result['success'] is True
        assert result['redirect'] == '/rule/owner_rules'


def test_handle_message_navigate_admin_page_denied_for_non_admin(app):
    with app.app_context():
        user = User.query.filter_by(email="neo@admin.admin").first()
        with patch(CHAT, return_value=_envelope(action='navigate', params={'destination': 'admin_settings'})):
            result = handle_message(user, [], "go to admin settings")
        assert result['success'] is False
        assert 'admin' in result['reply'].lower()


def test_handle_message_falls_back_to_plain_text_on_invalid_json(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value="not json at all"):
            result = handle_message(user, [], "hello")
        assert result['action'] == 'chat'
        assert result['reply'] == "not json at all"


def test_handle_message_deterministic_shortcut_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "what formats are supported?")
        mock_chat.assert_not_called()
        assert 'yara' in result['reply'].lower()


# ── disabled / rate-limited surface through the route-facing status ─────────

def test_dispatch_reports_disabled_status_when_agent_config_disabled(app):
    from app import db
    from app.core.db_class.db import AIAgentConfig

    with app.app_context():
        db.session.add(AIAgentConfig(agent_key='chatbot', enabled=False))
        db.session.commit()

        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "hello")
        mock_chat.assert_not_called()
        assert result['success'] is False
        assert result['_agent_status'] == 'disabled'


def test_dispatch_reports_rate_limited_status(app):
    import uuid as uuid_mod

    from app import db
    from app.core.db_class.db import AIAgentConfig, AIExecutionLog

    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        db.session.add(AIAgentConfig(agent_key='chatbot', enabled=True, max_per_hour=1))
        db.session.add(AIExecutionLog(
            uuid=str(uuid_mod.uuid4()), agent_key='chatbot', user_id=user.id, status='success',
        ))
        db.session.commit()

        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "hello")
        mock_chat.assert_not_called()
        assert result['success'] is False
        assert result['_agent_status'] == 'rate_limited'
