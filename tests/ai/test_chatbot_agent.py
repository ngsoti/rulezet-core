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


# ── search_rules shortcut — small local models are unreliable at this,
#    confirmed empirically: "cve 3456-4567" (no "CVE-" prefix) got a
#    hallucinated "chat" reply, and "do you have rule to detect X" got
#    action "chat" with the literal reply "ask". Both bypass the model. ────

def test_search_shortcut_handles_cve_without_prefix_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "Hello can you give me somes yara rules with cve 3456-4567 ?")
        mock_chat.assert_not_called()
        assert result['success'] is True
        assert result['redirect'] == '/rule/rules_list?rule_type=yara&vulnerabilities=CVE-3456-4567'


def test_search_shortcut_handles_open_ended_topic_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "Do you have rule to detect Fortinet exploitation?")
        mock_chat.assert_not_called()
        assert result['success'] is True
        # "exploitation" is generic jargon stripped by _simplify_search_topic —
        # the backend search is a single ILIKE substring match, so the full
        # phrase would almost never match while "Fortinet" alone matches broadly.
        assert result['redirect'] == '/rule/rules_list?search=Fortinet'


def test_simplify_search_topic_strips_trailing_generic_words():
    from app.features.ai.chatbot.chatbot_core import _simplify_search_topic

    assert _simplify_search_topic("Fortinet exploitation") == "Fortinet"
    assert _simplify_search_topic("ransomware attacks") == "ransomware"
    assert _simplify_search_topic("SQL injection vulnerability") == "SQL injection"
    # A specific multi-word term with no generic trailing word is left as-is.
    assert _simplify_search_topic("Cobalt Strike") == "Cobalt Strike"
    # Never strip down to nothing.
    assert _simplify_search_topic("exploitation") == "exploitation"


def test_search_shortcut_handles_properly_formed_cve_too(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "rules for CVE-2026-15155?")
        mock_chat.assert_not_called()
        assert result['redirect'] == '/rule/rules_list?vulnerabilities=CVE-2026-15155'


def test_search_shortcut_skips_vague_field_reference_lets_model_ask(app):
    # "with a CVE" names the field but gives no value — the shortcut must not
    # search for the literal words "a cve"; falls through to the model, whose
    # system prompt handles this as an "ask" for the missing value.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(action='ask', reply="Which CVE?")):
            result = handle_message(user, [], "I want yara rules with a CVE")
        assert result['action'] == 'ask'


def test_search_shortcut_handles_source_url_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "do we have some rules from https://github.com/Yara-Rules/rules")
        mock_chat.assert_not_called()
        assert result['success'] is True
        assert result['redirect'] == '/rule/rules_list?sources=https%3A%2F%2Fgithub.com%2FYara-Rules%2Frules'


def test_search_shortcut_source_url_never_misreads_repo_name_as_format(app):
    # "Yara-Rules" in the URL path must not get read as rule_type=yara —
    # only a format word OUTSIDE the URL counts.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT):
            result = handle_message(user, [], "do we have some rules from https://github.com/Yara-Rules/rules")
        assert 'rule_type' not in result['redirect']


def test_search_shortcut_source_url_still_honors_explicit_format(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT):
            result = handle_message(user, [], "do we have some yara rules from https://github.com/Neo23x0/signature-base")
        assert result['redirect'] == '/rule/rules_list?rule_type=yara&sources=https%3A%2F%2Fgithub.com%2FNeo23x0%2Fsignature-base'


def test_search_shortcut_ignores_url_with_no_rule_mention(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(reply="Nice project!")) as mock_chat:
            result = handle_message(user, [], "check out this cool project https://github.com/foo/bar")
        mock_chat.assert_called_once()


def test_search_shortcut_handles_attack_technique_id(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "do you have rules for attack technique T1055.001?")
        mock_chat.assert_not_called()
        assert result['redirect'] == '/rule/rules_list?attacks=T1055.001'


def test_search_shortcut_handles_known_tag(app):
    import uuid as uuid_mod
    from app import db
    from app.core.db_class.db import Tag

    with app.app_context():
        db.session.add(Tag(uuid=str(uuid_mod.uuid4()), name='ransomware'))
        db.session.commit()
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "show me rules tagged ransomware")
        mock_chat.assert_not_called()
        assert result['redirect'] == '/rule/rules_list?tags=ransomware'


def test_search_shortcut_ignores_unknown_tag(app):
    # No such tag exists in the DB — must not fabricate a filter for it, and
    # with nothing else in the message to go on, falls through to the model.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(reply="no match")) as mock_chat:
            handle_message(user, [], "show me rules tagged nonexistenttagxyz")
        mock_chat.assert_called_once()


def test_search_shortcut_handles_author_phrasing(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "find rules by jdoe")
        mock_chat.assert_not_called()
        assert result['redirect'] == '/rule/rules_list?authors=jdoe'


def test_search_shortcut_handles_editor_phrasing(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "rules edited by jdoe")
        mock_chat.assert_not_called()
        assert result['redirect'] == '/rule/rules_list?editors=jdoe'


def test_search_shortcut_by_tag_meta_phrase_never_becomes_a_fake_author(app):
    # "by tag" means "filter BY the tag criterion", not a person named "tag".
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(reply="ok")) as mock_chat:
            result = handle_message(user, [], "show me rules by tag")
        mock_chat.assert_called_once()


def test_search_shortcut_handles_bare_format_request_with_verb(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "show me yara rules")
        mock_chat.assert_not_called()
        assert result['redirect'] == '/rule/rules_list?rule_type=yara'


def test_search_shortcut_bare_format_without_verb_falls_through(app):
    # No request verb and no other signal — same guard as the existing
    # "does rulezet support yara rules" case, just phrased differently.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(reply="yes")) as mock_chat:
            handle_message(user, [], "I really like yara rules")
        mock_chat.assert_called_once()


def test_search_shortcut_combines_several_fields_at_once(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "yara rules for CVE-2024-1234 by jdoe")
        mock_chat.assert_not_called()
        assert result['redirect'] == '/rule/rules_list?rule_type=yara&vulnerabilities=CVE-2024-1234&authors=jdoe'


# ── create_rule shortcut — a multi-turn "create a X rule" -> paste content
#    flow confirmed live to fail: handed the exact rule text as the message,
#    the model replied "Please provide the content of the rule" (it had
#    already asked for it one turn earlier and didn't recognize the answer),
#    so the rule was never actually created despite the confirmation-sounding
#    reply. Bypasses the model for this one turn instead. ─────────────────────

_YARA_RULE_CONTENT = """rule Suspicious_PowerShell_Execution {
    meta:
        description = "Detects obfuscated or hidden PowerShell execution commands"
    strings:
        $ps = "powershell" ascii nocase
        $enc = "-EncodedCommand" ascii nocase
    condition:
        $ps and $enc
}"""


def test_create_rule_shortcut_handles_pasted_content_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        history = [
            {"role": "user", "content": "can you create a yara rule ?"},
            {"role": "assistant", "content": "Sure, please provide the content of the rule."},
        ]
        with patch(CHAT) as mock_chat:
            result = handle_message(user, history, _YARA_RULE_CONTENT)
        mock_chat.assert_not_called()
        assert result['action'] == 'create_rule'
        assert result['success'] is True
        assert 'link' in result


def test_create_rule_shortcut_requires_create_verb_somewhere_in_recent_history(app):
    # Rule-shaped content pasted with no "create/write/make/generate/build"
    # anywhere in recent history must not be auto-created — falls through to
    # the model like before.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(reply="That looks like a YARA rule.")) as mock_chat:
            result = handle_message(user, [], _YARA_RULE_CONTENT)
        mock_chat.assert_called_once()
        assert result['action'] != 'create_rule'


def test_create_rule_shortcut_requires_a_named_format(app):
    # A create-verb is present, but no format was ever named anywhere in the
    # exchange — the shortcut can't guess a format, so it defers to the model.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        history = [{"role": "user", "content": "can you create a rule for me?"}]
        with patch(CHAT, return_value=_envelope(reply="Which format?")) as mock_chat:
            result = handle_message(user, history, _YARA_RULE_CONTENT)
        mock_chat.assert_called_once()


def test_search_shortcut_never_hijacks_create_rule_requests(app):
    # The create-verb guard must send this to the model instead of the
    # search shortcut — whatever the model/downstream validation then does
    # with it is out of scope here, only that it wasn't silently redirected.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        envelope = _envelope(action='create_rule', params={'format': 'yara', 'content': ''})
        with patch(CHAT, return_value=envelope) as mock_chat:
            result = handle_message(user, [], "create a yara rule that detects CVE-2024-1234")
        mock_chat.assert_called_once()
        assert 'redirect' not in result


def test_search_shortcut_never_hijacks_plain_format_question(app):
    # A bare format name with no CVE/topic connector must still go through
    # _maybe_format_question (checked earlier in the shortcut chain), not the
    # search shortcut, and must never redirect.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "does rulezet support yara rules")
        mock_chat.assert_called_once()


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
