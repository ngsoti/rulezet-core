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
from app.features.ai.chatbot import chatbot_core
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


# ── navigate shortcut — confirmed live: "I want to go to my tag" got action
#    "chat" with the reply literally being the raw destination key
#    ("my_tags") as text, never an actual redirect. ───────────────────────────

def test_navigate_shortcut_handles_reported_case_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "I want to go to my tag")
        mock_chat.assert_not_called()
        assert result['action'] == 'navigate'
        assert result['redirect'] == '/tags/my_tags'


def test_navigate_shortcut_handles_several_phrasings(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        cases = {
            "take me to the dashboard": '/dashboard/',
            "go to my rules": '/rule/owner_rules',
            "open the admin logs": '/admin/logs',
        }
        for message, expected_path in cases.items():
            with patch(CHAT) as mock_chat:
                result = handle_message(user, [], message)
            mock_chat.assert_not_called()
            assert result['redirect'] == expected_path, message


def test_navigate_shortcut_still_enforces_admin_permission(app):
    with app.app_context():
        user = User.query.filter_by(email="neo@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "go to the admin logs")
        mock_chat.assert_not_called()
        assert result['success'] is False
        assert 'admin' in result['reply'].lower()


def test_navigate_shortcut_ignores_unrelated_go_to_phrasing(app):
    # "go to" with no recognized destination keyword must defer to the model
    # rather than silently doing nothing or guessing.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(reply="Sweet dreams!")) as mock_chat:
            handle_message(user, [], "go to sleep")
        mock_chat.assert_called_once()


# ── create_bundle shortcut — confirmed live to be the model's worst
#    failure of all: for every phrasing tried, it echoed the system
#    prompt's own JSON-template PLACEHOLDER text back verbatim
#    ({"reply": "short confirmation message"}) instead of attempting the
#    action, 100% reproducible. A name is all create_bundle needs. ──────────

def test_create_bundle_shortcut_handles_reported_case_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "create a bundle called Ransomware Toolkit")
        mock_chat.assert_not_called()
        assert result['action'] == 'create_bundle'
        assert result['success'] is True
        assert 'link' in result

        from app import db
        from app.core.db_class.db import Bundle
        bundle = Bundle.query.filter_by(name="Ransomware Toolkit").first()
        assert bundle is not None
        db.session.delete(bundle)
        db.session.commit()


def test_create_bundle_shortcut_handles_several_phrasings(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        for message in ["make a bundle named APT29 Hunt", "build a bundle titled Weekly Digest"]:
            with patch(CHAT) as mock_chat:
                result = handle_message(user, [], message)
            mock_chat.assert_not_called()
            assert result['action'] == 'create_bundle'
            assert result['success'] is True


def test_create_bundle_shortcut_requires_create_verb(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(reply="Which bundle?")) as mock_chat:
            handle_message(user, [], "I like the bundle called Weekly Digest")
        mock_chat.assert_called_once()


def test_create_bundle_shortcut_never_hijacks_create_rule_requests(app):
    # Not a bundle request at all — the create-rule-intent shortcut now
    # handles this deterministically instead (asks for content).
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "can you create a yara rule?")
        mock_chat.assert_not_called()
        assert result['action'] == 'ask'


def test_handle_message_falls_back_to_plain_text_on_invalid_json(app):
    # Message deliberately avoids every deterministic shortcut's trigger
    # words (greeting, format, rule/bundle, CVE, navigate...) so this
    # actually exercises the "model returned non-JSON" fallback path.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value="not json at all"):
            result = handle_message(user, [], "banana pancake recipe please")
        assert result['action'] == 'chat'
        assert result['reply'] == "not json at all"


def test_handle_message_deterministic_shortcut_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "what formats are supported?")
        mock_chat.assert_not_called()
        assert 'yara' in result['reply'].lower()


# ── bare greeting — confirmed live: a small model on the simplest possible
#    input ("hi") sometimes just echoes it back verbatim instead of replying.

def test_bare_greeting_gets_a_real_reply_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "hi")
        mock_chat.assert_not_called()
        assert result['reply'] == chatbot_core._GREETING_REPLY


def test_greeting_with_punctuation_still_matches(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            handle_message(user, [], "Hello!")
        mock_chat.assert_not_called()


def test_greeting_followed_by_a_real_request_is_not_swallowed(app):
    # "hi, can you create a rule?" must reach the model/other logic, not get
    # short-circuited into the plain greeting reply.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(reply="Sure, what should it detect?")) as mock_chat:
            handle_message(user, [], "hi, can you create a rule?")
        mock_chat.assert_called_once()


# ── identity — confirmed live: even after the system prompt was told the
#    assistant's name is Rulezy, "who are you"/"what's your name" still got
#    "I am Rulezet" (the platform's name, one line later in the same
#    prompt) back instead of its own. Fixed identity answer for this. ───────

def test_who_are_you_gets_the_right_identity_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "who are you?")
        mock_chat.assert_not_called()
        assert "Rulezy" in result['reply']
        assert not result['reply'].startswith("I am Rulezet")


def test_whats_your_name_gets_the_right_identity(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "what's your name")
        mock_chat.assert_not_called()
        assert "Rulezy" in result['reply']


def test_who_are_you_does_not_collide_with_what_is_rulezet(app):
    # "what is rulezet" is a different, pre-existing question (about the
    # platform) that must still reach the model, not the identity shortcut.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(reply="Rulezet is a rule-sharing platform.")) as mock_chat:
            handle_message(user, [], "what is rulezet?")
        mock_chat.assert_called_once()


# ── "I don't know, whatever you want" after being asked what a rule should
#    detect — confirmed live: the model just gets confused. This chatbot
#    never invents rule content on its own, so answer honestly instead. ─────

def test_punt_reply_during_create_rule_flow_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        history = [
            {"role": "user", "content": "can you create me a yara rule ?"},
            {"role": "assistant", "content": "Sure, what would you like the rule to detect?"},
        ]
        with patch(CHAT) as mock_chat:
            result = handle_message(user, history, "I don't know as you want")
        mock_chat.assert_not_called()
        assert 'prototype' in result['reply'].lower()
        assert 'Generate with AI' in result['reply']


def test_punt_reply_requires_create_verb_in_recent_history(app):
    # A punt phrase with no ongoing create-rule flow behind it isn't
    # necessarily about rule creation — defer to the model as usual.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT, return_value=_envelope(reply="ok")) as mock_chat:
            handle_message(user, [], "I don't know, what do you think?")
        mock_chat.assert_called_once()


def test_punt_reply_does_not_fire_during_bundle_creation(app):
    # The beta-limitation message is specifically about RULE content — a
    # punt during bundle creation (which just needs a name) is different.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        history = [
            {"role": "user", "content": "create a bundle for me"},
            {"role": "assistant", "content": "Sure, what should it be called?"},
        ]
        with patch(CHAT, return_value=_envelope(action='ask', reply="What should I call it?")) as mock_chat:
            result = handle_message(user, history, "I don't know, whatever you want")
        mock_chat.assert_called_once()
        assert 'prototype' not in result['reply'].lower()


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


# ── search reply honesty — the old reply always said "Here's what I found"
#    even for a filter that matched nothing; now it runs a real (per_page=1)
#    count first so the reply doesn't overclaim. ─────────────────────────────

def test_search_shortcut_reply_is_honest_about_zero_results(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "rules for CVE-9999-9999999?")
        mock_chat.assert_not_called()
        assert "didn't find anything" in result['reply'].lower()


def test_search_shortcut_reply_includes_a_real_count(app):
    # The seeded test rule is format="yara" — a real, non-zero count.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "show me yara rules")
        mock_chat.assert_not_called()
        assert 'Found' in result['reply'] and 'matching rule' in result['reply']
        assert "didn't find" not in result['reply'].lower()


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


# ── create-rule-intent shortcut — "I want you to create a new yara rule"
#    (no content yet) confirmed live to get an inconsistent model reply —
#    sometimes a proper ask for content, sometimes "Creating a new yara
#    rule..." with no ask at all and nothing actually created. Ask
#    deterministically instead of leaving this to chance. ────────────────────

def test_create_rule_intent_shortcut_asks_for_content_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "I want you to create a new yara rule")
        mock_chat.assert_not_called()
        assert result['action'] == 'ask'
        assert 'content' in result['reply'].lower()
        assert 'yara' in result['reply'].lower()


def test_create_rule_intent_shortcut_asks_for_format_too_when_unnamed(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "create a rule for me")
        mock_chat.assert_not_called()
        assert result['action'] == 'ask'
        assert 'format' in result['reply'].lower()


def test_create_rule_intent_shortcut_defers_to_content_shortcut_when_content_present(app):
    # A message that's already real rule content must go to the
    # content-handling shortcut, not get treated as a bare intent-only ask.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        history = [{"role": "user", "content": "create a yara rule"}]
        with patch(CHAT) as mock_chat:
            result = handle_message(user, history, _YARA_RULE_CONTENT)
        mock_chat.assert_not_called()
        assert result['action'] == 'create_rule'
        assert result['success'] is True


def test_create_rule_intent_shortcut_ignores_search_and_bundle_requests(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "I want yara rules with a CVE")
        # falls through to the model's own "ask" handling for this vague case
        mock_chat.assert_called_once()


# "I want a X rule" carries create intent without any of _CREATE_VERBS_RE's
# verbs — confirmed live to get a hallucinated "Got it, I'll create a new
# rule for you." with nothing actually created or asked for. Deliberately a
# separate, narrower pattern (singular "a/an rule") rather than adding
# "want" to _CREATE_VERBS_RE, since that regex also gates the search
# shortcut and "I want yara rules with a CVE" (plural, a real search) must
# keep working. ───────────────────────────────────────────────────────────

def test_want_a_rule_asks_for_content_never_calls_ollama(app):
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "I want a yara rule")
        mock_chat.assert_not_called()
        assert result['action'] == 'ask'
        assert 'yara' in result['reply'].lower()


def test_want_a_rule_tolerates_a_typo_in_the_format_name(app):
    # The exact reported case: "yaraa" (typo) right next to "rule" — a
    # light substring fallback (not full fuzzy matching over the whole
    # sentence) still resolves it to yara instead of asking generically.
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "I want a yaraa rule")
        mock_chat.assert_not_called()
        assert result['action'] == 'ask'
        assert 'yara' in result['reply'].lower()




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


def test_create_rule_shortcut_defaults_license_and_source(app):
    # A rule created via the chatbot with no license/source of its own
    # used to show "Unknown" for both — now defaults to a real license and
    # attributes the source to Rulezy + the model it's actually configured
    # to run on, instead of leaving the fields blank.
    from app.core.db_class.db import Rule

    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        history = [{"role": "user", "content": "create a yara rule"}]
        with patch(CHAT):
            result = handle_message(user, history, _YARA_RULE_CONTENT)
        rule_id = int(result['link'].rsplit('/', 1)[-1])
        rule = Rule.query.get(rule_id)
        assert rule.license == "MIT"
        assert rule.source.startswith("Rulezy (")


def test_create_rule_shortcut_never_overrides_a_license_the_rule_specifies(app):
    from app.core.db_class.db import Rule

    content = """rule Own_License_Test {
    meta:
        license = "GPL-3.0"
    strings:
        $a = "marker"
    condition:
        $a
}"""
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        history = [{"role": "user", "content": "create a yara rule"}]
        with patch(CHAT):
            result = handle_message(user, history, content)
        rule_id = int(result['link'].rsplit('/', 1)[-1])
        rule = Rule.query.get(rule_id)
        assert rule.license == "GPL-3.0"


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


def test_create_rule_shortcut_offers_a_link_when_the_rule_already_exists(app):
    # Creating the exact same rule content twice must not be a dead-end
    # error — the second attempt should point back at the rule that's
    # already there (parse_rule_by_format now resolves add_rule_core's
    # DUPLICATE: message back into a real Rule for this).
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        history = [{"role": "user", "content": "create a yara rule"}]

        with patch(CHAT) as mock_chat:
            first = handle_message(user, history, _YARA_RULE_CONTENT)
        assert first['success'] is True
        first_link = first['link']

        with patch(CHAT) as mock_chat:
            second = handle_message(user, history, _YARA_RULE_CONTENT)
        mock_chat.assert_not_called()  # still the deterministic shortcut, not the model
        assert second['success'] is False
        assert 'already exists' in second['reply'].lower()
        assert second['link'] == first_link


def test_search_shortcut_never_hijacks_create_rule_requests(app):
    # The create-verb guard must keep this out of the search shortcut — it's
    # not a search at all. It's now handled by the create-rule-intent
    # shortcut instead (asks for content, deterministically, never the model).
    with app.app_context():
        user = User.query.filter_by(email="admin@admin.admin").first()
        with patch(CHAT) as mock_chat:
            result = handle_message(user, [], "create a yara rule that detects CVE-2024-1234")
        mock_chat.assert_not_called()
        assert 'redirect' not in result
        assert result['action'] == 'ask'


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
