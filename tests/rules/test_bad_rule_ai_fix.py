"""
Tests for the Rule Fixer "Try AI fix" feature on the bad-rule edit page
(AI_04_RULE_FIXER.md Phase 1): button gating, permissions, the script-format
denylist, and the bounded repair loop in bad_rule_core.py::run_ai_fix.
"""

from app import db
from app.core.db_class.db import AIAgentConfig, AIGeneration, InvalidRuleModel, User
from app.features.ai.ai_core import AgentResult
from app.features.rule.rules_core import bad_rule_core as BadRuleModel


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _admin(app):
    with app.app_context():
        return User.query.filter_by(email="admin@admin.admin").first()


def _owner(app):
    with app.app_context():
        return User.query.filter_by(email="t@t.t").first()


def _make_bad_rule(app, user_id, rule_type="yara", error_message="syntax error"):
    with app.app_context():
        bad_rule = InvalidRuleModel(
            file_name="broken.yar", error_message=error_message,
            raw_content="rule x { condition: tru }", rule_type=rule_type,
            user_id=user_id, url="Unknown", license="Unknown",
        )
        db.session.add(bad_rule)
        db.session.commit()
        return bad_rule.id


def _set_rule_fixer_enabled(app, enabled):
    with app.app_context():
        cfg = AIAgentConfig.query.filter_by(agent_key='rule_fixer').first()
        if cfg:
            cfg.enabled = enabled
        else:
            db.session.add(AIAgentConfig(agent_key='rule_fixer', enabled=enabled,
                                          max_per_hour=30, timeout_s=120, num_predict=2048))
        db.session.commit()


class _FakeAgent:
    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(kwargs)
        return self._results.pop(0)


# ── button gating (edit_bad_rule.html) ────────────────────────────────────────

def test_ai_fix_button_shown_when_agent_enabled(app, client):
    _set_rule_fixer_enabled(app, True)
    owner = _owner(app)
    bad_rule_id = _make_bad_rule(app, owner.id)
    _login(client, owner)

    res = client.get(f"/rule/bad_rule/{bad_rule_id}/edit")
    assert res.status_code == 200
    assert b"Try AI fix" in res.data


def test_ai_fix_button_hidden_when_agent_disabled(app, client):
    _set_rule_fixer_enabled(app, False)
    owner = _owner(app)
    bad_rule_id = _make_bad_rule(app, owner.id)
    _login(client, owner)

    res = client.get(f"/rule/bad_rule/{bad_rule_id}/edit")
    assert res.status_code == 200
    assert b"Try AI fix" not in res.data


def test_ai_fix_button_hidden_for_script_format_even_when_enabled(app, client):
    _set_rule_fixer_enabled(app, True)
    owner = _owner(app)
    bad_rule_id = _make_bad_rule(app, owner.id, rule_type="nse")
    _login(client, owner)

    res = client.get(f"/rule/bad_rule/{bad_rule_id}/edit")
    assert res.status_code == 200
    assert b"Try AI fix" not in res.data


def test_ai_fix_button_hidden_for_non_yara_formats(app, client):
    """rule_fixer's default model is a YARA-specific fine-tune — restricted
    to YARA only for now, not just the script-format denylist."""
    _set_rule_fixer_enabled(app, True)
    owner = _owner(app)
    for rule_type in ("sigma", "suricata", "crs"):
        bad_rule_id = _make_bad_rule(app, owner.id, rule_type=rule_type)
        _login(client, owner)
        res = client.get(f"/rule/bad_rule/{bad_rule_id}/edit")
        assert res.status_code == 200
        assert b"Try AI fix" not in res.data, f"should be hidden for {rule_type}"


# ── route permissions ──────────────────────────────────────────────────────────

def test_ai_fix_route_requires_login(client, app):
    bad_rule_id = _make_bad_rule(app, _owner(app).id)
    res = client.post(f"/rule/bad_rule/{bad_rule_id}/ai_fix")
    assert res.status_code in (302, 401)


def test_ai_fix_route_forbidden_for_non_owner_non_admin(app, client):
    _set_rule_fixer_enabled(app, True)
    owner = _owner(app)
    bad_rule_id = _make_bad_rule(app, owner.id)
    with app.app_context():
        other = User.query.filter_by(email="neo@admin.admin").first()
    _login(client, other)

    res = client.post(f"/rule/bad_rule/{bad_rule_id}/ai_fix")
    assert res.status_code == 403


def test_ai_fix_route_404_for_missing_bad_rule(app, client):
    _login(client, _admin(app))
    res = client.post("/rule/bad_rule/999999/ai_fix")
    assert res.status_code == 404


def test_ai_fix_route_blocks_script_format(app, client):
    _set_rule_fixer_enabled(app, True)
    owner = _owner(app)
    bad_rule_id = _make_bad_rule(app, owner.id, rule_type="nse")
    _login(client, owner)

    res = client.post(f"/rule/bad_rule/{bad_rule_id}/ai_fix")
    assert res.status_code == 400
    assert res.get_json()["ok"] is False


def test_ai_fix_route_blocks_non_yara_format(app, client):
    _set_rule_fixer_enabled(app, True)
    owner = _owner(app)
    bad_rule_id = _make_bad_rule(app, owner.id, rule_type="sigma")
    _login(client, owner)

    res = client.post(f"/rule/bad_rule/{bad_rule_id}/ai_fix")
    assert res.status_code == 400
    assert res.get_json()["ok"] is False


def test_ai_fix_route_blocks_when_agent_disabled(app, client):
    _set_rule_fixer_enabled(app, False)
    owner = _owner(app)
    bad_rule_id = _make_bad_rule(app, owner.id)
    _login(client, owner)

    res = client.post(f"/rule/bad_rule/{bad_rule_id}/ai_fix")
    assert res.status_code == 400


# ── run_ai_fix_streaming step sequence (one-shot design) ──────────────────────
#
# No retry loop, no verify_syntax_rule_by_format re-validation (see the
# "one-shot redesign" note in bad_rule_core.py and AI_04_RULE_FIXER.md) —
# exactly one call to the agent, then the shared "thinking steps" protocol
# (AI_00_FOUNDATION.md §10): a sequence of {"type": "step", "stage", "text"}
# events, closed by exactly one {"type": "result", ...}.

def test_streaming_emits_step_sequence_then_one_result_on_success(app, monkeypatch):
    with app.app_context():
        owner = User.query.filter_by(email="t@t.t").first()
        bad_rule_id = _make_bad_rule(app, owner.id)
        bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)

        fake_agent = _FakeAgent([
            AgentResult(ok=True, content="rule x { condition: true }", model_used="qwen2.5-coder:7b",
                        meta={"explanation": "Fixed the typo."}),
        ])
        monkeypatch.setattr("app.features.ai.ai_core.get_agent", lambda key: fake_agent)

        events = list(BadRuleModel.run_ai_fix_streaming(bad_rule, owner))
        assert len(fake_agent.calls) == 1  # exactly one model call, no retry

        step_stages = [e["stage"] for e in events if e["type"] == "step"]
        assert step_stages == ["reading", "thinking", "writing", "done"]
        assert all(isinstance(e["text"], str) and e["text"] for e in events if e["type"] == "step")

        assert [e["type"] for e in events][-1] == "result"
        result = events[-1]
        assert result["ok"] is True
        assert result["fixed_content"] == "rule x { condition: true }"
        assert result["explanation"] == "Fixed the typo."

        # Original bad rule row is untouched — only an explicit Save commits anything.
        untouched = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)
        assert untouched.raw_content == "rule x { condition: tru }"
        assert untouched.error_message == "syntax error"

        gens = AIGeneration.query.filter_by(agent_key='rule_fixer').all()
        assert len(gens) == 1
        assert gens[0].content == "rule x { condition: true }"
        assert gens[0].rule_id is None


def test_streaming_rejects_fragment_instead_of_full_rule(app, monkeypatch):
    """A real failure mode of the small local model: instead of the full
    rule with the fix applied, it returns just the changed line/section.
    That must never be saved or shown as a usable candidate — and since
    there's no retry loop anymore, it's simply reported as a failure."""
    long_original = "rule x {\n" + "\n".join(f'    $s{i} = "str{i}"' for i in range(20)) + "\n  condition: tru\n}"
    with app.app_context():
        owner = User.query.filter_by(email="t@t.t").first()
        bad_rule_id = _make_bad_rule(app, owner.id)
        bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)
        bad_rule.raw_content = long_original
        db.session.commit()

        fake_agent = _FakeAgent([
            AgentResult(ok=True, content="condition: true", model_used="m", meta={"explanation": "just the fix"}),
        ])
        monkeypatch.setattr("app.features.ai.ai_core.get_agent", lambda key: fake_agent)

        events = list(BadRuleModel.run_ai_fix_streaming(bad_rule, owner))
        result = next(e for e in events if e["type"] == "result")

        assert result["ok"] is False
        assert "fragment" in result["error"].lower()
        assert len(fake_agent.calls) == 1

        failed_step = next(e for e in events if e["type"] == "step" and e["stage"] == "failed")
        assert "fragment" in failed_step["text"].lower()

        assert AIGeneration.query.filter_by(agent_key='rule_fixer').count() == 0


def test_streaming_stops_immediately_when_model_could_not_fix(app, monkeypatch):
    with app.app_context():
        owner = User.query.filter_by(email="t@t.t").first()
        bad_rule_id = _make_bad_rule(app, owner.id)
        bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)

        fake_agent = _FakeAgent([
            AgentResult(ok=False, error="The model could not determine a targeted fix for this error."),
        ])
        monkeypatch.setattr("app.features.ai.ai_core.get_agent", lambda key: fake_agent)

        events = list(BadRuleModel.run_ai_fix_streaming(bad_rule, owner))
        step_stages = [e["stage"] for e in events if e["type"] == "step"]
        assert step_stages == ["reading", "thinking", "failed"]

        result = next(e for e in events if e["type"] == "result")
        assert result["ok"] is False
        assert len(fake_agent.calls) == 1
        # No candidate was ever produced, so there's nothing to show for review.
        assert result.get("fixed_content") is None


def test_run_ai_fix_succeeds_end_to_end(app, monkeypatch):
    with app.app_context():
        owner = User.query.filter_by(email="t@t.t").first()
        bad_rule_id = _make_bad_rule(app, owner.id)
        bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)

        fake_agent = _FakeAgent([
            AgentResult(ok=True, content="rule x { condition: true }", model_used="qwen2.5-coder:7b",
                        meta={"explanation": "Fixed the typo."}),
        ])
        monkeypatch.setattr("app.features.ai.ai_core.get_agent", lambda key: fake_agent)

        result = BadRuleModel.run_ai_fix(bad_rule, owner)

        assert result["ok"] is True
        assert result["fixed_content"] == "rule x { condition: true }"
        assert result["explanation"] == "Fixed the typo."
        assert len(fake_agent.calls) == 1


def test_run_ai_fix_respects_disabled_agent_end_to_end(app):
    """No mocking here — exercises the real AIAgent.run() enabled-check, so
    a disabled agent never reaches Ollama at all."""
    with app.app_context():
        db.session.add(AIAgentConfig(agent_key='rule_fixer', enabled=False,
                                      max_per_hour=30, timeout_s=120, num_predict=2048))
        db.session.commit()
        owner = User.query.filter_by(email="t@t.t").first()
        bad_rule_id = _make_bad_rule(app, owner.id)
        bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)

        result = BadRuleModel.run_ai_fix(bad_rule, owner)

        assert result["ok"] is False
        assert "disabled" in result["error"].lower()
