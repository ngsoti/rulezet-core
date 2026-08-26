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


# ── run_ai_fix loop ────────────────────────────────────────────────────────────

# ── run_ai_fix_streaming event sequence ───────────────────────────────────────

def test_streaming_emits_candidate_and_validated_events_live(app, monkeypatch):
    with app.app_context():
        owner = User.query.filter_by(email="t@t.t").first()
        bad_rule_id = _make_bad_rule(app, owner.id)
        bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)

        fake_agent = _FakeAgent([
            AgentResult(ok=True, content="rule x { condition: true }", model_used="m",
                        meta={"explanation": "Fixed the typo."}),
        ])
        monkeypatch.setattr("app.features.ai.ai_core.get_agent", lambda key: fake_agent)
        monkeypatch.setattr(
            "app.features.rule.rule_format.main_format.verify_syntax_rule_by_format",
            lambda rule_dict: (True, ""),
        )

        events = list(BadRuleModel.run_ai_fix_streaming(bad_rule, owner))
        types = [e["type"] for e in events]

        # The candidate's actual content must appear before validation is known,
        # so the frontend can show the diff without waiting for the final result.
        assert "candidate" in types
        assert "validated" in types
        assert types.index("candidate") < types.index("validated")
        assert types[-1] == "result"

        candidate_event = next(e for e in events if e["type"] == "candidate")
        assert candidate_event["content"] == "rule x { condition: true }"
        assert candidate_event["explanation"] == "Fixed the typo."

        validated_event = next(e for e in events if e["type"] == "validated")
        assert validated_event["valid"] is True
        assert validated_event["message"] is None


def test_streaming_validated_event_reports_failure_reason(app, monkeypatch):
    with app.app_context():
        owner = User.query.filter_by(email="t@t.t").first()
        bad_rule_id = _make_bad_rule(app, owner.id)
        bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)

        fake_agent = _FakeAgent([
            AgentResult(ok=True, content="still broken", model_used="m", meta={}),
            AgentResult(ok=True, content="fixed", model_used="m", meta={}),
        ])
        validations = iter([(False, "line 4: still wrong"), (True, "")])
        monkeypatch.setattr("app.features.ai.ai_core.get_agent", lambda key: fake_agent)
        monkeypatch.setattr(
            "app.features.rule.rule_format.main_format.verify_syntax_rule_by_format",
            lambda rule_dict: next(validations),
        )

        events = list(BadRuleModel.run_ai_fix_streaming(bad_rule, owner))
        validated_events = [e for e in events if e["type"] == "validated"]

        assert len(validated_events) == 2
        assert validated_events[0]["valid"] is False
        assert validated_events[0]["message"] == "line 4: still wrong"
        assert validated_events[1]["valid"] is True


def test_streaming_rejects_fragment_instead_of_full_rule(app, monkeypatch):
    """A real failure mode of the small local model: instead of the full
    rule with the fix applied, it returns just the changed line/section.
    That must never be validated, saved, or fed forward as the next
    attempt's starting content."""
    long_original = "rule x {\n" + "\n".join(f'    $s{i} = "str{i}"' for i in range(20)) + "\n  condition: tru\n}"
    with app.app_context():
        owner = User.query.filter_by(email="t@t.t").first()
        bad_rule_id = _make_bad_rule(app, owner.id)
        bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)
        bad_rule.raw_content = long_original
        db.session.commit()

        fake_agent = _FakeAgent([
            AgentResult(ok=True, content="condition: true", model_used="m", meta={"explanation": "just the fix"}),
            AgentResult(ok=True, content=long_original.replace("tru", "true"), model_used="m", meta={"explanation": "full fix"}),
        ])
        monkeypatch.setattr("app.features.ai.ai_core.get_agent", lambda key: fake_agent)
        monkeypatch.setattr(
            "app.features.rule.rule_format.main_format.verify_syntax_rule_by_format",
            lambda rule_dict: (True, ""),  # would validate fine if it ever got the chance
        )

        events = list(BadRuleModel.run_ai_fix_streaming(bad_rule, owner))
        result = next(e for e in events if e["type"] == "result")

        assert result["ok"] is True
        assert result["fixed_content"] == long_original.replace("tru", "true")
        # The second call must have been seeded with the ORIGINAL content, not the fragment.
        assert fake_agent.calls[1]["content"] == long_original
        assert fake_agent.calls[1]["error_message"] == "syntax error"

        validated_events = [e for e in events if e["type"] == "validated"]
        assert validated_events[0]["valid"] is False
        assert "fragment" in validated_events[0]["message"].lower()


def test_run_ai_fix_succeeds_on_first_attempt(app, monkeypatch):
    with app.app_context():
        owner = User.query.filter_by(email="t@t.t").first()
        bad_rule_id = _make_bad_rule(app, owner.id)
        bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)

        fake_agent = _FakeAgent([
            AgentResult(ok=True, content="rule x { condition: true }", model_used="qwen2.5:7b",
                        meta={"explanation": "Fixed the typo."}),
        ])
        monkeypatch.setattr("app.features.ai.ai_core.get_agent", lambda key: fake_agent)
        monkeypatch.setattr(
            "app.features.rule.rule_format.main_format.verify_syntax_rule_by_format",
            lambda rule_dict: (True, ""),
        )

        result = BadRuleModel.run_ai_fix(bad_rule, owner)

        assert result["ok"] is True
        assert result["fixed_content"] == "rule x { condition: true }"
        assert result["explanation"] == "Fixed the typo."
        assert len(result["attempts"]) == 1
        assert result["attempts"][0]["outcome"] == "valid"
        assert len(fake_agent.calls) == 1

        # Original bad rule row is untouched — only an explicit Save commits anything.
        untouched = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)
        assert untouched.raw_content == "rule x { condition: tru }"
        assert untouched.error_message == "syntax error"

        gens = AIGeneration.query.filter_by(agent_key='rule_fixer').all()
        assert len(gens) == 1
        assert gens[0].content == "rule x { condition: true }"
        assert gens[0].rule_id is None


def test_run_ai_fix_retries_then_succeeds(app, monkeypatch):
    with app.app_context():
        owner = User.query.filter_by(email="t@t.t").first()
        bad_rule_id = _make_bad_rule(app, owner.id)
        bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)

        fake_agent = _FakeAgent([
            AgentResult(ok=True, content="attempt 1", model_used="m", meta={"explanation": "try 1"}),
            AgentResult(ok=True, content="attempt 2 (valid)", model_used="m", meta={"explanation": "try 2"}),
        ])
        validations = iter([(False, "still broken"), (True, "")])
        monkeypatch.setattr("app.features.ai.ai_core.get_agent", lambda key: fake_agent)
        monkeypatch.setattr(
            "app.features.rule.rule_format.main_format.verify_syntax_rule_by_format",
            lambda rule_dict: next(validations),
        )

        result = BadRuleModel.run_ai_fix(bad_rule, owner)

        assert result["ok"] is True
        assert result["fixed_content"] == "attempt 2 (valid)"
        assert len(result["attempts"]) == 2
        assert result["attempts"][0]["outcome"] == "still_invalid"
        assert result["attempts"][1]["outcome"] == "valid"
        # second attempt was seeded with the first attempt's own error, not the original one
        assert fake_agent.calls[1]["error_message"] == "still broken"


def test_run_ai_fix_exhausts_attempts_without_touching_bad_rule(app, monkeypatch):
    with app.app_context():
        owner = User.query.filter_by(email="t@t.t").first()
        bad_rule_id = _make_bad_rule(app, owner.id)
        bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)

        fake_agent = _FakeAgent([
            AgentResult(ok=True, content=f"attempt {i}", model_used="m", meta={})
            for i in range(3)
        ])
        monkeypatch.setattr("app.features.ai.ai_core.get_agent", lambda key: fake_agent)
        monkeypatch.setattr(
            "app.features.rule.rule_format.main_format.verify_syntax_rule_by_format",
            lambda rule_dict: (False, "nope"),
        )

        result = BadRuleModel.run_ai_fix(bad_rule, owner, max_attempts=3)

        assert result["ok"] is False
        assert len(result["attempts"]) == 3
        assert len(fake_agent.calls) == 3
        # Still hands back the last attempt for manual review, not a dead end.
        assert result["fixed_content"] == "attempt 2"

        untouched = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)
        assert untouched.error_message == "syntax error"
        assert AIGeneration.query.filter_by(agent_key='rule_fixer').count() == 0


def test_run_ai_fix_stops_immediately_when_model_could_not_fix(app, monkeypatch):
    with app.app_context():
        owner = User.query.filter_by(email="t@t.t").first()
        bad_rule_id = _make_bad_rule(app, owner.id)
        bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)

        fake_agent = _FakeAgent([
            AgentResult(ok=False, error="The model could not determine a targeted fix for this error."),
        ])
        monkeypatch.setattr("app.features.ai.ai_core.get_agent", lambda key: fake_agent)

        result = BadRuleModel.run_ai_fix(bad_rule, owner, max_attempts=3)

        assert result["ok"] is False
        assert len(result["attempts"]) == 1
        assert len(fake_agent.calls) == 1
        # No candidate was ever produced, so there's nothing to show for review.
        assert result.get("fixed_content") is None


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

        result = BadRuleModel.run_ai_fix(bad_rule, owner, max_attempts=3)

        assert result["ok"] is False
        assert "disabled" in result["error"].lower()
        assert len(result["attempts"]) == 1
