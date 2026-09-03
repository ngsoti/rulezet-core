"""
Tests for editing a pending proposal's author-justification message
(POST /rule/edit_proposal_message/<id>) and the reviewer bookkeeping on
accept/reject (GET /rule/validate_proposal).
"""

from app import db
from app.core.db_class.db import ActivityLog, Rule, RuleEditProposal, User


def _login(client, email, password):
    return client.post("/account/login", data={
        "email": email, "password": password, "remember_me": False,
    }, follow_redirects=True)


def _make_other_user():
    user = User(
        first_name="Other", last_name="User", email="other@t.t",
        password="password1@A", admin=False, api_key="other_api_key",
        is_verified=True,
    )
    db.session.add(user)
    db.session.commit()
    return user.id


def _make_proposal(rule_id, user_id, status="pending"):
    proposal = RuleEditProposal(
        rule_id=rule_id, user_id=user_id,
        proposed_content="rule test { condition: 0 }",
        old_content="rule test { condition: 1 }",
        message="original justification",
        status=status,
    )
    db.session.add(proposal)
    db.session.commit()
    return proposal.id


def test_author_can_edit_pending_proposal(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        author = User.query.filter_by(email="t@t.t").first()
        proposal_id = _make_proposal(rule.id, author.id)

    _login(client, "t@t.t", "password1@A")
    res = client.post(f"/rule/edit_proposal_message/{proposal_id}",
                       json={"message": "updated justification"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["message"] == "updated justification"

    with app.app_context():
        proposal = RuleEditProposal.query.get(proposal_id)
        assert proposal.message == "updated justification"
        log = ActivityLog.query.filter_by(
            target_type="proposal", target_id=proposal_id,
            action="proposal.message_edited").first()
        assert log is not None


def test_non_author_non_admin_cannot_edit(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        author = User.query.filter_by(email="t@t.t").first()
        proposal_id = _make_proposal(rule.id, author.id)
        _make_other_user()

    _login(client, "other@t.t", "password1@A")
    res = client.post(f"/rule/edit_proposal_message/{proposal_id}",
                       json={"message": "hacked"})
    assert res.status_code == 403

    with app.app_context():
        proposal = RuleEditProposal.query.get(proposal_id)
        assert proposal.message == "original justification"


def test_admin_can_edit_pending_proposal(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        author = User.query.filter_by(email="t@t.t").first()
        proposal_id = _make_proposal(rule.id, author.id)

    _login(client, "admin@admin.admin", "admin")
    res = client.post(f"/rule/edit_proposal_message/{proposal_id}",
                       json={"message": "admin edit"})
    assert res.status_code == 200


def test_cannot_edit_decided_proposal(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        author = User.query.filter_by(email="t@t.t").first()
        proposal_id = _make_proposal(rule.id, author.id, status="accepted")

    _login(client, "t@t.t", "password1@A")
    res = client.post(f"/rule/edit_proposal_message/{proposal_id}",
                       json={"message": "too late"})
    assert res.status_code == 400

    with app.app_context():
        proposal = RuleEditProposal.query.get(proposal_id)
        assert proposal.message == "original justification"


def test_validate_proposal_records_reviewer(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        author = User.query.filter_by(email="t@t.t").first()
        proposal_id = _make_proposal(rule.id, author.id)
        rule_id = rule.id

    # create_rule_test() makes t@t.t the rule owner, so logging in as t@t.t
    # satisfies validate_proposal's owner-or-admin check regardless of who
    # authored the proposal.
    _login(client, "t@t.t", "password1@A")
    res = client.get(
        f"/rule/validate_proposal?ruleId={rule_id}&decision=accepted&ruleproposalId={proposal_id}")
    assert res.status_code == 200

    with app.app_context():
        proposal = RuleEditProposal.query.get(proposal_id)
        assert proposal.status == "accepted"
        assert proposal.reviewed_by_id is not None
        assert proposal.reviewed_at is not None
