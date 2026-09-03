"""
Tests for revising an existing proposal (POST /rule/propose_revision/<id>):
continuing a pending/rejected proposal with a follow-up one. The original
proposal is left untouched (still pending/rejected, still fully decidable)
and any number of revisions can be attached to it.
"""

from app import db
from app.core.db_class.db import Rule, RuleEditProposal, User


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


def _make_proposal(rule_id, user_id, status="pending", proposed_content="rule test { condition: 0 }"):
    proposal = RuleEditProposal(
        rule_id=rule_id, user_id=user_id,
        proposed_content=proposed_content,
        old_content="rule test { condition: 1 }",
        message="original justification",
        status=status,
    )
    db.session.add(proposal)
    db.session.commit()
    return proposal.id


def test_author_can_revise_pending_proposal(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        author = User.query.filter_by(email="t@t.t").first()
        proposal_id = _make_proposal(rule.id, author.id)

    _login(client, "t@t.t", "password1@A")
    res = client.post(f"/rule/propose_revision/{proposal_id}",
                       data={"rule_content": "rule test { condition: 2 }", "message": "v2", "edit_type": "content_update"},
                       headers={"Accept": "application/json"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

    with app.app_context():
        old = RuleEditProposal.query.get(proposal_id)
        assert old.status == "pending"  # left untouched — still fully decidable
        new = RuleEditProposal.query.filter_by(previous_proposal_id=proposal_id).first()
        assert new is not None
        assert new.proposed_content == "rule test { condition: 2 }"
        assert new.status == "pending"


def test_can_revise_the_same_proposal_multiple_times(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        author = User.query.filter_by(email="t@t.t").first()
        proposal_id = _make_proposal(rule.id, author.id)

    _login(client, "t@t.t", "password1@A")
    for content in ("rule test { condition: 2 }", "rule test { condition: 3 }"):
        res = client.post(f"/rule/propose_revision/{proposal_id}",
                           data={"rule_content": content, "message": "v", "edit_type": "content_update"},
                           headers={"Accept": "application/json"})
        assert res.status_code == 200

    with app.app_context():
        base = RuleEditProposal.query.get(proposal_id)
        assert base.status == "pending"
        assert RuleEditProposal.query.filter_by(previous_proposal_id=proposal_id).count() == 2


def test_author_can_revise_rejected_proposal(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        author = User.query.filter_by(email="t@t.t").first()
        proposal_id = _make_proposal(rule.id, author.id, status="rejected")

    _login(client, "t@t.t", "password1@A")
    res = client.post(f"/rule/propose_revision/{proposal_id}",
                       data={"rule_content": "rule test { condition: 2 }", "message": "fix", "edit_type": "content_update"},
                       headers={"Accept": "application/json"})
    assert res.status_code == 200


def test_non_author_non_admin_cannot_revise(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        author = User.query.filter_by(email="t@t.t").first()
        proposal_id = _make_proposal(rule.id, author.id)
        _make_other_user()

    _login(client, "other@t.t", "password1@A")
    res = client.post(f"/rule/propose_revision/{proposal_id}",
                       data={"rule_content": "rule test { condition: 2 }"},
                       headers={"Accept": "application/json"})
    assert res.status_code == 403


def test_cannot_revise_accepted_proposal(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        author = User.query.filter_by(email="t@t.t").first()
        proposal_id = _make_proposal(rule.id, author.id, status="accepted")

    _login(client, "t@t.t", "password1@A")
    res = client.post(f"/rule/propose_revision/{proposal_id}",
                       data={"rule_content": "rule test { condition: 2 }"},
                       headers={"Accept": "application/json"})
    assert res.status_code == 400


def test_get_proposal_exposes_revision_links(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        author = User.query.filter_by(email="t@t.t").first()
        proposal_id = _make_proposal(rule.id, author.id)

    _login(client, "t@t.t", "password1@A")
    res = client.post(f"/rule/propose_revision/{proposal_id}",
                       data={"rule_content": "rule test { condition: 2 }", "message": "v2", "edit_type": "content_update"},
                       headers={"Accept": "application/json"})
    new_id = res.get_json()["redirect_url"].split("id=")[1]

    old_res = client.get(f"/rule/get_proposal?id={proposal_id}")
    old_proposal = old_res.get_json()["proposal"]
    assert old_proposal["status"] == "pending"  # still decidable despite having a revision
    assert old_proposal["revisions"][0]["id"] == int(new_id)
    assert old_proposal["revisions"][0]["status"] == "pending"
    revised_event = next(e for e in old_proposal["system_events"] if e["type"] == "revised")
    assert revised_event["link"] == f"/rule/proposal_content_discuss?id={new_id}"
    assert revised_event["status"] == "pending"

    new_res = client.get(f"/rule/get_proposal?id={new_id}")
    new_proposal = new_res.get_json()["proposal"]
    assert new_proposal["previous_proposal"]["id"] == proposal_id
    created_event = next(e for e in new_proposal["system_events"] if e["type"] == "created")
    assert created_event["link"] == f"/rule/proposal_content_discuss?id={proposal_id}"


def test_accepting_a_revision_auto_rejects_the_parent(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id
        author = User.query.filter_by(email="t@t.t").first()
        proposal_id = _make_proposal(rule.id, author.id)

    _login(client, "t@t.t", "password1@A")
    res = client.post(f"/rule/propose_revision/{proposal_id}",
                       data={"rule_content": "rule test { condition: 2 }", "message": "v2", "edit_type": "content_update"},
                       headers={"Accept": "application/json"})
    revision_id = res.get_json()["redirect_url"].split("id=")[1]

    # Accept the revision (child) — the parent must flip to rejected on its own.
    res = client.get(
        f"/rule/validate_proposal?ruleId={rule_id}&decision=accepted&ruleproposalId={revision_id}")
    assert res.status_code == 200

    with app.app_context():
        parent = RuleEditProposal.query.get(proposal_id)
        revision = RuleEditProposal.query.get(int(revision_id))
        assert revision.status == "accepted"
        assert parent.status == "rejected"
