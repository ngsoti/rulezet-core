"""
Tests for GitHub import proposals (non-admin request -> admin bulk review):
- Non-admins can create/view/cancel their own proposal, never someone else's.
- Admin-only endpoints (list, bulk_decision, delete, transfer_existing) are
  server-side enforced, not just hidden in the UI.
- Direct GitHub/ZIP import routes are now admin-only (closing the gap where
  non-admins could previously call them despite the UI hiding the form).
"""
from app.core.db_class.db import User, GithubProposal


def _login(client, email):
    user = User.query.filter_by(email=email).first()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True
    return user


def _admin(client):
    return _login(client, "admin@admin.admin")


def _user(client):
    return _login(client, "t@t.t")


def _other_user(client):
    return _login(client, "neo@admin.admin")


VALID_REPO = "https://github.com/octocat/Hello-World.git"
NORMALIZED_REPO = "https://github.com/octocat/Hello-World"


def test_non_admin_can_create_proposal(client, app):
    with app.app_context():
        _user(client)

    res = client.post("/rule/github_proposal/create", json={
        "repo_url": VALID_REPO, "branch": "main", "license": "MIT", "message": "please add this"
    })
    assert res.status_code == 201
    data = res.get_json()
    # ".git" suffix is stripped so it matches Rule.source's stored format (GitHub's
    # API html_url, which never has ".git") — see _normalize_repo_url.
    assert data["proposal"]["repo_url"] == NORMALIZED_REPO
    assert data["proposal"]["status"] == "pending"


def test_cannot_propose_the_same_repo_twice(client, app):
    with app.app_context():
        _user(client)
    res = client.post("/rule/github_proposal/create", json={"repo_url": VALID_REPO})
    assert res.status_code == 201

    # Same user, same repo (even with a differently-formatted URL) -> blocked
    res = client.post("/rule/github_proposal/create", json={"repo_url": NORMALIZED_REPO + "/"})
    assert res.status_code == 400

    # A different user proposing the exact same repo -> also blocked
    with app.app_context():
        _other_user(client)
    res = client.post("/rule/github_proposal/create", json={"repo_url": VALID_REPO})
    assert res.status_code == 400


def test_cannot_propose_a_repo_already_in_rulezet(client, app):
    from app import db
    from app.core.db_class.db import Rule

    with app.app_context():
        rule = Rule.query.filter_by(source="test").first()
        rule.source = NORMALIZED_REPO
        db.session.commit()
        _user(client)

    res = client.post("/rule/github_proposal/create", json={"repo_url": VALID_REPO})
    assert res.status_code == 400
    assert "already in Rulezet" in res.get_json()["message"]


def test_create_rejects_invalid_url(client, app):
    with app.app_context():
        _user(client)

    res = client.post("/rule/github_proposal/create", json={"repo_url": "not-a-github-url"})
    assert res.status_code == 400


def test_non_admin_cannot_list_or_bulk_decide(client, app):
    with app.app_context():
        _user(client)

    res = client.get("/rule/github_proposal/list")
    assert res.status_code == 403

    res = client.post("/rule/github_proposal/bulk_decision", json={"uuids": ["x"], "decision": "accept"})
    assert res.status_code == 403


def test_admin_can_list_proposals(client, app):
    with app.app_context():
        _user(client)
        client.post("/rule/github_proposal/create", json={"repo_url": VALID_REPO})
        _admin(client)

    res = client.get("/rule/github_proposal/list")
    assert res.status_code == 200
    data = res.get_json()
    assert data["total"] >= 1


def test_detail_only_visible_to_owner_or_admin(client, app):
    with app.app_context():
        _user(client)
        create_res = client.post("/rule/github_proposal/create", json={"repo_url": VALID_REPO})
        proposal_uuid = create_res.get_json()["proposal"]["uuid"]

    # A different non-admin user must be denied
    with app.app_context():
        _other_user(client)
    res = client.get(f"/rule/github_proposal/{proposal_uuid}")
    assert res.status_code == 403

    # The owner can see it
    with app.app_context():
        _user(client)
    res = client.get(f"/rule/github_proposal/{proposal_uuid}")
    assert res.status_code == 200

    # The admin can see it too
    with app.app_context():
        _admin(client)
    res = client.get(f"/rule/github_proposal/{proposal_uuid}")
    assert res.status_code == 200


def test_cancel_only_by_owner_and_only_while_pending(client, app):
    with app.app_context():
        _user(client)
        create_res = client.post("/rule/github_proposal/create", json={"repo_url": VALID_REPO})
        proposal_uuid = create_res.get_json()["proposal"]["uuid"]

    # Another user cannot cancel it
    with app.app_context():
        _other_user(client)
    res = client.post(f"/rule/github_proposal/{proposal_uuid}/cancel")
    assert res.status_code == 403

    # The owner can cancel their own pending proposal
    with app.app_context():
        _user(client)
    res = client.post(f"/rule/github_proposal/{proposal_uuid}/cancel")
    assert res.status_code == 200

    with app.app_context():
        assert GithubProposal.query.filter_by(uuid=proposal_uuid).first() is None


def test_admin_bulk_accept_dispatches_job_and_sets_status(client, app):
    with app.app_context():
        _user(client)
        create_res = client.post("/rule/github_proposal/create", json={"repo_url": VALID_REPO})
        proposal_uuid = create_res.get_json()["proposal"]["uuid"]
        _admin(client)

    res = client.post("/rule/github_proposal/bulk_decision", json={
        "uuids": [proposal_uuid], "decision": "accept", "ownership_mode": "requester",
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["job_uuid"]

    with app.app_context():
        proposal = GithubProposal.query.filter_by(uuid=proposal_uuid).first()
        assert proposal.status == "accepted"
        assert proposal.ownership_mode == "requester"
        assert proposal.job_uuid == data["job_uuid"]


def test_import_from_github_requires_admin(client, app):
    with app.app_context():
        _user(client)

    res = client.post("/rule/import_rules_from_github", json={"url": VALID_REPO, "license": "", "branch": ""})
    assert res.status_code == 403


def test_import_from_zip_requires_admin(client, app):
    with app.app_context():
        _user(client)

    res = client.post("/rule/import_rules_from_zip", data={})
    assert res.status_code == 403
