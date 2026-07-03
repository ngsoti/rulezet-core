"""
Tests for the "turn a comment into a GitHub issue" admin action
(POST /api/comments/<uuid>/create_issue).
"""

import os
from unittest.mock import patch, MagicMock

from app.core.db_class.db import Notification, Rule, User


def login_admin(client):
    client.post("/account/login", data={
        "email": "admin@admin.admin",
        "password": "admin",
        "remember_me": False,
    }, follow_redirects=True)
    return client


def login_user(client):
    client.post("/account/login", data={
        "email": "t@t.t",
        "password": "password1@A",
        "remember_me": False,
    }, follow_redirects=True)
    return client


def _post_comment(client, rule_id):
    r = client.post("/api/comments/", json={
        "object_type": "rule",
        "object_id": rule_id,
        "content": "This rule has a false positive on svchost.exe",
    })
    assert r.status_code == 201, r.get_json()
    return r.get_json()["comment"]["uuid"]


def _github_response(status_code=201, number=42):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {
        "html_url": f"https://github.com/rulezet/rulezet-core/issues/{number}",
        "number": number,
    }
    resp.text = ""
    return resp


def test_create_issue_requires_admin(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id

    login_user(client)
    comment_uuid = _post_comment(client, rule_id)

    r = client.post(f"/api/comments/{comment_uuid}/create_issue")
    assert r.status_code == 403


def test_create_issue_requires_token(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id

    login_user(client)
    comment_uuid = _post_comment(client, rule_id)

    login_admin(client)
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("GITHUB_TOKEN", None)
        r = client.post(f"/api/comments/{comment_uuid}/create_issue")
    assert r.status_code == 400
    assert "GITHUB_TOKEN" in r.get_json()["message"]


def test_create_issue_success_and_duplicate_guard(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id

    login_user(client)
    comment_uuid = _post_comment(client, rule_id)

    login_admin(client)
    with patch.dict(os.environ, {"GITHUB_TOKEN": "fake-token"}):
        with patch("app.api.comment.comment_api.requests.post", return_value=_github_response()) as mock_post:
            r = client.post(f"/api/comments/{comment_uuid}/create_issue")
            assert r.status_code == 201, r.get_json()
            data = r.get_json()
            assert data["issue_number"] == 42
            assert data["issue_url"].endswith("/issues/42")

            # GitHub was called against the official repo with a title/body/labels
            called_url = mock_post.call_args.args[0]
            assert called_url == "https://api.github.com/repos/rulezet/rulezet-core/issues"
            payload = mock_post.call_args.kwargs["json"]
            assert payload["title"].startswith("[Admin Proposed]")
            assert "svchost.exe" in payload["body"]
            assert payload["labels"] == ["admin-proposed"]

        # Second call must not hit GitHub again — comment already has an issue
        with patch("app.api.comment.comment_api.requests.post") as mock_post_2:
            r2 = client.post(f"/api/comments/{comment_uuid}/create_issue")
            assert r2.status_code == 400
            assert r2.get_json()["issue_url"].endswith("/issues/42")
            mock_post_2.assert_not_called()


def test_create_issue_invalid_token_alerts_admins(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id
        admin = User.query.filter_by(email="admin@admin.admin").first()
        admin_id = admin.id

    login_user(client)
    comment_uuid = _post_comment(client, rule_id)

    login_admin(client)
    with patch.dict(os.environ, {"GITHUB_TOKEN": "dead-token"}):
        with patch("app.api.comment.comment_api.requests.post",
                    return_value=_github_response(status_code=401)):
            r = client.post(f"/api/comments/{comment_uuid}/create_issue")
    assert r.status_code == 502
    assert "invalid or expired" in r.get_json()["message"]

    with app.app_context():
        notif = Notification.query.filter_by(
            user_id=admin_id, notif_type="github_token_invalid"
        ).first()
        assert notif is not None
        assert notif.link == "/admin/settings"

        # Comment must NOT have been marked as having an issue
        from app.core.db_class.db import UnifiedComment
        c = UnifiedComment.query.filter_by(uuid=comment_uuid).first()
        assert c.github_issue_url is None
