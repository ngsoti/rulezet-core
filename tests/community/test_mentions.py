"""
Tests for the @mention picker's backend pieces:
- GET /account/search_mentionable_users?q=
- @[Name](id) tokens in a posted comment trigger a user_mentioned notification
"""

from app import db
from app.core.db_class.db import Notification, Rule, User


def _login(client, email, password):
    return client.post("/account/login", data={
        "email": email, "password": password, "remember_me": False,
    }, follow_redirects=True)


def _post_comment(client, object_type, object_id, content):
    return client.post("/api/comments/", json={
        "object_type": object_type, "object_id": object_id, "content": content,
    })


def test_search_requires_two_chars(app, client):
    _login(client, "t@t.t", "password1@A")
    res = client.get("/account/search_mentionable_users?q=a")
    assert res.status_code == 200
    assert res.get_json()["users"] == []


def test_search_matches_and_excludes_requester(app, client):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        admin_id = admin.id

    _login(client, "t@t.t", "password1@A")
    res = client.get("/account/search_mentionable_users?q=admin")
    data = res.get_json()
    ids = [u["id"] for u in data["users"]]
    assert admin_id in ids

    _login(client, "admin@admin.admin", "admin")
    res = client.get("/account/search_mentionable_users?q=admin")
    ids = [u["id"] for u in res.get_json()["users"]]
    assert admin_id not in ids  # requester never appears in their own results


def test_mention_in_rule_comment_notifies_mentioned_user(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id
        admin = User.query.filter_by(email="admin@admin.admin").first()
        admin_id = admin.id

    _login(client, "t@t.t", "password1@A")
    res = _post_comment(client, "rule", rule_id, f"cc @[Admin Admin]({admin_id}) take a look")
    assert res.status_code == 201

    with app.app_context():
        notif = Notification.query.filter_by(user_id=admin_id, notif_type="user_mentioned").first()
        assert notif is not None
        assert str(rule_id) in notif.link


def test_self_mention_does_not_notify(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id
        author = User.query.filter_by(email="t@t.t").first()
        author_id = author.id

    _login(client, "t@t.t", "password1@A")
    res = _post_comment(client, "rule", rule_id, f"note to self @[Theo Theo]({author_id})")
    assert res.status_code == 201

    with app.app_context():
        notif = Notification.query.filter_by(user_id=author_id, notif_type="user_mentioned").first()
        assert notif is None
