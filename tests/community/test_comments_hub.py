"""
Tests for the cross-object Comments Hub
(page: GET /community/comments — API: GET /api/comments/hub).
"""

import uuid

from app import db
from app.core.db_class.db import Bundle, Rule, RuleEditProposal, UnifiedComment, User


# ── Auth helpers (same pattern as tests/connector/test_connector_crud.py) ─────

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


# ── Data helpers ───────────────────────────────────────────────────────────────

def _make_bundle(user_id, access=True, name="Test bundle"):
    bundle = Bundle(
        uuid=str(uuid.uuid4()),
        name=name,
        description="test bundle",
        user_id=user_id,
        access=access,
    )
    db.session.add(bundle)
    db.session.commit()
    return bundle.id


def _make_comment(object_type, object_id, user_id, content="hello world",
                  parent_id=None, is_active=True):
    comment = UnifiedComment(
        uuid=str(uuid.uuid4()),
        content=content,
        object_type=object_type,
        object_id=object_id,
        created_by=user_id,
        parent_id=parent_id,
        depth=1 if parent_id else 0,
        is_active=is_active,
    )
    db.session.add(comment)
    db.session.commit()
    return comment.id


def _make_proposal(rule_id, user_id):
    proposal = RuleEditProposal(
        rule_id=rule_id,
        user_id=user_id,
        proposed_content="rule test { condition: 0 }",
        old_content="rule test { condition: 1 }",
        message="fix condition",
    )
    db.session.add(proposal)
    db.session.commit()
    return proposal.id


def _get_hub(client, **params):
    from urllib.parse import urlencode
    return client.get("/api/comments/hub?" + urlencode(params))


def _group(data, object_type, object_id):
    return next((i for i in data["items"]
                 if i["object_type"] == object_type and i["object_id"] == object_id), None)


# ── Auth enforcement ───────────────────────────────────────────────────────────

def test_hub_page_requires_login(client):
    r = client.get("/community/comments", follow_redirects=False)
    assert r.status_code in (302, 403)


def test_hub_api_requires_login(client):
    r = client.get("/api/comments/hub")
    assert r.status_code == 401


def test_hub_page_renders_for_logged_in_user(client):
    login_user(client)
    r = client.get("/community/comments")
    assert r.status_code == 200


# ── Privacy: private bundles ───────────────────────────────────────────────────

def test_private_bundle_comments_hidden_from_non_owner(app, client):
    with app.app_context():
        owner = User.query.filter_by(email="neo@admin.admin").first()
        bundle_id = _make_bundle(owner.id, access=False, name="Secret bundle")
        _make_comment("bundle", bundle_id, owner.id,
                      content="private-bundle-secret-comment-content")

    login_user(client)  # t@t.t — not the owner, not admin
    r = _get_hub(client, scope="all")
    assert r.status_code == 200
    data = r.get_json()
    assert _group(data, "bundle", bundle_id) is None
    assert "private-bundle-secret-comment-content" not in r.get_data(as_text=True)
    assert "Secret bundle" not in r.get_data(as_text=True)


def test_private_bundle_comments_visible_to_owner(app, client):
    with app.app_context():
        owner = User.query.filter_by(email="t@t.t").first()
        bundle_id = _make_bundle(owner.id, access=False, name="My private bundle")
        _make_comment("bundle", bundle_id, owner.id, content="my own private note")

    login_user(client)  # t@t.t is the owner
    data = _get_hub(client, scope="all").get_json()
    group = _group(data, "bundle", bundle_id)
    assert group is not None
    assert group["is_private"] is True
    assert group["comment_count"] == 1


def test_private_bundle_comments_visible_to_admin(app, client):
    with app.app_context():
        owner = User.query.filter_by(email="neo@admin.admin").first()
        bundle_id = _make_bundle(owner.id, access=False, name="Secret bundle for admin")
        _make_comment("bundle", bundle_id, owner.id, content="admin should see this")

    login_admin(client)
    data = _get_hub(client, scope="all").get_json()
    group = _group(data, "bundle", bundle_id)
    assert group is not None
    assert group["comment_count"] == 1


def test_public_bundle_comments_visible_to_everyone(app, client):
    with app.app_context():
        owner = User.query.filter_by(email="neo@admin.admin").first()
        bundle_id = _make_bundle(owner.id, access=True, name="Public bundle")
        _make_comment("bundle", bundle_id, owner.id, content="public bundle comment")

    login_user(client)
    data = _get_hub(client, scope="all").get_json()
    assert _group(data, "bundle", bundle_id) is not None


# ── Scope filter (main vs all) ─────────────────────────────────────────────────

def test_scope_main_excludes_replies(app, client):
    with app.app_context():
        user = User.query.filter_by(email="t@t.t").first()
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id
        root_id = _make_comment("rule", rule_id, user.id, content="root comment")
        _make_comment("rule", rule_id, user.id, content="a reply", parent_id=root_id)

    login_user(client)

    data_main = _get_hub(client, scope="main").get_json()
    group_main = _group(data_main, "rule", rule_id)
    assert group_main is not None
    assert group_main["comment_count"] == 1

    data_all = _get_hub(client, scope="all").get_json()
    group_all = _group(data_all, "rule", rule_id)
    assert group_all is not None
    assert group_all["comment_count"] == 2
    assert any(c["is_reply"] for c in group_all["preview"])


# ── Proposal entries fold into their parent rule's group ───────────────────────

def test_proposal_comments_fold_into_parent_rule_group(app, client):
    with app.app_context():
        user = User.query.filter_by(email="t@t.t").first()
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id
        proposal_id = _make_proposal(rule.id, user.id)
        _make_comment("proposal", proposal_id, user.id, content="discussing this edit")

    login_user(client)
    data = _get_hub(client, scope="all").get_json()

    # No standalone "proposal" row — a suggested-edit discussion is a
    # sub-category of its rule's row, not its own hub entry.
    assert _group(data, "proposal", proposal_id) is None

    group = _group(data, "rule", rule_id)
    assert group is not None
    assert group["comment_count"] == 1
    assert len(group["categories"]) == 1
    cat = group["categories"][0]
    assert cat["kind"] == "proposal"
    assert cat["object_type"] == "proposal"
    assert cat["object_id"] == proposal_id
    assert cat["proposal_status"] == "pending"
    assert group["preview"][0]["link"].startswith(
        f"/rule/proposal_content_discuss?id={proposal_id}&comment=")


def test_rule_comments_and_proposal_comments_merge_into_one_row(app, client):
    with app.app_context():
        user = User.query.filter_by(email="t@t.t").first()
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id
        _make_comment("rule", rule_id, user.id, content="plain comment on the rule")
        proposal_id = _make_proposal(rule.id, user.id)
        _make_comment("proposal", proposal_id, user.id, content="discussing the suggested edit")

    login_user(client)
    data = _get_hub(client, scope="all").get_json()

    # One row for the rule, not two — a rule's plain comments and its
    # suggested-edit discussions are the same conversation about the rule.
    assert data["total"] == 1
    group = _group(data, "rule", rule_id)
    assert group is not None
    assert group["comment_count"] == 2
    kinds = sorted(c["kind"] for c in group["categories"])
    assert kinds == ["comment", "proposal"]


# ── Search filter ──────────────────────────────────────────────────────────────

def test_search_filters_by_content(app, client):
    with app.app_context():
        user = User.query.filter_by(email="t@t.t").first()
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id
        bundle_id = _make_bundle(user.id, access=True, name="Search bundle")
        _make_comment("rule", rule_id, user.id, content="zebra-unique-token here")
        _make_comment("bundle", bundle_id, user.id, content="nothing to see")

    login_user(client)
    data = _get_hub(client, scope="all", search="zebra-unique-token").get_json()
    assert data["total"] == 1
    assert _group(data, "rule", rule_id) is not None
    assert _group(data, "bundle", bundle_id) is None


# ── Soft-deleted comments ──────────────────────────────────────────────────────

def test_soft_deleted_comments_never_surface(app, client):
    with app.app_context():
        user = User.query.filter_by(email="t@t.t").first()
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id
        _make_comment("rule", rule_id, user.id,
                      content="deleted-comment-content", is_active=False)

    login_user(client)
    r = _get_hub(client, scope="all")
    data = r.get_json()
    assert _group(data, "rule", rule_id) is None
    assert "deleted-comment-content" not in r.get_data(as_text=True)
