"""
Regression tests for the rule.tag_any permission carve-out in quick_meta
(app/features/rule/rule.py). A user holding rule.tag_any may patch tag_ids
on ANY rule, but that grant must never widen to cves/technique_ids on a
rule they don't own — only a tag_ids-only payload is allowed through.
"""

import uuid

from app import db
from app.core.db_class.db import Rule, RuleTagAssociation, Tag, User
from app.features.roles import roles_core


def _login(client, email):
    user = User.query.filter_by(email=email).first()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True
    return user


def _make_tag():
    tag = Tag.query.filter_by(name="test-tag").first()
    if tag:
        return tag
    admin = User.query.filter_by(email="admin@admin.admin").first()
    tag = Tag(uuid=str(uuid.uuid4()), name="test-tag", created_by=admin.id, source="Manual")
    db.session.add(tag)
    db.session.commit()
    return tag


def test_non_owner_without_permission_is_forbidden(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()
        _login(client, "neo@admin.admin")  # not the rule owner, no role

        res = client.patch(f"/rule/{rule.id}/quick_meta", json={"tag_ids": [tag.id]})
        assert res.status_code == 403
        assert RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag.id).first() is None


def test_tagger_can_tag_any_rule_with_tag_ids_only(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()
        tagger = User.query.filter_by(email="neo@admin.admin").first()
        role = roles_core.get_all_roles()[0]
        role = next(r for r in roles_core.get_all_roles() if r.name == "Tag manager")
        roles_core.add_user_to_role(role.id, tagger.id, granted_by_id=None)

        _login(client, "neo@admin.admin")
        res = client.patch(f"/rule/{rule.id}/quick_meta", json={"tag_ids": [tag.id]})
        assert res.status_code == 200
        assert RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag.id).first() is not None


def test_tagger_cannot_smuggle_other_fields_via_tag_permission(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()
        tagger = User.query.filter_by(email="neo@admin.admin").first()
        role = next(r for r in roles_core.get_all_roles() if r.name == "Tag manager")
        roles_core.add_user_to_role(role.id, tagger.id, granted_by_id=None)

        _login(client, "neo@admin.admin")
        # Mixing tag_ids with cve_ids must fall back to the ownership check
        # and be rejected — rule.tag_any only ever covers a tag_ids-only patch.
        res = client.patch(
            f"/rule/{rule.id}/quick_meta",
            json={"tag_ids": [tag.id], "cve_ids": ["CVE-2024-0001"]},
        )
        assert res.status_code == 403


def test_owner_still_unaffected(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()
        _login(client, "t@t.t")  # the rule's owner

        res = client.patch(
            f"/rule/{rule.id}/quick_meta",
            json={"tag_ids": [tag.id], "cve_ids": ["CVE-2024-0001"]},
        )
        assert res.status_code == 200
        assert RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag.id).first() is not None
