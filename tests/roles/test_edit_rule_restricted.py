"""
Tests for the rule.tag_any-restricted branch of /rule/edit_rule/<id>: a
non-owner Tag Manager can view/POST this page, but the handler only ever
reads tags/vulnerabilities from the request — title/content/format/license/
source/version/description/original_uuid must never change no matter what a
crafted POST body contains. Also covers the matching carve-out on the
/attack/rule/<id>/add|remove endpoints (used live by the page's ATT&CK
widget), contribution crediting, and rule-history logging for all three.
"""

import uuid

from app import db
from app.core.db_class.db import (
    AttackTechnique, Rule, RuleAttackAssociation, RuleEditContribution,
    RuleTagAssociation, RuleUpdateHistory, Tag, User,
)
from app.features.roles import roles_core


def _login(client, email):
    user = User.query.filter_by(email=email).first()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True
    return user


def _make_tag_manager(app):
    roles_core.seed_default_permissions_and_roles()
    user = User.query.filter_by(email="neo@admin.admin").first()
    role = next(r for r in roles_core.get_all_roles() if r.name == "Tag manager")
    roles_core.add_user_to_role(role.id, user.id, granted_by_id=None)
    return user


def _make_tag(name="rest-edit-tag"):
    admin = User.query.filter_by(email="admin@admin.admin").first()
    tag = Tag(uuid=str(uuid.uuid4()), name=name, created_by=admin.id, source="Manual")
    db.session.add(tag)
    db.session.commit()
    return tag


def _make_technique(technique_id="T1059"):
    tech = AttackTechnique.query.filter_by(technique_id=technique_id).first()
    if tech:
        return tech
    tech = AttackTechnique(technique_id=technique_id, name="Command and Scripting Interpreter",
                            tactic_keys=["execution"])
    db.session.add(tech)
    db.session.commit()
    return tech


# ── GET access ────────────────────────────────────────────────────────────────

def test_owner_can_view_edit_rule_normally(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        _login(client, "t@t.t")  # owner
        res = client.get(f"/rule/edit_rule/{rule.id}")
        assert res.status_code == 200
        assert b"Edit " in res.data


def test_plain_user_cannot_view_edit_rule_for_someone_elses_rule(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        _login(client, "neo@admin.admin")  # no role, not owner
        res = client.get(f"/rule/edit_rule/{rule.id}")
        assert res.status_code == 200
        assert b"Access Denied" in res.data or b"access" in res.data.lower()


def test_tag_manager_can_view_edit_rule_in_restricted_mode(app, client):
    with app.app_context():
        _make_tag_manager(app)
        rule = Rule.query.filter_by(title="test").first()
        _login(client, "neo@admin.admin")
        res = client.get(f"/rule/edit_rule/{rule.id}")
        assert res.status_code == 200
        assert b"Save Tags" in res.data
        assert b"rf-restricted" in res.data


def test_owner_sees_normal_unrestricted_edit_page(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        _login(client, "t@t.t")
        res = client.get(f"/rule/edit_rule/{rule.id}")
        assert res.status_code == 200
        assert b"Save Tags" not in res.data


# ── POST — restricted branch only touches tags/vulnerabilities ────────────────

def test_tag_manager_post_updates_tags_and_cve_only(app, client):
    with app.app_context():
        _make_tag_manager(app)
        tag_manager = User.query.filter_by(email="neo@admin.admin").first()
        rule = Rule.query.filter_by(title="test").first()
        original_title = rule.title
        original_content = rule.to_string
        tag = _make_tag()

        _login(client, "neo@admin.admin")
        res = client.post(f"/rule/edit_rule/{rule.id}", data={
            "tags": f'[{{"id": {tag.id}}}]',
            "vulnerabilities": '["CVE-2024-9999"]',
            # A crafted attempt to smuggle other fields through — must be ignored.
            "title": "HIJACKED TITLE",
            "to_string": "rule hijacked { condition: true }",
            "format": "sigma",
        }, follow_redirects=False)
        assert res.status_code == 302

        db.session.refresh(rule)
        assert rule.title == original_title
        assert rule.to_string == original_content
        assert rule.format == "yara"
        assert RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag.id).first() is not None
        assert "CVE-2024-9999" in rule.cve_id


def test_tag_manager_post_credits_contributor_and_writes_history(app, client):
    with app.app_context():
        _make_tag_manager(app)
        tag_manager = User.query.filter_by(email="neo@admin.admin").first()
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag("rest-edit-tag-2")
        history_before = RuleUpdateHistory.query.filter_by(rule_id=rule.id).count()

        _login(client, "neo@admin.admin")
        client.post(f"/rule/edit_rule/{rule.id}", data={
            "tags": f'[{{"id": {tag.id}}}]',
            "vulnerabilities": "[]",
        })

        assert RuleEditContribution.query.filter_by(rule_id=rule.id, user_id=tag_manager.id).first() is not None
        assert RuleUpdateHistory.query.filter_by(rule_id=rule.id).count() == history_before + 1
        entry = RuleUpdateHistory.query.filter_by(rule_id=rule.id).order_by(RuleUpdateHistory.id.desc()).first()
        assert entry.change_type == "metadata"


def test_plain_user_post_to_edit_rule_is_forbidden(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        _login(client, "neo@admin.admin")  # no role at all
        res = client.post(f"/rule/edit_rule/{rule.id}", data={"tags": "[]", "vulnerabilities": "[]"})
        assert res.status_code == 200
        assert b"Access Denied" in res.data or b"access" in res.data.lower()


# ── ATT&CK add/remove carve-out ────────────────────────────────────────────────

def test_tag_manager_can_add_attack_technique(app, client):
    with app.app_context():
        _make_tag_manager(app)
        tag_manager = User.query.filter_by(email="neo@admin.admin").first()
        rule = Rule.query.filter_by(title="test").first()
        tech = _make_technique()

        _login(client, "neo@admin.admin")
        res = client.post(f"/attack/rule/{rule.id}/add", json={"technique_id": tech.technique_id})
        assert res.status_code == 200
        assert res.get_json()["success"] is True
        assert RuleAttackAssociation.query.filter_by(rule_id=rule.id, technique_id=tech.technique_id).first() is not None
        assert RuleEditContribution.query.filter_by(rule_id=rule.id, user_id=tag_manager.id).first() is not None


def test_tag_manager_can_remove_attack_technique(app, client):
    with app.app_context():
        _make_tag_manager(app)
        rule = Rule.query.filter_by(title="test").first()
        tech = _make_technique("T1105")
        db.session.add(RuleAttackAssociation(
            uuid=str(uuid.uuid4()), rule_id=rule.id, technique_id=tech.technique_id,
            user_id=None, source="manual",
        ))
        db.session.commit()

        _login(client, "neo@admin.admin")
        res = client.delete(f"/attack/rule/{rule.id}/remove/{tech.technique_id}")
        assert res.status_code == 200
        assert res.get_json()["success"] is True
        assert RuleAttackAssociation.query.filter_by(rule_id=rule.id, technique_id=tech.technique_id).first() is None


def test_plain_user_cannot_add_attack_technique_to_others_rule(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        tech = _make_technique("T1027")
        _login(client, "neo@admin.admin")  # no role
        res = client.post(f"/attack/rule/{rule.id}/add", json={"technique_id": tech.technique_id})
        assert res.status_code == 403


def test_owner_attack_add_unaffected_by_new_permission_check(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        tech = _make_technique("T1071")
        _login(client, "t@t.t")  # owner
        res = client.post(f"/attack/rule/{rule.id}/add", json={"technique_id": tech.technique_id})
        assert res.status_code == 200


# ── /tags/admin/list access ────────────────────────────────────────────────────

def test_tag_manager_can_view_tags_admin_list(app, client):
    with app.app_context():
        _make_tag_manager(app)
        _login(client, "neo@admin.admin")
        res = client.get("/tags/admin/list")
        assert res.status_code == 200


def test_tag_manager_tags_admin_list_hides_full_admin_nav(app, client):
    with app.app_context():
        _make_tag_manager(app)
        _login(client, "neo@admin.admin")
        res = client.get("/tags/admin/list")
        assert res.status_code == 200
        assert b"adminNavPanel" not in res.data


def test_plain_user_cannot_view_tags_admin_list(app, client):
    with app.app_context():
        _login(client, "neo@admin.admin")  # no role
        res = client.get("/tags/admin/list")
        assert res.status_code == 200
        assert b"Access Denied" in res.data or b"access" in res.data.lower()


def test_tag_manager_passes_admin_only_helper_on_tags_routes(app, client):
    """/tags/toggle_status is gated purely by _admin_only() — confirms the
    Tag Manager exception was added there, not just on the page route."""
    with app.app_context():
        _make_tag_manager(app)
        tag = _make_tag("tm-toggle-status-tag")
        _login(client, "neo@admin.admin")
        res = client.get(f"/tags/toggle_status?tag_uuid={tag.uuid}")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "success"


def test_plain_user_still_blocked_by_admin_only_helper_on_tags_routes(app, client):
    with app.app_context():
        tag = _make_tag("tm-toggle-status-tag-2")
        _login(client, "neo@admin.admin")  # no role
        res = client.get(f"/tags/toggle_status?tag_uuid={tag.uuid}")
        assert res.status_code == 403
