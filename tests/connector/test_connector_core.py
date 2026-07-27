"""
Unit tests for connector_core.py business logic functions.
Tests run in app context directly against the SQLite test DB.
"""

import datetime
import uuid

import pytest

from app import db
from app.core.db_class.db import (
    Bundle, BundleRuleAssociation, Connector, Rule,
    RuleTagAssociation, RuleUpdateHistory, Tag, User,
)
from app.features.connector import connector_core as core


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def admin(app):
    with app.app_context():
        yield User.query.filter_by(email="admin@admin.admin").first()


@pytest.fixture
def connector(app, admin):
    """Create a fresh connector for each test."""
    with app.app_context():
        c = core.create_connector(
            owner_id=admin.id,
            name="UnitTestConn",
            instance_url="http://unit.test.example.com",
        )
        yield c
        # Teardown: delete if still exists
        existing = Connector.query.filter_by(uuid=c.uuid).first()
        if existing:
            db.session.delete(existing)
            db.session.commit()


def _remote_rule(title="Remote Rule", to_string="rule r { condition: true }",
                 fmt="yara", rule_uuid=None):
    return {
        "uuid":           rule_uuid or str(uuid.uuid4()),
        "format":         fmt,
        "title":          title,
        "description":    "A remote rule",
        "to_string":      to_string,
        "author":         "remote-author",
        "source":         "https://github.com/remote/repo",
        "version":        1,
        "license":        "MIT",
        "tags":           [],
        "update_history": [],
    }


# ── _get_or_create_shadow_user ────────────────────────────────────────────────

def test_shadow_user_created_on_first_call(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        assert shadow is not None
        assert shadow.id is not None
        assert "@connector.local" in shadow.email


def test_shadow_user_idempotent(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        s1 = core._get_or_create_shadow_user(c)
        s2 = core._get_or_create_shadow_user(c)
        assert s1.id == s2.id


def test_shadow_user_cannot_login(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        # Password is a random UUID hex — not a real password
        assert not shadow.verify_password("password")
        assert not shadow.verify_password("")


def test_shadow_user_is_not_admin(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        assert shadow.admin is False


def test_shadow_user_not_verified(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        assert shadow.is_verified is False


# ── _upsert_rule ──────────────────────────────────────────────────────────────

def test_upsert_creates_new_rule(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Brand New Rule")
        result = core._upsert_rule(c, shadow.id, remote)
        assert result == "created"
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        assert rule is not None
        assert rule.title == "Brand New Rule"


def test_upsert_skips_identical_existing_rule(app, connector):
    """Re-pulling an unchanged rule returns skipped."""
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Existing Rule")
        core._upsert_rule(c, shadow.id, remote)
        result = core._upsert_rule(c, shadow.id, remote)
        assert result == "skipped"


def test_upsert_matches_by_uuid_only_not_content(app, connector):
    """Two rules with identical content but different uuids are distinct."""
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        content = "rule same_content { condition: true }"
        remote1 = _remote_rule(title="Original", to_string=content)
        remote2 = _remote_rule(title="Duplicate Content", to_string=content)
        core._upsert_rule(c, shadow.id, remote1)
        result = core._upsert_rule(c, shadow.id, remote2)
        assert result == "created"


def test_upsert_invalid_without_uuid(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule()
        remote["uuid"] = None
        result = core._upsert_rule(c, shadow.id, remote)
        assert result == "invalid"


def test_upsert_sets_connector_id(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Connector Tag Test")
        core._upsert_rule(c, shadow.id, remote)
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        assert rule.connector_id == c.id


def test_upsert_preserves_source(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Source Test")
        remote["source"] = "https://github.com/original/source"
        core._upsert_rule(c, shadow.id, remote)
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        # Source from remote must be preserved, not overwritten with connector URL
        assert rule.source == "https://github.com/original/source"
        assert rule.sync_instance_url == c.instance_url


def test_upsert_shadow_owner(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Shadow Owner Test")
        core._upsert_rule(c, shadow.id, remote)
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        assert rule.user_id == shadow.id


def test_upsert_returns_updated_when_content_changed(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Will Be Updated")
        core._upsert_rule(c, shadow.id, remote)
        remote["to_string"] = "rule r { condition: false }"
        result = core._upsert_rule(c, shadow.id, remote)
        assert result == "updated"


def test_upsert_updates_in_place(app, connector):
    """The local rule keeps its id — it is updated, not deleted/recreated."""
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Old Version")
        core._upsert_rule(c, shadow.id, remote)
        old_rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        old_id = old_rule.id

        remote["title"] = "New Version"
        remote["to_string"] = "rule r { condition: false }"
        core._upsert_rule(c, shadow.id, remote)

        rule = Rule.query.get(old_id)
        assert rule.is_deleted is False
        assert rule.title == "New Version"
        assert rule.to_string == "rule r { condition: false }"
        assert Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).count() == 1


def test_upsert_metadata_only_change_records_metadata_history(app, connector):
    """Title/description-only changes (no content change) are imported and now
    get their own 'metadata' RuleUpdateHistory entry — distinct from a 'content'
    entry — so an admin/connector-driven metadata change is still visible in
    the rule's history."""
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Meta Rule")
        core._upsert_rule(c, shadow.id, remote)
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        rule_id = rule.id

        remote["title"] = "Meta Rule Renamed"
        result = core._upsert_rule(c, shadow.id, remote)
        assert result == "updated"

        rule = Rule.query.get(rule_id)
        assert rule.title == "Meta Rule Renamed"

        entries = RuleUpdateHistory.query.filter_by(rule_id=rule_id).all()
        assert len(entries) == 1
        assert entries[0].change_type == "metadata"
        assert entries[0].old_snapshot["title"] == "Meta Rule"
        assert entries[0].new_snapshot["title"] == "Meta Rule Renamed"


def test_upsert_archives_previous_version(app, connector):
    """A RuleUpdateHistory entry must keep the version that was overwritten."""
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        old_content = "rule r { condition: true }"
        new_content = "rule r { condition: false }"
        remote = _remote_rule(title="Versioned Rule", to_string=old_content)
        core._upsert_rule(c, shadow.id, remote)
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()

        remote["to_string"] = new_content
        core._upsert_rule(c, shadow.id, remote)

        history = RuleUpdateHistory.query.filter_by(rule_id=rule.id).all()
        assert len(history) == 1
        assert history[0].old_content == old_content
        assert history[0].new_content == new_content
        assert history[0].success is True


def test_upsert_restores_deleted_rule(app, connector):
    """A locally deleted rule is restored (same id) on pull."""
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Deleted Then Pulled")
        core._upsert_rule(c, shadow.id, remote)
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        rule_id = rule.id
        rule.is_deleted = True
        rule.deleted_at = datetime.datetime.utcnow()
        db.session.commit()

        result = core._upsert_rule(c, shadow.id, remote)
        assert result == "updated"

        rule = Rule.query.get(rule_id)
        assert rule.is_deleted is False
        assert rule.deleted_at is None
        assert Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).count() == 1


def test_upsert_imports_remote_history(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="History Rule")
        remote["update_history"] = [
            {"old_content": "old", "new_content": "new",
             "message": "fix", "success": True,
             "analyzed_at": "2024-01-15T10:00:00", "manuel_submit": False}
        ]
        core._upsert_rule(c, shadow.id, remote)
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        history = RuleUpdateHistory.query.filter_by(rule_id=rule.id).all()
        assert len(history) == 1
        assert history[0].message == "fix"


# ── _upsert_bundle ────────────────────────────────────────────────────────────

def _remote_bundle(name="Remote Bundle", bundle_uuid=None):
    now = datetime.datetime.utcnow().isoformat()
    return {
        "uuid":        bundle_uuid or str(uuid.uuid4()),
        "name":        name,
        "description": "A remote bundle",
        "updated_at":  now,
        "created_at":  now,
    }


def test_upsert_bundle_creates_new(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_bundle(name="New Bundle")
        result = core._upsert_bundle(c, shadow.id, remote)
        assert result == "created"
        b = Bundle.query.filter_by(remote_bundle_uuid=remote["uuid"]).first()
        assert b is not None
        assert b.name == "New Bundle"


def test_upsert_bundle_skips_identical_existing(app, connector):
    """Re-pulling an unchanged bundle returns skipped."""
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_bundle(name="Existing Bundle")
        core._upsert_bundle(c, shadow.id, remote)
        result = core._upsert_bundle(c, shadow.id, remote)
        assert result == "skipped"


def test_upsert_bundle_updates_when_newer(app, connector):
    """A bundle with a newer remote timestamp gets its fields updated."""
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_bundle(name="Original Name")
        core._upsert_bundle(c, shadow.id, remote)

        remote["name"] = "Updated Name"
        remote["updated_at"] = datetime.datetime(2099, 1, 1).isoformat()
        result = core._upsert_bundle(c, shadow.id, remote)
        assert result == "updated"

        b = Bundle.query.filter_by(remote_bundle_uuid=remote["uuid"]).first()
        assert b.name == "Updated Name"


def test_upsert_bundle_invalid_without_uuid(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_bundle()
        remote["uuid"] = None
        result = core._upsert_bundle(c, shadow.id, remote)
        assert result == "invalid"


def test_upsert_bundle_sets_connector_id(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_bundle(name="Connector Bundle")
        core._upsert_bundle(c, shadow.id, remote)
        b = Bundle.query.filter_by(remote_bundle_uuid=remote["uuid"]).first()
        assert b.connector_id == c.id


def test_upsert_bundle_attaches_rules(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote_r = _remote_rule(title="Bundle Member")
        core._upsert_rule(c, shadow.id, remote_r)

        remote_b = _remote_bundle(name="Bundle With Rules")
        remote_b["rules"] = [remote_r["uuid"]]
        core._upsert_bundle(c, shadow.id, remote_b)
        db.session.commit()

        bundle = Bundle.query.filter_by(remote_bundle_uuid=remote_b["uuid"]).first()
        rule = Rule.query.filter_by(remote_rule_uuid=remote_r["uuid"]).first()
        assoc = BundleRuleAssociation.query.filter_by(
            bundle_id=bundle.id, rule_id=rule.id).first()
        assert assoc is not None


def test_upsert_bundle_repairs_missing_rules(app, connector):
    """An already-imported bundle gets its missing rules attached on re-pull."""
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote_b = _remote_bundle(name="Initially Empty Bundle")
        core._upsert_bundle(c, shadow.id, remote_b)

        remote_r = _remote_rule(title="Late Member")
        core._upsert_rule(c, shadow.id, remote_r)
        remote_b["rules"] = [remote_r["uuid"]]
        result = core._upsert_bundle(c, shadow.id, remote_b)
        db.session.commit()
        assert result == "updated"

        bundle = Bundle.query.filter_by(remote_bundle_uuid=remote_b["uuid"]).first()
        rule = Rule.query.filter_by(remote_rule_uuid=remote_r["uuid"]).first()
        assoc = BundleRuleAssociation.query.filter_by(
            bundle_id=bundle.id, rule_id=rule.id).first()
        assert assoc is not None


def test_upsert_bundle_unknown_rule_uuids_skipped(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote_b = _remote_bundle(name="Bundle Unknown Rules")
        remote_b["rules"] = [str(uuid.uuid4()), str(uuid.uuid4())]
        result = core._upsert_bundle(c, shadow.id, remote_b)
        db.session.commit()
        assert result == "created"
        bundle = Bundle.query.filter_by(remote_bundle_uuid=remote_b["uuid"]).first()
        assert BundleRuleAssociation.query.filter_by(bundle_id=bundle.id).count() == 0


# ── _sync_tags ────────────────────────────────────────────────────────────────

def _make_tag(app, name="test:tag", color="#ff0000"):
    with app.app_context():
        import uuid as _uuid_helper
        admin_id = User.query.filter_by(email="admin@admin.admin").first().id
        tag = Tag(
            uuid=str(_uuid_helper.uuid4()),
            name=name,
            color=color,
            visibility=True,
            created_by=admin_id,
        )
        db.session.add(tag)
        db.session.commit()
        return tag.id


def test_sync_tags_attaches_existing_tag(app, connector):
    tag_id = _make_tag(app, name="tlp:clear")
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Tag Test Rule")
        remote["tags"] = ["tlp:clear"]
        core._upsert_rule(c, shadow.id, remote)
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        assoc = RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag_id).first()
        assert assoc is not None


def test_sync_tags_ignores_unknown_tags(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Unknown Tag Rule")
        remote["tags"] = ["nonexistent:tag-xyz"]
        result = core._upsert_rule(c, shadow.id, remote)
        # Must not crash; rule is still created
        assert result == "created"


def test_sync_tags_no_duplicates(app, connector):
    tag_id = _make_tag(app, name="sigma:high")
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Dup Tag Rule")
        remote["tags"] = ["sigma:high", "sigma:high"]  # intentional duplicate
        core._upsert_rule(c, shadow.id, remote)
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        assocs = RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag_id).all()
        assert len(assocs) == 1


# ── _import_rule_history ──────────────────────────────────────────────────────

def test_import_history_adds_entries(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="History Import Rule")
        remote["update_history"] = [
            {"old_content": "v1", "new_content": "v2", "message": "update1",
             "success": True, "analyzed_at": "2024-03-01T12:00:00", "manuel_submit": False},
            {"old_content": "v2", "new_content": "v3", "message": "update2",
             "success": True, "analyzed_at": "2024-04-01T12:00:00", "manuel_submit": True},
        ]
        core._upsert_rule(c, shadow.id, remote)
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        history = RuleUpdateHistory.query.filter_by(rule_id=rule.id).all()
        assert len(history) == 2


def test_import_history_deduplicates_by_timestamp(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Dup History Rule")
        same_ts = "2024-05-01T08:00:00"
        remote["update_history"] = [
            {"old_content": "a", "new_content": "b", "message": "first",
             "success": True, "analyzed_at": same_ts, "manuel_submit": False},
            {"old_content": "a", "new_content": "b", "message": "duplicate",
             "success": True, "analyzed_at": same_ts, "manuel_submit": False},
        ]
        core._upsert_rule(c, shadow.id, remote)
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        history = RuleUpdateHistory.query.filter_by(rule_id=rule.id).all()
        assert len(history) == 1


def test_import_history_empty_list_is_ok(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="No History Rule")
        remote["update_history"] = []
        result = core._upsert_rule(c, shadow.id, remote)
        assert result == "created"


# ── create_connector / delete_connector CRUD ──────────────────────────────────

def test_create_connector_strips_trailing_slash(app, admin):
    with app.app_context():
        c = core.create_connector(
            owner_id=admin.id,
            name="SlashTest",
            instance_url="http://example.com/",
        )
        assert c.instance_url == "http://example.com"
        db.session.delete(c)
        db.session.commit()


def test_create_connector_default_active(app, admin):
    with app.app_context():
        c = core.create_connector(
            owner_id=admin.id,
            name="ActiveTest",
            instance_url="http://active.example.com",
        )
        assert c.is_active is True
        db.session.delete(c)
        db.session.commit()


def test_delete_connector_nullifies_rule_connector_id(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Orphan After Delete")
        core._upsert_rule(c, shadow.id, remote)
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        rule_id = rule.id

        core.delete_connector(c)

        rule = Rule.query.get(rule_id)
        assert rule is not None
        assert rule.connector_id is None


def test_system_connector_cannot_be_deleted(app):
    with app.app_context():
        sys_conn = Connector.query.filter_by(is_system=True).first()
        if sys_conn is None:
            pytest.skip("No system connector")
        result = core.delete_connector(sys_conn)
        assert result is False
        assert Connector.query.filter_by(uuid=sys_conn.uuid).first() is not None
