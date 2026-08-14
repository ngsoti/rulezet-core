"""
Tests for the additive Role/Permission system (app/features/roles/roles_core.py)
and User.has_permission(). Admins must keep bypassing every check unchanged;
this system only ever grants a non-admin extra capability, never restricts one.
"""

from app import db
from app.core.db_class.db import Permission, Role, RolePermission, UserRole, User
from app.features.roles import roles_core


def test_seed_is_idempotent(app):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        roles_core.seed_default_permissions_and_roles()

        assert Permission.query.filter_by(key="rule.tag_any").count() == 1
        role = Role.query.filter_by(name="Tag manager").first()
        assert role is not None
        assert role.is_system is True
        assert RolePermission.query.filter_by(role_id=role.id).count() == 1


def test_admin_has_permission_without_any_role(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        assert admin.has_permission("rule.tag_any") is True
        assert admin.has_permission("some.nonexistent.key") is True


def test_regular_user_lacks_permission_by_default(app):
    with app.app_context():
        user = User.query.filter_by(email="t@t.t").first()
        assert user.has_permission("rule.tag_any") is False


def test_user_gains_permission_via_role_assignment(app):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        user = User.query.filter_by(email="neo@admin.admin").first()
        role = Role.query.filter_by(name="Tag manager").first()

        assert user.has_permission("rule.tag_any") is False

        ok, err = roles_core.add_user_to_role(role.id, user.id, granted_by_id=None)
        assert ok is True, err

        # re-fetch: has_permission queries fresh, but be defensive against
        # any session-level identity-map staleness across the assignment
        db.session.expire(user)
        assert user.has_permission("rule.tag_any") is True

        ok, err = roles_core.remove_user_from_role(role.id, user.id)
        assert ok is True, err
        db.session.expire(user)
        assert user.has_permission("rule.tag_any") is False


def test_get_role_users_reports_who_granted_it(app):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        admin = User.query.filter_by(email="admin@admin.admin").first()
        target = User.query.filter_by(email="neo@admin.admin").first()
        role = Role.query.filter_by(name="Tag manager").first()

        roles_core.add_user_to_role(role.id, target.id, granted_by_id=admin.id)

        result = roles_core.get_role_users(role.id)
        row = next(r for r in result["items"] if r["id"] == target.id)
        assert row["granted_by"] == {
            "id": admin.id, "username": admin.get_username(), "avatar": admin.get_avatar_url(),
        }


def test_get_role_users_granted_by_none_when_unattributed(app):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        target = User.query.filter_by(email="neo@admin.admin").first()
        role = Role.query.filter_by(name="Tag manager").first()

        roles_core.add_user_to_role(role.id, target.id, granted_by_id=None)

        result = roles_core.get_role_users(role.id)
        row = next(r for r in result["items"] if r["id"] == target.id)
        assert row["granted_by"] is None


def test_add_user_to_role_rejects_duplicate(app):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        user = User.query.filter_by(email="neo@admin.admin").first()
        role = Role.query.filter_by(name="Tag manager").first()

        ok, err = roles_core.add_user_to_role(role.id, user.id, granted_by_id=None)
        assert ok is True, err
        ok, err = roles_core.add_user_to_role(role.id, user.id, granted_by_id=None)
        assert ok is False
        assert "already" in err


def test_create_update_delete_role(app):
    with app.app_context():
        role, err = roles_core.create_role("Curator", "Approves community tags")
        assert err is None
        assert role.is_system is False

        role2, err = roles_core.create_role("Curator")
        assert role2 is None
        assert "already exists" in err

        updated, err = roles_core.update_role(role.id, description="Updated description")
        assert err is None
        assert updated.description == "Updated description"

        ok, err = roles_core.delete_role(role.id)
        assert ok is True, err
        assert Role.query.get(role.id) is None


def test_system_role_cannot_be_deleted(app):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        role = Role.query.filter_by(name="Tag manager").first()
        ok, err = roles_core.delete_role(role.id)
        assert ok is False
        assert "System roles" in err
        assert Role.query.get(role.id) is not None


def test_bulk_delete_roles_skips_system_roles(app):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        tagger = Role.query.filter_by(name="Tag manager").first()
        r1, _ = roles_core.create_role("Bulk1")
        r2, _ = roles_core.create_role("Bulk2")

        deleted, skipped = roles_core.bulk_delete_roles([tagger.id, r1.id, r2.id])
        assert deleted == 2
        assert skipped == 1
        assert Role.query.get(tagger.id) is not None
        assert Role.query.get(r1.id) is None
        assert Role.query.get(r2.id) is None


def test_bulk_delete_roles_none_means_all_non_system(app):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        r1, _ = roles_core.create_role("BulkAll1")
        r2, _ = roles_core.create_role("BulkAll2")

        deleted, skipped = roles_core.bulk_delete_roles(None)
        assert deleted == 2
        assert skipped == 1  # the seeded Tag manager system role
        assert Role.query.filter_by(is_system=False).count() == 0
        assert Role.query.filter_by(name="Tag manager").first() is not None


def test_set_role_permissions_syncs_wholesale(app):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        tag_perm = Permission.query.filter_by(key="rule.tag_any").first()
        extra_perm = Permission(uuid="11111111-1111-1111-1111-111111111111",
                                 key="test.other", label="Other", description=None)
        db.session.add(extra_perm)
        db.session.commit()

        role, _ = roles_core.create_role("Multi")
        ok, err = roles_core.set_role_permissions(role.id, [tag_perm.id, extra_perm.id])
        assert ok is True, err
        assert RolePermission.query.filter_by(role_id=role.id).count() == 2

        # Resubmitting with only one permission must remove the other, not just add.
        ok, err = roles_core.set_role_permissions(role.id, [tag_perm.id])
        assert ok is True, err
        remaining = RolePermission.query.filter_by(role_id=role.id).all()
        assert len(remaining) == 1
        assert remaining[0].permission_id == tag_perm.id
