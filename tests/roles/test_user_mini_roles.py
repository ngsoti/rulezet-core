"""
Tests for /account/user_mini/<id> now surfacing roles and a gated is_admin
flag (used by UserChip's hover tooltip), and for the role badges rendered on
the own-profile page and detail_user page.

is_admin must stay gated exactly like detail_user/get_user already are —
this endpoint has no @login_required, so an ungated is_admin would let any
anonymous visitor enumerate who's an admin by hovering/fetching UserChip data.
"""

from app.core.db_class.db import User
from app.features.roles import roles_core


def _login(client, email):
    user = User.query.filter_by(email=email).first()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True
    return user


def test_user_mini_includes_roles(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        target = User.query.filter_by(email="neo@admin.admin").first()
        role = next(r for r in roles_core.get_all_roles() if r.name == "Tag manager")
        roles_core.add_user_to_role(role.id, target.id, granted_by_id=None)

        res = client.get(f"/account/user_mini/{target.id}")
        data = res.get_json()
        assert data["roles"] == [{"id": role.id, "name": "Tag manager"}]


def test_user_mini_hides_is_admin_from_anonymous_viewer(app, client):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        res = client.get(f"/account/user_mini/{admin.id}")
        data = res.get_json()
        assert data["is_admin"] is False


def test_user_mini_hides_is_admin_from_other_non_admin_viewer(app, client):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        _login(client, "t@t.t")
        res = client.get(f"/account/user_mini/{admin.id}")
        data = res.get_json()
        assert data["is_admin"] is False


def test_user_mini_shows_is_admin_to_admin_viewer(app, client):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        _login(client, "admin@admin.admin")
        res = client.get(f"/account/user_mini/{admin.id}")
        data = res.get_json()
        assert data["is_admin"] is True


def test_user_mini_shows_own_is_admin_to_self(app, client):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        _login(client, "admin@admin.admin")
        res = client.get(f"/account/user_mini/{admin.id}")
        data = res.get_json()
        assert data["is_admin"] is True


def test_detail_user_page_renders_role_badge(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        target = User.query.filter_by(email="neo@admin.admin").first()
        role = next(r for r in roles_core.get_all_roles() if r.name == "Tag manager")
        roles_core.add_user_to_role(role.id, target.id, granted_by_id=None)

        _login(client, "admin@admin.admin")
        res = client.get(f"/account/detail_user/{target.id}")
        assert res.status_code == 200
        assert b"Tag manager" in res.data


def test_own_profile_page_renders_role_badge(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        target = User.query.filter_by(email="neo@admin.admin").first()
        role = next(r for r in roles_core.get_all_roles() if r.name == "Tag manager")
        roles_core.add_user_to_role(role.id, target.id, granted_by_id=None)

        _login(client, "neo@admin.admin")
        res = client.get("/account/")
        assert res.status_code == 200
        assert b"Tag manager" in res.data
