"""
Route-level smoke tests for the Roles & Permissions admin feature
(app/features/roles/roles.py) — page rendering, admin gate, and the
DataTable-compatible JSON endpoints.
"""

from app.core.db_class.db import Role, User
from app.features.roles import roles_core


def _login(client, email):
    user = User.query.filter_by(email=email).first()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True
    return user


def test_non_admin_is_blocked(app, client):
    with app.app_context():
        _login(client, "neo@admin.admin")
        res = client.get("/admin/roles/list")
        assert res.status_code == 403


def test_anonymous_is_redirected_to_login(app, client):
    res = client.get("/admin/roles/list")
    assert res.status_code == 302
    assert "/account/login" in res.headers["Location"]


def test_admin_can_view_role_list_page(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        _login(client, "admin@admin.admin")
        res = client.get("/admin/roles/list")
        assert res.status_code == 200


def test_admin_can_view_role_detail_page(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        role = Role.query.filter_by(name="Tag manager").first()
        _login(client, "admin@admin.admin")
        res = client.get(f"/admin/roles/detail/{role.id}")
        assert res.status_code == 200
        assert b"Tag manager" in res.data


def test_data_table_endpoint_shape(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        _login(client, "admin@admin.admin")
        res = client.get("/admin/roles/data_table")
        data = res.get_json()
        assert "items" in data and "total" in data and "total_pages" in data
        assert any(r["name"] == "Tag manager" for r in data["items"])


def test_role_users_endpoint_shape(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        role = Role.query.filter_by(name="Tag manager").first()
        _login(client, "admin@admin.admin")
        res = client.get(f"/admin/roles/{role.id}/users")
        data = res.get_json()
        assert "items" in data and "total" in data and "total_pages" in data
