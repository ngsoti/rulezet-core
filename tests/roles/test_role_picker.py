"""
Tests for the admin user-list role picker: the /admin/roles/all lightweight
listing endpoint, and users_data_table (account.py) now surfacing each
user's currently assigned roles so the picker can render checked/unchecked
state without a second round-trip per row.
"""

from app.core.db_class.db import User
from app.features.roles import roles_core


def _login(client, email):
    user = User.query.filter_by(email=email).first()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True
    return user


def test_all_roles_endpoint_is_admin_gated(app, client):
    with app.app_context():
        _login(client, "neo@admin.admin")
        res = client.get("/admin/roles/all")
        assert res.status_code == 403


def test_all_roles_endpoint_returns_compact_list(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        _login(client, "admin@admin.admin")
        res = client.get("/admin/roles/all")
        data = res.get_json()
        assert data["success"] is True
        assert any(r["name"] == "Tag manager" for r in data["roles"])
        # compact — no permissions/user_count noise for a dropdown
        assert set(data["roles"][0].keys()) == {"id", "name"}


def test_users_data_table_includes_roles(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        tagger = User.query.filter_by(email="neo@admin.admin").first()
        role = next(r for r in roles_core.get_all_roles() if r.name == "Tag manager")
        roles_core.add_user_to_role(role.id, tagger.id, granted_by_id=None)

        _login(client, "admin@admin.admin")
        res = client.get("/account/users_data_table")
        data = res.get_json()
        row = next(u for u in data["items"] if u["id"] == tagger.id)
        assert row["roles"] == [{"id": role.id, "name": "Tag manager"}]

        other = User.query.filter_by(email="t@t.t").first()
        other_row = next(u for u in data["items"] if u["id"] == other.id)
        assert other_row["roles"] == []
