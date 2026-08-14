"""
Tests for opening /rule/bulk_tag and its supporting /jobs/create job types
to non-admin users holding rule.tag_any (the "Tag manager" role), while
making sure they cannot see or reach any OTHER admin page/action:

- /rule/bulk_tag itself: admin OR rule.tag_any may view it, everyone else
  gets access_denied.
- The full admin nav panel embedded in that page (links to Users, Trash,
  Connectors, Logs, ...) must never render for a non-admin, even one with
  rule.tag_any — only admins get it.
- /jobs/create must only accept 'bulk_add_tag_to_rules'/
  'bulk_remove_tag_from_rules' from a rule.tag_any non-admin; every other
  job_type (e.g. 'db_backup', 'connector_pull', 'delete_github_rules')
  must still 403 for them, exactly as it already does for a plain user.
- Sidebar's "Bulk Tag" link appears for a non-admin Tag manager (profile
  dropdown + global search NAV_PAGES) without exposing the admin mega-menu.
"""

from app.core.db_class.db import BackgroundJob, User
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


def test_plain_user_gets_access_denied(app, client):
    with app.app_context():
        _login(client, "t@t.t")
        res = client.get("/rule/bulk_tag")
        assert res.status_code == 200
        assert b"Access Denied" in res.data or b"access" in res.data.lower()
        # Never the real page content
        assert b"Bulk Tag Rules" not in res.data


def test_tag_manager_can_view_bulk_tag_page(app, client):
    with app.app_context():
        _make_tag_manager(app)
        _login(client, "neo@admin.admin")
        res = client.get("/rule/bulk_tag")
        assert res.status_code == 200
        assert b"Bulk Tag Rules" in res.data


def test_admin_can_still_view_bulk_tag_page(app, client):
    with app.app_context():
        _login(client, "admin@admin.admin")
        res = client.get("/rule/bulk_tag")
        assert res.status_code == 200
        assert b"Bulk Tag Rules" in res.data


def test_tag_manager_does_not_see_full_admin_nav_on_bulk_tag_page(app, client):
    """The embedded admin nav panel links to Users/Trash/Connectors/Logs/etc
    — a non-admin Tag manager must not see (or be able to click into) any
    of that, only admins get the panel."""
    with app.app_context():
        _make_tag_manager(app)
        _login(client, "neo@admin.admin")
        res = client.get("/rule/bulk_tag")
        assert res.status_code == 200
        # Admin-nav-panel-only entries that must never reach a non-admin
        assert b"adminNavPanel" not in res.data
        assert b"/account/admin/all_users" not in res.data
        assert b"/connector/list" not in res.data
        assert b"/admin/logs" not in res.data


def test_admin_still_sees_full_admin_nav_on_bulk_tag_page(app, client):
    with app.app_context():
        _login(client, "admin@admin.admin")
        res = client.get("/rule/bulk_tag")
        assert res.status_code == 200
        assert b"adminNavPanel" in res.data


def test_jobs_create_forbidden_for_plain_user(app, client):
    with app.app_context():
        _login(client, "t@t.t")
        res = client.post("/jobs/create", json={"job_type": "bulk_add_tag_to_rules", "payload": {}})
        assert res.status_code == 403


def test_jobs_create_allows_bulk_add_tag_for_tag_manager(app, client):
    with app.app_context():
        _make_tag_manager(app)
        _login(client, "neo@admin.admin")
        res = client.post("/jobs/create", json={
            "job_type": "bulk_add_tag_to_rules",
            "payload": {"tag_ids": [1], "filters": {"rule_ids": [1]}},
        })
        assert res.status_code == 200
        job = BackgroundJob.query.filter_by(uuid=res.get_json()["job"]["uuid"]).first()
        assert job is not None
        assert job.job_type == "bulk_add_tag_to_rules"


def test_jobs_create_allows_bulk_remove_tag_for_tag_manager(app, client):
    with app.app_context():
        _make_tag_manager(app)
        _login(client, "neo@admin.admin")
        res = client.post("/jobs/create", json={
            "job_type": "bulk_remove_tag_from_rules",
            "payload": {"tag_ids": [1], "filters": {"rule_ids": [1]}},
        })
        assert res.status_code == 200


def test_jobs_create_still_forbids_unrelated_job_types_for_tag_manager(app, client):
    """A Tag manager must not be able to smuggle an unrelated admin job type
    (db backup, connector pull, permanent trash delete, ...) through the
    same endpoint just because they hold rule.tag_any."""
    with app.app_context():
        _make_tag_manager(app)
        _login(client, "neo@admin.admin")
        for job_type in ["db_backup", "connector_pull", "delete_github_rules",
                          "trash_permanent_delete_bulk", "update_package"]:
            res = client.post("/jobs/create", json={"job_type": job_type, "payload": {}})
            assert res.status_code == 403, f"{job_type} should still be admin-only"


def test_jobs_create_still_works_for_admin_on_any_job_type(app, client):
    with app.app_context():
        _login(client, "admin@admin.admin")
        res = client.post("/jobs/create", json={"job_type": "bulk_add_tag_to_rules", "payload": {}})
        assert res.status_code == 200


def test_sidebar_shows_bulk_tag_link_for_tag_manager(app, client):
    with app.app_context():
        _make_tag_manager(app)
        _login(client, "neo@admin.admin")
        res = client.get("/rule/rules_list")
        assert res.status_code == 200
        assert b'href="/rule/bulk_tag"' in res.data


def test_sidebar_hides_bulk_tag_link_for_plain_user(app, client):
    with app.app_context():
        _login(client, "t@t.t")
        res = client.get("/rule/rules_list")
        assert res.status_code == 200
        assert b'href="/rule/bulk_tag"' not in res.data


def test_sidebar_admin_mega_menu_absent_for_tag_manager(app, client):
    """A non-admin Tag manager gets the standalone Bulk Tag link, never the
    full Admin dropdown that Bulk Tag lives inside for admins."""
    with app.app_context():
        _make_tag_manager(app)
        _login(client, "neo@admin.admin")
        res = client.get("/rule/rules_list")
        assert res.status_code == 200
        assert b"admin-mega-menu" not in res.data
