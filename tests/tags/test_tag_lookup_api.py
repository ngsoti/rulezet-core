"""
Tests for GET /api/tags/private/lookup — lets a Tag Manager (or admin) verify
what a tag_id/uuid actually refers to before calling bulk_add with it, or
find a tag's id/uuid by name. Same rule.tag_any-or-admin gate as bulk_add.
"""

import uuid

from app import db
from app.core.db_class.db import Tag, User
from app.features.roles import roles_core


def _make_tag(name="lookup-tag"):
    admin = User.query.filter_by(email="admin@admin.admin").first()
    tag = Tag(uuid=str(uuid.uuid4()), name=name, created_by=admin.id, source="Manual")
    db.session.add(tag)
    db.session.commit()
    return tag


def test_invalid_api_key_is_rejected(app, client):
    with app.app_context():
        res = client.get("/api/tags/private/lookup?id=1", headers={"X-API-KEY": "not-a-real-key"})
        assert res.status_code == 403


def test_api_key_without_permission_is_forbidden(app, client):
    with app.app_context():
        tag = _make_tag()
        res = client.get(f"/api/tags/private/lookup?id={tag.id}", headers={"X-API-KEY": "user_api_key"})
        assert res.status_code == 403


def test_tagger_can_lookup_by_id(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        tagger = User.query.filter_by(email="neo@admin.admin").first()
        role = next(r for r in roles_core.get_all_roles() if r.name == "Tag manager")
        roles_core.add_user_to_role(role.id, tagger.id, granted_by_id=None)
        tag = _make_tag()

        res = client.get(f"/api/tags/private/lookup?id={tag.id}", headers={"X-API-KEY": "user_api_key"})
        assert res.status_code == 200
        data = res.get_json()
        assert len(data["tags"]) == 1
        assert data["tags"][0]["id"] == tag.id
        assert data["tags"][0]["name"] == tag.name


def test_admin_can_lookup_by_uuid(app, client):
    with app.app_context():
        tag = _make_tag()
        res = client.get(f"/api/tags/private/lookup?uuid={tag.uuid}", headers={"X-API-KEY": "admin_api_key"})
        assert res.status_code == 200
        data = res.get_json()
        assert data["tags"][0]["uuid"] == tag.uuid


def test_lookup_by_name_returns_all_matches(app, client):
    with app.app_context():
        t1 = _make_tag("phishing:campaign-a")
        t2 = _make_tag("phishing:campaign-b")
        _make_tag("malware:trojan")

        res = client.get("/api/tags/private/lookup?name=phishing", headers={"X-API-KEY": "admin_api_key"})
        assert res.status_code == 200
        names = {t["name"] for t in res.get_json()["tags"]}
        assert names == {t1.name, t2.name}


def test_lookup_by_id_not_found(app, client):
    with app.app_context():
        res = client.get("/api/tags/private/lookup?id=999999", headers={"X-API-KEY": "admin_api_key"})
        assert res.status_code == 404


def test_lookup_by_name_not_found(app, client):
    with app.app_context():
        res = client.get("/api/tags/private/lookup?name=nonexistent-xyz", headers={"X-API-KEY": "admin_api_key"})
        assert res.status_code == 404


def test_lookup_requires_at_least_one_param(app, client):
    with app.app_context():
        res = client.get("/api/tags/private/lookup", headers={"X-API-KEY": "admin_api_key"})
        assert res.status_code == 400
