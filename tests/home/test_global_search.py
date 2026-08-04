"""
Tests for the main-nav global search (GET /global_search, app/home.py +
app/home_core.py). Focus: visibility rules must hold for every caller —
anonymous, an authenticated non-owner, the bundle's own author, and an
admin — exactly mirroring the rules already enforced on the bundle list
page (bundle_core.get_all_bundles_page).
"""
import uuid

import pytest

from app import db
from app.core.db_class.db import Bundle, Rule, User

#  ".test" is an RFC 2606 reserved TLD — WTForms' Email() validator rejects
#  it outright, so this mirrors the codebase's own throwaway-domain style
#  (t@t.t, admin@admin.admin in app/core/utils/init_db.py) instead.
OWNER_EMAIL = "owner@owner.owner"
OWNER_PASSWORD = "OwnerPass1@"
OTHER_EMAIL = "other@other.other"
OTHER_PASSWORD = "OtherPass1@"


def login(client, email, password):
    return client.post("/account/login", data={
        "email": email,
        "password": password,
        "remember_me": False,
    }, follow_redirects=True)


def login_admin(client):
    return login(client, "admin@admin.admin", "admin")


@pytest.fixture
def search_fixtures(app):
    """Two non-admin users, and a public + a private bundle both owned by
    `owner` — `other` owns neither, so it stands in for "any other logged-in
    visitor" when checking that private bundles stay private to non-owners.
    """
    with app.app_context():
        owner = User(first_name="Bundle", last_name="Owner", email=OWNER_EMAIL,
                     password=OWNER_PASSWORD, admin=False, is_verified=True)
        other = User(first_name="Other", last_name="Person", email=OTHER_EMAIL,
                     password=OTHER_PASSWORD, admin=False, is_verified=True)
        db.session.add_all([owner, other])
        db.session.commit()

        public_bundle = Bundle(uuid=str(uuid.uuid4()), name="Zephyr Public Bundle",
                                user_id=owner.id, access=True)
        private_bundle = Bundle(uuid=str(uuid.uuid4()), name="Zephyr Private Bundle",
                                 user_id=owner.id, access=False)
        db.session.add_all([public_bundle, private_bundle])
        db.session.commit()

        return {
            "owner_id": owner.id,
            "other_id": other.id,
            "public_id": public_bundle.id,
            "public_uuid": public_bundle.uuid,
            "private_id": private_bundle.id,
            "private_uuid": private_bundle.uuid,
        }


def bundle_names(response):
    return [b["name"] for b in response.get_json()["bundles"]]


def bundle_ids(response):
    return [b["id"] for b in response.get_json()["bundles"]]


# ── Basic shape / rules (always public, no auth gate) ──────────────────────

def test_endpoint_reachable_without_login(client):
    r = client.get("/global_search", query_string={"q": "test"})
    assert r.status_code == 200


def test_empty_query_returns_empty_lists(client):
    r = client.get("/global_search", query_string={"q": ""})
    assert r.status_code == 200
    assert r.get_json() == {"rules": [], "bundles": [], "users": []}


def test_rule_search_finds_seeded_rule_by_title(client):
    r = client.get("/global_search", query_string={"q": "test"})
    titles = [rule["title"] for rule in r.get_json()["rules"]]
    assert "test" in titles


def test_rule_search_by_exact_uuid_returns_that_rule_first(client, app):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        rule_id, rule_uuid = rule.id, rule.uuid

    r = client.get("/global_search", query_string={"q": rule_uuid})
    rules = r.get_json()["rules"]
    assert rules[0]["id"] == rule_id


def test_rule_search_by_exact_numeric_id(client, app):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        rule_id = rule.id

    r = client.get("/global_search", query_string={"q": str(rule_id)})
    rules = r.get_json()["rules"]
    assert rules[0]["id"] == rule_id


# ── Bundle visibility: anonymous ────────────────────────────────────────────

def test_anonymous_sees_only_the_public_bundle(client, search_fixtures):
    r = client.get("/global_search", query_string={"q": "Zephyr"})
    names = bundle_names(r)
    assert "Zephyr Public Bundle" in names
    assert "Zephyr Private Bundle" not in names


def test_anonymous_cannot_find_private_bundle_by_exact_uuid(client, search_fixtures):
    r = client.get("/global_search", query_string={"q": search_fixtures["private_uuid"]})
    assert bundle_ids(r) == []


def test_anonymous_gets_no_user_results(client, search_fixtures):
    r = client.get("/global_search", query_string={"q": "Owner"})
    assert r.get_json()["users"] == []


# ── Bundle visibility: authenticated, not the owner ─────────────────────────

def test_other_authenticated_user_does_not_see_someone_elses_private_bundle(client, search_fixtures):
    login(client, OTHER_EMAIL, OTHER_PASSWORD)
    r = client.get("/global_search", query_string={"q": "Zephyr"})
    names = bundle_names(r)
    assert "Zephyr Public Bundle" in names
    assert "Zephyr Private Bundle" not in names


def test_other_authenticated_user_cannot_find_private_bundle_by_exact_uuid(client, search_fixtures):
    login(client, OTHER_EMAIL, OTHER_PASSWORD)
    r = client.get("/global_search", query_string={"q": search_fixtures["private_uuid"]})
    assert bundle_ids(r) == []


# ── Bundle visibility: the bundle's own author ──────────────────────────────

def test_owner_sees_both_own_public_and_private_bundle(client, search_fixtures):
    login(client, OWNER_EMAIL, OWNER_PASSWORD)
    r = client.get("/global_search", query_string={"q": "Zephyr"})
    names = bundle_names(r)
    assert "Zephyr Public Bundle" in names
    assert "Zephyr Private Bundle" in names


def test_owner_can_find_own_private_bundle_by_exact_uuid(client, search_fixtures):
    login(client, OWNER_EMAIL, OWNER_PASSWORD)
    r = client.get("/global_search", query_string={"q": search_fixtures["private_uuid"]})
    assert search_fixtures["private_id"] in bundle_ids(r)


# ── Bundle visibility: admin sees everything ────────────────────────────────

def test_admin_sees_every_bundle_including_someone_elses_private_one(client, search_fixtures):
    login_admin(client)
    r = client.get("/global_search", query_string={"q": "Zephyr"})
    names = bundle_names(r)
    assert "Zephyr Public Bundle" in names
    assert "Zephyr Private Bundle" in names


def test_admin_can_find_others_private_bundle_by_exact_uuid(client, search_fixtures):
    login_admin(client)
    r = client.get("/global_search", query_string={"q": search_fixtures["private_uuid"]})
    assert search_fixtures["private_id"] in bundle_ids(r)


# ── User search: authenticated-only, safe fields only ───────────────────────

def test_authenticated_user_can_search_users(client, search_fixtures):
    login(client, OTHER_EMAIL, OTHER_PASSWORD)
    r = client.get("/global_search", query_string={"q": "Owner"})
    users = r.get_json()["users"]
    assert any(u["id"] == search_fixtures["owner_id"] for u in users)


def test_user_search_result_never_exposes_email_or_admin_flag(client, search_fixtures):
    login(client, OTHER_EMAIL, OTHER_PASSWORD)
    r = client.get("/global_search", query_string={"q": "Owner"})
    hit = next(u for u in r.get_json()["users"] if u["id"] == search_fixtures["owner_id"])
    assert set(hit.keys()) == {"id", "username", "avatar"}


def test_user_search_by_exact_numeric_id(client, search_fixtures):
    login(client, OTHER_EMAIL, OTHER_PASSWORD)
    r = client.get("/global_search", query_string={"q": str(search_fixtures["owner_id"])})
    users = r.get_json()["users"]
    assert users[0]["id"] == search_fixtures["owner_id"]
