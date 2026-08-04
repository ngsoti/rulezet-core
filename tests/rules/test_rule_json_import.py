"""
Tests for the "From JSON" tab on /rule/create_rule
(POST /rule/import_from_json, app/features/rule/rule.py).

Covers what the other create-rule paths (Manual/Parse) already exercise —
syntax validation, duplicate detection — plus the two things unique to
this route: a uuid-based duplicate check (add_rule_core only dedups by
content) and the fact that user_id must always come from the submitter,
never from the pasted JSON.
"""
import json

from app.core.db_class.db import Rule

VALID_PAYLOAD = {
    "title": "JSON Import Test Rule",
    "format": "yara",
    "to_string": "rule json_import_test { condition: true }",
    "license": "MIT",
    "description": "Imported via the JSON tab",
    "source": "unit-test",
    "author": "Someone Else",
    "version": "2.0",
    "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
}


def login(client, email, password):
    return client.post("/account/login", data={
        "email": email,
        "password": password,
        "remember_me": False,
    }, follow_redirects=True)


def login_user(client):
    return login(client, "t@t.t", "password1@A")


def login_admin(client):
    return login(client, "admin@admin.admin", "admin")


def import_json(client, payload):
    return client.post("/rule/import_from_json",
                        data={"rule_json": json.dumps(payload)},
                        follow_redirects=True)


def test_requires_login(client):
    resp = client.post("/rule/import_from_json",
                        data={"rule_json": json.dumps(VALID_PAYLOAD)},
                        follow_redirects=False)
    assert resp.status_code == 302
    assert "/account/login" in resp.headers["Location"]


def test_valid_import_creates_rule_owned_by_submitter(client, app):
    login_user(client)
    resp = import_json(client, VALID_PAYLOAD)
    assert resp.status_code == 200
    assert "/rule/detail_rule/" in resp.request.path or resp.request.path.startswith("/rule/detail_rule")

    with app.app_context():
        rule = Rule.query.filter_by(title=VALID_PAYLOAD["title"]).first()
        assert rule is not None
        assert rule.original_uuid == VALID_PAYLOAD["uuid"]
        # a fresh uuid is always generated — the pasted one only becomes original_uuid
        assert rule.uuid != VALID_PAYLOAD["uuid"]


def test_user_id_is_forced_to_submitter_not_spoofable(client, app):
    login_user(client)
    spoofed = dict(VALID_PAYLOAD, user_id=999999)
    import_json(client, spoofed)

    with app.app_context():
        rule = Rule.query.filter_by(title=VALID_PAYLOAD["title"]).first()
        assert rule is not None
        assert rule.user_id != 999999
        from app.core.db_class.db import User
        t = User.query.filter_by(email="t@t.t").first()
        assert rule.user_id == t.id


def test_bad_syntax_is_rejected(client, app):
    login_user(client)
    bad = dict(VALID_PAYLOAD, title="Bad Syntax JSON Rule",
               to_string="rule test { condition: }")  # missing expression — invalid YARA
    resp = import_json(client, bad)
    assert resp.status_code == 200
    assert b"Invalid rule" in resp.data or b"error" in resp.data.lower()

    with app.app_context():
        assert Rule.query.filter_by(title="Bad Syntax JSON Rule").first() is None


def test_duplicate_uuid_is_rejected(client, app):
    login_user(client)
    import_json(client, VALID_PAYLOAD)  # first import succeeds

    again = dict(VALID_PAYLOAD, title="A Different Title",
                  to_string="rule a_totally_different_body { condition: true }")
    resp = import_json(client, again)
    assert b"already exists" in resp.data

    with app.app_context():
        assert Rule.query.filter_by(title="A Different Title").first() is None
        # only the first import's rule exists for that uuid
        assert Rule.query.filter_by(original_uuid=VALID_PAYLOAD["uuid"]).count() == 1


def test_duplicate_content_is_rejected(client, app):
    login_user(client)
    import_json(client, VALID_PAYLOAD)  # first import succeeds

    same_content = dict(VALID_PAYLOAD, title="Different Title Same Body",
                         uuid="11111111-2222-3333-4444-555555555555")
    resp = import_json(client, same_content)
    assert b"content matches" in resp.data

    with app.app_context():
        assert Rule.query.filter_by(title="Different Title Same Body").first() is None


def test_invalid_json_is_rejected(client):
    login_user(client)
    resp = client.post("/rule/import_from_json",
                        data={"rule_json": "{not valid json"},
                        follow_redirects=True)
    assert b"Invalid JSON" in resp.data


def test_non_object_json_is_rejected(client):
    login_user(client)
    resp = client.post("/rule/import_from_json",
                        data={"rule_json": json.dumps(["a", "list", "not", "an", "object"])},
                        follow_redirects=True)
    assert b"single rule object" in resp.data


def test_empty_body_is_rejected(client):
    login_user(client)
    resp = client.post("/rule/import_from_json", data={"rule_json": ""}, follow_redirects=True)
    assert b"Paste the rule JSON" in resp.data


def test_oversized_payload_is_rejected(client):
    login_user(client)
    huge = json.dumps(dict(VALID_PAYLOAD, description="x" * 400_000))
    resp = client.post("/rule/import_from_json", data={"rule_json": huge}, follow_redirects=True)
    assert b"too large" in resp.data


def test_missing_required_fields_is_rejected(client, app):
    login_user(client)
    resp = import_json(client, {"title": "Only A Title"})
    assert b"must include" in resp.data

    with app.app_context():
        assert Rule.query.filter_by(title="Only A Title").first() is None


def test_extra_unknown_fields_are_ignored(client, app):
    login_user(client)
    payload = dict(VALID_PAYLOAD, title="Rule With Extra Fields",
                    to_string="rule extra_fields_test { condition: true }",
                    vote_up=99999, admin=True, password_hash="hacked", id=1)
    resp = import_json(client, payload)
    assert resp.status_code == 200

    with app.app_context():
        rule = Rule.query.filter_by(title="Rule With Extra Fields").first()
        assert rule is not None
        assert rule.vote_up == 0
        assert rule.id != 1


def test_admin_can_also_import(client, app):
    login_admin(client)
    payload = dict(VALID_PAYLOAD, title="Admin Imported Rule",
                    to_string="rule admin_import_test { condition: true }")
    import_json(client, payload)

    with app.app_context():
        from app.core.db_class.db import User
        admin = User.query.filter_by(email="admin@admin.admin").first()
        rule = Rule.query.filter_by(title="Admin Imported Rule").first()
        assert rule is not None
        assert rule.user_id == admin.id
