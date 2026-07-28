"""
Tests for the velociraptor blueprint routes (CRUD + admin-only gating).
All routes require an admin session — mirrors tests/connector/test_connector_crud.py.
"""

from app.core.db_class.db import Rule, VelociraptorServer


def login_admin(client):
    client.post("/account/login", data={
        "email": "admin@admin.admin",
        "password": "admin",
        "remember_me": False,
    }, follow_redirects=True)
    return client


def login_user(client):
    client.post("/account/login", data={
        "email": "t@t.t",
        "password": "password1@A",
        "remember_me": False,
    }, follow_redirects=True)
    return client


FAKE_SERVER_PAYLOAD = {
    "name": "RouteTestServer",
    "api_connection_string": "127.0.0.1:8001",
    "ca_certificate": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
    "client_cert": "-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----",
    "client_key": "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----",
}


# ── Auth enforcement ──────────────────────────────────────────────────────────

def test_list_requires_login(client):
    r = client.get("/velociraptor/list", follow_redirects=False)
    assert r.status_code in (302, 403)


def test_create_requires_admin(client):
    login_user(client)
    r = client.post("/velociraptor/create", json=FAKE_SERVER_PAYLOAD)
    assert r.status_code == 403


def test_get_requires_admin(client):
    login_user(client)
    r = client.get("/velociraptor/get")
    assert r.status_code == 403


# ── CRUD as admin ─────────────────────────────────────────────────────────────

def test_create_list_delete_as_admin(app, client):
    login_admin(client)

    r = client.post("/velociraptor/create", json=FAKE_SERVER_PAYLOAD)
    assert r.status_code == 200
    data = r.get_json()
    assert data["success"] is True
    server_uuid = data["server"]["uuid"]

    # Response never contains credential material
    assert "client_cert" not in data["server"]
    assert "client_key" not in data["server"]

    r2 = client.get("/velociraptor/get")
    assert r2.status_code == 200
    assert any(s["uuid"] == server_uuid for s in r2.get_json())

    r3 = client.post(f"/velociraptor/delete/{server_uuid}")
    assert r3.status_code == 200
    assert r3.get_json()["success"] is True

    with app.app_context():
        assert VelociraptorServer.query.filter_by(uuid=server_uuid).first() is None


def test_create_missing_fields_rejected(client):
    login_admin(client)
    r = client.post("/velociraptor/create", json={"name": "incomplete"})
    assert r.status_code == 400
    assert r.get_json()["success"] is False


def test_create_strips_scheme_prefix_from_connection_string(client):
    """Regression test for the real user-reported bug: pasting a URL
    (https://127.0.0.1:8889, gRPC targets are bare host:port) used to cause
    a cryptic "Misformatted domain name" gRPC error. The scheme is now
    stripped at create time so a bare host:port always ends up stored."""
    login_admin(client)
    payload = dict(FAKE_SERVER_PAYLOAD, api_connection_string="https://127.0.0.1:8889")
    r = client.post("/velociraptor/create", json=payload)
    assert r.status_code == 200
    data = r.get_json()
    assert data["success"] is True
    assert data["server"]["api_connection_string"] == "127.0.0.1:8889"
    client.post(f"/velociraptor/delete/{data['server']['uuid']}")


def test_create_with_path_segment_gives_clear_error(client):
    """A URL with a residual path (not just host:port) can't be salvaged."""
    login_admin(client)
    payload = dict(FAKE_SERVER_PAYLOAD, api_connection_string="https://127.0.0.1:8889/app/index.html")
    r = client.post("/velociraptor/create", json=payload)
    assert r.status_code == 400
    assert r.get_json()["success"] is False


def test_delete_nonexistent_returns_404(client):
    login_admin(client)
    r = client.post("/velociraptor/delete/does-not-exist")
    assert r.status_code == 404


def test_toggle_active_as_admin(client):
    login_admin(client)
    r = client.post("/velociraptor/create", json=FAKE_SERVER_PAYLOAD)
    server_uuid = r.get_json()["server"]["uuid"]

    r2 = client.post(f"/velociraptor/toggle_active/{server_uuid}")
    assert r2.status_code == 200
    assert r2.get_json()["is_active"] is False

    client.post(f"/velociraptor/delete/{server_uuid}")


def test_push_requires_active_server(client):
    login_admin(client)
    r = client.post("/velociraptor/create", json=FAKE_SERVER_PAYLOAD)
    server_uuid = r.get_json()["server"]["uuid"]
    client.post(f"/velociraptor/toggle_active/{server_uuid}")  # disable it

    r2 = client.post("/velociraptor/push", json={"rule_id": 1, "server_uuid": server_uuid})
    assert r2.status_code == 400
    assert r2.get_json()["success"] is False

    client.post(f"/velociraptor/delete/{server_uuid}")


def test_push_missing_params_rejected(client):
    login_admin(client)
    r = client.post("/velociraptor/push", json={})
    assert r.status_code == 400


# ── Update (edit) ──────────────────────────────────────────────────────────────

def test_update_name_and_connection_string(app, client):
    login_admin(client)
    r = client.post("/velociraptor/create", json=FAKE_SERVER_PAYLOAD)
    uuid = r.get_json()["server"]["uuid"]

    r2 = client.post(f"/velociraptor/update/{uuid}", json={
        "name": "RenamedServer",
        "api_connection_string": "127.0.0.1:8002",
    })
    assert r2.status_code == 200, r2.get_json()
    data = r2.get_json()
    assert data["success"] is True
    assert data["server"]["name"] == "RenamedServer"
    assert data["server"]["api_connection_string"] == "127.0.0.1:8002"

    client.post(f"/velociraptor/delete/{uuid}")


def test_update_without_cert_fields_preserves_existing_secrets(app, client):
    """Cert/key fields are never sent back by to_json(), so the edit form
    leaves them blank by default — blank must mean "keep the existing value",
    not "erase it"."""
    login_admin(client)
    r = client.post("/velociraptor/create", json=FAKE_SERVER_PAYLOAD)
    uuid = r.get_json()["server"]["uuid"]

    with app.app_context():
        server = VelociraptorServer.query.filter_by(uuid=uuid).first()
        original_encrypted_key = server.client_key_encrypted

    r2 = client.post(f"/velociraptor/update/{uuid}", json={"name": "StillHasSecrets", "description": "note"})
    assert r2.status_code == 200
    assert r2.get_json()["success"] is True

    with app.app_context():
        server = VelociraptorServer.query.filter_by(uuid=uuid).first()
        assert server.client_key_encrypted == original_encrypted_key
        assert server.description == "note"

    client.post(f"/velociraptor/delete/{uuid}")


def test_update_rejects_gui_url_same_as_create(client):
    login_admin(client)
    r = client.post("/velociraptor/create", json=FAKE_SERVER_PAYLOAD)
    uuid = r.get_json()["server"]["uuid"]

    r2 = client.post(f"/velociraptor/update/{uuid}", json={
        "api_connection_string": "https://127.0.0.1:8889/app/index.html",
    })
    assert r2.status_code == 400
    assert r2.get_json()["success"] is False

    client.post(f"/velociraptor/delete/{uuid}")


def test_update_requires_admin(client):
    login_user(client)
    r = client.post("/velociraptor/update/does-not-exist", json={"name": "x"})
    assert r.status_code == 403


def test_update_nonexistent_returns_404(client):
    login_admin(client)
    r = client.post("/velociraptor/update/does-not-exist", json={"name": "x"})
    assert r.status_code == 404


# ── History ────────────────────────────────────────────────────────────────────

def test_history_records_create_update_and_test(client):
    login_admin(client)
    r = client.post("/velociraptor/create", json=FAKE_SERVER_PAYLOAD)
    server_uuid = r.get_json()["server"]["uuid"]

    client.post(f"/velociraptor/update/{server_uuid}", json={"name": "RenamedForHistory"})
    client.post(f"/velociraptor/test/{server_uuid}")  # will fail (no real server) but still logs an attempt where relevant

    r2 = client.get(f"/velociraptor/history/{server_uuid}")
    assert r2.status_code == 200
    entries = r2.get_json()
    actions = [e["action"] for e in entries]
    assert "velociraptor.server_create" in actions
    assert "velociraptor.server_update" in actions
    for e in entries:
        assert set(e.keys()) == {"action", "description", "timestamp", "extra"}

    client.post(f"/velociraptor/delete/{server_uuid}")


def test_history_requires_admin(client):
    login_user(client)
    r = client.get("/velociraptor/history/does-not-exist")
    assert r.status_code == 403


def test_history_nonexistent_returns_404(client):
    login_admin(client)
    r = client.get("/velociraptor/history/does-not-exist")
    assert r.status_code == 404


def test_push_triggered_history_links_back_to_the_rule(app, client):
    """The history timeline needs to link to the pushed rule, so
    trigger_push() must attach rule_uuid/rule_title to the history entry —
    not just the opaque integer rule_id."""
    login_admin(client)
    r = client.post("/velociraptor/create", json=FAKE_SERVER_PAYLOAD)
    server_uuid = r.get_json()["server"]["uuid"]

    with app.app_context():
        rule = Rule.query.first()
        rule_id, rule_uuid, rule_title = rule.id, rule.uuid, rule.title

    client.post("/velociraptor/push", json={"rule_id": rule_id, "server_uuid": server_uuid})

    r2 = client.get(f"/velociraptor/history/{server_uuid}")
    entries = r2.get_json()
    triggered = [e for e in entries if e["action"] == "velociraptor.push_triggered"]
    assert len(triggered) == 1
    assert triggered[0]["extra"]["rule_uuid"] == rule_uuid
    assert triggered[0]["extra"]["rule_title"] == rule_title

    client.post(f"/velociraptor/delete/{server_uuid}")
