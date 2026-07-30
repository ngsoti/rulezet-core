"""
Tests for the pivotick blueprint (admin-configurable node/edge render style
for the rule/bundle/attack PivoTick graphs).
"""


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


# ── Public style endpoint ─────────────────────────────────────────────────────

def test_style_get_returns_default_config(client):
    r = client.get("/pivotick/style/rule")
    assert r.status_code == 200
    data = r.get_json()
    assert data["graph_type"] == "rule"
    assert "tag" in data["config"]["nodes"]["types"]
    assert data["config"]["nodes"]["types"]["tag"]["icon"] == "fa-solid fa-tag"


def test_style_get_unknown_graph_type_404(client):
    r = client.get("/pivotick/style/does-not-exist")
    assert r.status_code == 404


def test_style_vulnerability_is_not_a_triangle(client):
    # A triangle's narrow area clips the FontAwesome glyph rendered on top of it.
    for graph_type in ("rule", "bundle"):
        data = client.get(f"/pivotick/style/{graph_type}").get_json()
        assert data["config"]["nodes"]["types"]["vulnerability"]["shape"] != "triangle"


def test_style_has_attack_node_and_edge_type(client):
    for graph_type in ("rule", "bundle"):
        data = client.get(f"/pivotick/style/{graph_type}").get_json()
        assert data["config"]["nodes"]["types"]["attack"]["icon"] == "fa-solid fa-crosshairs"
        assert "attack" in data["config"]["edges"]["types"]


def test_style_get_does_not_require_login(client):
    # Anonymous visitors view public rule/bundle graphs too.
    r = client.get("/pivotick/style/bundle")
    assert r.status_code == 200


# ── Admin page ────────────────────────────────────────────────────────────────

def test_admin_page_requires_login(client):
    r = client.get("/admin/pivotick", follow_redirects=False)
    assert r.status_code in (302, 403)


def test_admin_page_requires_admin(client):
    login_user(client)
    r = client.get("/admin/pivotick")
    assert r.status_code == 403


def test_admin_page_loads_for_admin(client):
    login_admin(client)
    r = client.get("/admin/pivotick")
    assert r.status_code == 200
    assert b"pivotick-admin-app" in r.data


# ── Save / reset ──────────────────────────────────────────────────────────────

def test_save_requires_admin(client):
    login_user(client)
    r = client.post("/admin/pivotick/style/rule", json={"nodes": {"default": {}, "types": {}}, "edges": {"default": {}, "types": {}}})
    assert r.status_code == 403


def test_save_and_persist_and_reset(client):
    login_admin(client)

    custom = {
        "nodes": {
            "default": {"shape": "circle", "color": "#111111", "dark_color": "#222222", "size": 10, "icon": None},
            "types": {
                "tag": {"shape": "circle", "color": "#00ff00", "dark_color": "#00cc00", "size": 99, "icon": "fa-solid fa-hashtag"},
            },
        },
        "edges": {
            "default": {"color": "#333333", "dark_color": "#444444", "width": 1, "dashed": False},
            "types": {},
        },
    }
    r = client.post("/admin/pivotick/style/rule", json=custom)
    assert r.status_code == 200
    data = r.get_json()
    assert data["success"] is True
    assert data["config"]["nodes"]["types"]["tag"]["icon"] == "fa-solid fa-hashtag"
    assert data["config"]["nodes"]["types"]["tag"]["size"] == 99
    # Untouched types (e.g. "rule") survive via the default-merge.
    assert "rule" in data["config"]["nodes"]["types"]

    # Persisted — a fresh GET reflects the customization.
    r2 = client.get("/pivotick/style/rule")
    assert r2.get_json()["config"]["nodes"]["types"]["tag"]["icon"] == "fa-solid fa-hashtag"

    # Reset restores the built-in default.
    r3 = client.post("/admin/pivotick/style/rule/reset")
    assert r3.status_code == 200
    assert r3.get_json()["config"]["nodes"]["types"]["tag"]["icon"] == "fa-solid fa-tag"


def test_save_rejects_malformed_payload(client):
    login_admin(client)
    r = client.post("/admin/pivotick/style/rule", json={"nope": True})
    assert r.status_code == 400
    assert r.get_json()["success"] is False
