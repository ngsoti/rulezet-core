"""
Unit tests for velociraptor_core.py business logic functions.
Tests run in app context directly against the SQLite test DB.

The actual gRPC call (_run_vql) is monkeypatched in tests that exercise
test_server_connection()/push_artifact() — there's no live Velociraptor
server to test against in CI, so we verify the surrounding logic (state
updates, error handling, return shapes) instead.
"""

import pytest

from app import db
from app.core.db_class.db import User, VelociraptorServer
from app.features.velociraptor import velociraptor_core as core


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def admin(app):
    with app.app_context():
        yield User.query.filter_by(email="admin@admin.admin").first()


@pytest.fixture
def server(app, admin):
    with app.app_context():
        s = core.create_server(
            added_by_id=admin.id,
            name="UnitTestServer",
            api_connection_string="127.0.0.1:8001",
            ca_certificate="-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
            client_cert="-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----",
            client_key="-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----",
        )
        yield s
        existing = VelociraptorServer.query.filter_by(uuid=s.uuid).first()
        if existing:
            db.session.delete(existing)
            db.session.commit()


# ── Connection string validation ────────────────────────────────────────────
# Regression tests for a real user-reported bug: pasting the GUI URL
# (https://127.0.0.1:8889) instead of the api_connection_string field
# (127.0.0.1:8001) produced a cryptic gRPC "Misformatted domain name" error.

def test_normalize_connection_string_accepts_valid():
    assert core.normalize_connection_string("127.0.0.1:8001") == "127.0.0.1:8001"
    assert core.normalize_connection_string("  127.0.0.1:8001  ") == "127.0.0.1:8001"


def test_normalize_connection_string_strips_scheme():
    assert core.normalize_connection_string("https://127.0.0.1:8001") == "127.0.0.1:8001"
    assert core.normalize_connection_string("https://127.0.0.1:8001/") == "127.0.0.1:8001"
    assert core.normalize_connection_string("http://vr.example.com:8001") == "vr.example.com:8001"


def test_normalize_connection_string_rejects_path_segment():
    # A scheme prefix is stripped, but a residual path (e.g. the GUI's own
    # app URL, not just its host:port) still can't be salvaged into a valid
    # gRPC target.
    with pytest.raises(ValueError):
        core.normalize_connection_string("https://127.0.0.1:8889/app/index.html")


def test_normalize_connection_string_rejects_placeholder():
    with pytest.raises(ValueError):
        core.normalize_connection_string("test")
    with pytest.raises(ValueError):
        core.normalize_connection_string("")


def test_normalize_connection_string_accepts_gui_looking_url_shape():
    # normalize_connection_string only fixes the syntax bug (scheme prefix
    # causing "Misformatted domain name") — it has no way to know 8889 is
    # semantically the GUI port rather than the gRPC API port, so a bare
    # https://host:port strips cleanly to a *shape-valid* host:port. Whether
    # it's actually the wrong port is something only a real connection
    # attempt (test_server_connection) can catch.
    assert core.normalize_connection_string("https://127.0.0.1:8889") == "127.0.0.1:8889"


# ── CRUD ──────────────────────────────────────────────────────────────────────

def test_create_server(app, server):
    with app.app_context():
        assert server is not None
        assert server.name == "UnitTestServer"
        assert server.is_active is True
        assert server.is_verified is False


def test_credentials_encrypted_at_rest(app, server):
    with app.app_context():
        assert "SECRET" not in server.client_key_encrypted
        assert "CLIENT" not in server.client_cert_encrypted
        # CA cert is public — not encrypted
        assert "CA" in server.ca_certificate


def test_to_json_never_exposes_credentials(app, server):
    with app.app_context():
        j = server.to_json()
        for key in ("ca_certificate", "client_cert", "client_cert_encrypted",
                    "client_key", "client_key_encrypted"):
            assert key not in j, f"{key} must never appear in to_json()"


def test_build_pyvelociraptor_config_round_trip(app, server):
    with app.app_context():
        config = core._build_pyvelociraptor_config(server)
        assert isinstance(config, dict)
        assert config["client_private_key"] == "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----"
        assert config["client_cert"] == "-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----"
        assert config["api_connection_string"] == "127.0.0.1:8001"


def test_get_servers_and_get_by_uuid(app, server):
    with app.app_context():
        assert any(s.uuid == server.uuid for s in core.get_servers())
        assert core.get_server_by_uuid(server.uuid).id == server.id
        assert core.get_server_by_uuid("does-not-exist") is None


def test_set_server_active(app, server):
    with app.app_context():
        assert core.set_server_active(server, False)
        assert server.is_active is False
        assert core.set_server_active(server, True)
        assert server.is_active is True


def test_delete_server(app, admin):
    with app.app_context():
        s = core.create_server(
            added_by_id=admin.id, name="ToDelete",
            api_connection_string="127.0.0.1:8001",
            ca_certificate="ca", client_cert="cert", client_key="key",
        )
        uuid_ = s.uuid
        assert core.delete_server(s)
        assert core.get_server_by_uuid(uuid_) is None


# ── gRPC-dependent logic (mocked) ──────────────────────────────────────────────

def test_test_server_connection_success(app, server, monkeypatch):
    with app.app_context():
        # Shape verified against a live v0.77.1 server's actual info() output —
        # there's no "Version" column, hence Platform/PlatformVersion instead.
        monkeypatch.setattr(core, "_run_vql", lambda *a, **k: [
            {"Hostname": "endpoint01", "OS": "linux", "Platform": "ubuntu", "PlatformVersion": "24.04"}
        ])
        ok, msg = core.test_server_connection(server)
        assert ok is True
        assert "endpoint01" in msg
        assert "ubuntu" in msg
        assert server.is_verified is True
        assert server.last_error is None


def test_test_server_connection_failure(app, server, monkeypatch):
    with app.app_context():
        def _boom(*a, **k):
            raise RuntimeError("connection refused")
        monkeypatch.setattr(core, "_run_vql", _boom)
        ok, msg = core.test_server_connection(server)
        assert ok is False
        assert "connection refused" in msg
        assert server.last_error is not None


def test_push_artifact_success(app, server, monkeypatch):
    with app.app_context():
        # artifact_set() is a VQL function called as `SELECT artifact_set(...)
        # AS Result FROM scope()` — confirmed live that it returns the parsed
        # artifact definition nested under "Result", not flat.
        monkeypatch.setattr(core, "_run_vql", lambda *a, **k: [
            {"Result": {"name": "Rulezet.Detection.YARA.Test"}}
        ])
        ok, msg = core.push_artifact(server, "name: Rulezet.Detection.YARA.Test\n")
        assert ok is True
        assert "Rulezet.Detection.YARA.Test" in msg
        assert server.artifacts_pushed == 1
        assert server.last_push_at is not None


def test_push_artifact_no_name_in_result_is_a_failure(app, server, monkeypatch):
    """Regression test: artifact_set() called as a plugin (FROM artifact_set(...))
    instead of a function used to silently return 0 rows with no exception —
    this must be treated as a failure, not a false-positive success."""
    with app.app_context():
        monkeypatch.setattr(core, "_run_vql", lambda *a, **k: [])
        ok, msg = core.push_artifact(server, "name: X\n")
        assert ok is False
        assert server.artifacts_pushed == 0


def test_push_artifact_failure_does_not_increment_counter(app, server, monkeypatch):
    with app.app_context():
        def _boom(*a, **k):
            raise RuntimeError("artifact_set failed")
        monkeypatch.setattr(core, "_run_vql", _boom)
        ok, msg = core.push_artifact(server, "name: X\n")
        assert ok is False
        assert server.artifacts_pushed == 0


def test_trigger_push_skips_inactive_server(app, server):
    with app.app_context():
        server.is_active = False
        db.session.commit()
        job = core.trigger_push(server, rule_id=1, triggered_by=server.added_by_id)
        assert job is None


def test_trigger_push_creates_job(app, server):
    with app.app_context():
        job = core.trigger_push(server, rule_id=1, triggered_by=server.added_by_id)
        assert job is not None
        assert job.job_type == "velociraptor_push"
        assert job.payload["server_id"] == server.id
        assert job.payload["rule_id"] == 1
