"""
velociraptor_core.py — Business logic for the Velociraptor connector feature.

All DB interactions stay here. Blueprints and job handlers call these
functions and never touch the session directly.

Pushes a Rulezet-generated detection artifact (see
app/features/rule/exporters/velociraptor_exporter.py) into a live Velociraptor
server over its gRPC API, authenticated via mutual TLS using the cert/key
pair from that server's "API client config" YAML.

NOTE: verified end-to-end against a real, running Velociraptor v0.77.1 server
(mutual TLS via grpc.ssl_channel_credentials + the 'VelociraptorServer' SNI
override, then a genuine artifact_set() push confirmed via
artifact_definitions() on that server) — not just written against
documentation. artifact_set() is a VQL *function*, not a plugin: it must be
called as `SELECT artifact_set(...) AS Result FROM scope()`, not
`FROM artifact_set(...)` — the plugin-style call compiles to zero rows with
no exception at all, which is why _run_vql() treats an ERROR-level log line
with no rows as a hard failure rather than trusting an empty-but-exception-free
result.
"""

import base64
import datetime
import hashlib
import uuid as uuid_mod

from app import db
from app.core.db_class.db import ActivityLog, VelociraptorServer
from app.core.utils.activity_log import log_activity
from app.features.jobs.jobs_core import create_job


# ─── Encryption at rest ────────────────────────────────────────────────────────
# No existing precedent in this codebase encrypts stored credentials
# (Connector.api_key_outbound is plaintext) — but a Velociraptor client
# private key is impersonation-capable against production endpoint
# infrastructure, a much larger blast radius than a typical API key, so it's
# encrypted here with Fernet rather than matching that precedent verbatim.

def _get_fernet():
    from cryptography.fernet import Fernet
    from flask import current_app

    key = current_app.config.get('VELOCIRAPTOR_ENCRYPTION_KEY')
    if not key:
        # Zero-config fallback: derive a stable key from SECRET_KEY so this
        # works out of the box. Set VELOCIRAPTOR_ENCRYPTION_KEY explicitly in
        # production for a key that's independent of SECRET_KEY rotation.
        secret = current_app.config.get('SECRET_KEY', 'rulezet-dev-secret')
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)


def _encrypt(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def _decrypt(ciphertext: str) -> str:
    return _get_fernet().decrypt(ciphertext.encode()).decode()


# ─── CRUD ───────────────────────────────────────────────────────────────────────

def get_servers() -> list:
    """Return all configured Velociraptor servers (admin-only feature — no
    per-owner filtering, matching how the Connector blueprint's before_request
    hook actually gates the whole feature to admins)."""
    return VelociraptorServer.query.order_by(VelociraptorServer.created_at.desc()).all()


def get_server_by_uuid(server_uuid: str) -> VelociraptorServer | None:
    return VelociraptorServer.query.filter_by(uuid=server_uuid).first()


def get_server_history(server: VelociraptorServer) -> list:
    """Return the last 30 activity log entries for this server (server
    create/update/delete, connection tests, push triggered/done) — mirrors
    Connector's get_connector_history()."""
    entries = (ActivityLog.query
               .filter(
                   ActivityLog.target_type == 'velociraptor_server',
                   ActivityLog.target_id == server.id,
               )
               .order_by(ActivityLog.created_at.desc())
               .limit(30)
               .all())
    return [
        {
            'action':      e.action,
            'description': e.description,
            'timestamp':   e.created_at.strftime('%Y-%m-%d %H:%M:%S') if e.created_at else None,
            'extra':       e.extra or {},
        }
        for e in entries
    ]


def normalize_connection_string(value: str) -> str:
    """Normalize + validate a Velociraptor API connection string.

    A common mistake: pasting the GUI URL (e.g. https://127.0.0.1:8889)
    instead of the `api_connection_string` field from the API client config
    (a bare host:port, e.g. 127.0.0.1:8001 — the GUI and the gRPC API listen
    on different ports). gRPC targets are host:port, not URLs, so a scheme
    prefix doesn't get rejected cleanly — it causes a confusing
    "Misformatted domain name" DNS resolution error deep in gRPC instead.
    Raises ValueError with a clear message when the value can't be salvaged.
    """
    value = (value or '').strip()
    if '://' in value:
        _, _, value = value.partition('://')
        value = value.rstrip('/')
    if not value or '/' in value or ':' not in value:
        raise ValueError(
            "Invalid API connection string — it must be a bare host:port "
            "(e.g. 127.0.0.1:8001) from the `api_connection_string` field in "
            "your Velociraptor API client config, not the GUI URL (that's a "
            "different port, typically 8889)."
        )
    return value


def create_server(added_by_id: int, name: str, api_connection_string: str,
                  ca_certificate: str, client_cert: str, client_key: str,
                  description: str = None) -> VelociraptorServer | None:
    # Left outside the try/except below so a bad connection string raises
    # ValueError with a clear message instead of being swallowed into the
    # generic "Could not create the server connection" the route falls back to.
    api_connection_string = normalize_connection_string(api_connection_string)

    try:
        server = VelociraptorServer(
            uuid=str(uuid_mod.uuid4()),
            name=name.strip(),
            description=description,
            api_connection_string=api_connection_string,
            ca_certificate=ca_certificate.strip(),
            client_cert_encrypted=_encrypt(client_cert.strip()),
            client_key_encrypted=_encrypt(client_key.strip()),
            added_by_id=added_by_id,
        )
        db.session.add(server)
        db.session.commit()

        log_activity('velociraptor.server_create',
                     f"Added Velociraptor server '{server.name}' ({server.api_connection_string})",
                     target_type='velociraptor_server', target_id=server.id, target_uuid=server.uuid)
        return server
    except Exception as e:
        db.session.rollback()
        print(f"[velociraptor_core] create_server error: {e}")
        return None


def update_server(server: VelociraptorServer, data: dict) -> bool:
    """Partial update of a server's fields. Certificate/key fields are only
    touched when a new value is actually provided — they're never round-tripped
    back to the client (to_json() never exposes them), so the edit form leaves
    them blank by default and "blank" must mean "keep the existing value", not
    "erase it".

    Left outside the try/except below so a bad connection string raises
    ValueError with a clear message, same as create_server().
    """
    new_connection_string = None
    if data.get('api_connection_string'):
        new_connection_string = normalize_connection_string(data['api_connection_string'])

    try:
        connection_changed = False

        if data.get('name'):
            server.name = data['name'].strip()
        if 'description' in data:
            server.description = data.get('description') or None
        if new_connection_string and new_connection_string != server.api_connection_string:
            server.api_connection_string = new_connection_string
            connection_changed = True
        if data.get('ca_certificate'):
            server.ca_certificate = data['ca_certificate'].strip()
            connection_changed = True
        if data.get('client_cert'):
            server.client_cert_encrypted = _encrypt(data['client_cert'].strip())
            connection_changed = True
        if data.get('client_key'):
            server.client_key_encrypted = _encrypt(data['client_key'].strip())
            connection_changed = True

        # Credentials changed — the last test result no longer reflects reality.
        if connection_changed:
            server.is_verified = False
            server.last_error = None

        db.session.commit()
        log_activity('velociraptor.server_update', f"Updated Velociraptor server '{server.name}'",
                     target_type='velociraptor_server', target_id=server.id, target_uuid=server.uuid)
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[velociraptor_core] update_server error: {e}")
        return False


def delete_server(server: VelociraptorServer) -> bool:
    try:
        name, sid, suuid = server.name, server.id, server.uuid
        db.session.delete(server)
        db.session.commit()
        log_activity('velociraptor.server_delete', f"Deleted Velociraptor server '{name}'",
                     extra={'server_uuid': suuid})
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[velociraptor_core] delete_server error: {e}")
        return False


def set_server_active(server: VelociraptorServer, is_active: bool) -> bool:
    try:
        server.is_active = is_active
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[velociraptor_core] set_server_active error: {e}")
        return False


# ─── gRPC connection ────────────────────────────────────────────────────────────

def _build_pyvelociraptor_config(server: VelociraptorServer):
    """Build the plain dict pyvelociraptor.LoadConfigFile() would normally
    read from an "API client config" YAML file — same shape
    (ca_certificate / client_cert / client_private_key / api_connection_string),
    just sourced from our encrypted DB columns instead of a file on disk."""
    return {
        'ca_certificate': server.ca_certificate,
        'client_cert': _decrypt(server.client_cert_encrypted),
        'client_private_key': _decrypt(server.client_key_encrypted),
        'api_connection_string': server.api_connection_string,
    }


def _run_vql(server: VelociraptorServer, vql: str, env: dict = None, timeout: int = 30) -> list:
    """Execute a single VQL query against a Velociraptor server and return the
    collected result rows (list of dicts, decoded from the JSON response chunks).

    pyvelociraptor itself only loads/decrypts the API client config (a plain
    dict) — it doesn't wrap channel/stub creation, so that's done directly
    with grpc here, following the exact pattern in its own bundled
    client_example.py (mutual TLS + the 'VelociraptorServer' SNI override,
    which is required since Velociraptor serves a self-signed cert)."""
    import json as _json
    import grpc
    from pyvelociraptor import api_pb2, api_pb2_grpc

    config = _build_pyvelociraptor_config(server)
    creds = grpc.ssl_channel_credentials(
        root_certificates=config['ca_certificate'].encode('utf8'),
        private_key=config['client_private_key'].encode('utf8'),
        certificate_chain=config['client_cert'].encode('utf8'),
    )
    options = (('grpc.ssl_target_name_override', 'VelociraptorServer'),)

    env_list = [dict(key=k, value=v) for k, v in (env or {}).items()]
    rows = []
    error_logs = []
    with grpc.secure_channel(config['api_connection_string'], creds, options) as channel:
        stub = api_pb2_grpc.APIStub(channel)
        request = api_pb2.VQLCollectorArgs(
            max_row=1000,
            timeout=timeout,
            Query=[api_pb2.VQLRequest(Name="RulezetQuery", VQL=vql)],
            env=env_list,
        )
        for response in stub.Query(request):
            if response.Response:
                rows.extend(_json.loads(response.Response))
            elif response.log and response.log.startswith('ERROR:'):
                # A VQL compile/runtime error surfaces as a log line, not a gRPC
                # exception — the query "succeeds" at the transport level with
                # zero rows, so without this check a bad query silently looks
                # like success. Confirmed live: `FROM artifact_set(...)` (wrong —
                # it's a function, not a plugin) returned 0 rows with no
                # exception, and only this log line revealed the real failure.
                error_logs.append(response.log)

    if error_logs and not rows:
        raise RuntimeError('; '.join(error_logs))
    return rows


def test_server_connection(server: VelociraptorServer) -> tuple[bool, str]:
    """Run a trivial VQL query to confirm the stored credentials actually
    reach and authenticate against the server. Returns (success, message)."""
    try:
        # info()'s actual columns (verified against a live v0.77.1 server —
        # there's no "version" field on info() despite some docs implying it,
        # and FROM version() isn't a real plugin either).
        rows = _run_vql(server, "SELECT Hostname, OS, Platform, PlatformVersion FROM info()")
        now = datetime.datetime.now(datetime.timezone.utc)
        server.last_test_at = now
        if rows:
            server.is_verified = True
            server.last_error = None
            db.session.commit()
            info = rows[0]
            platform = f"{info.get('Platform', '?')} {info.get('PlatformVersion', '')}".strip()
            return True, f"Connected to {info.get('Hostname', 'server')} ({platform})."
        server.last_error = "Query returned no rows."
        db.session.commit()
        return False, "Connected, but the info() query returned no rows."
    except ImportError:
        msg = "pyvelociraptor is not installed on this server — run `pip install -r requirements.txt`."
        server.last_error = msg
        db.session.commit()
        return False, msg
    except Exception as e:
        server.last_error = str(e)
        db.session.commit()
        return False, f"Connection failed: {e}"


def push_artifact(server: VelociraptorServer, artifact_yaml: str) -> tuple[bool, str]:
    """Register/update a custom artifact on the Velociraptor server via its
    built-in artifact_set() VQL function. Returns (success, message).

    artifact_set() is a VQL *function*, not a plugin — it must be called as
    a scalar expression (`SELECT artifact_set(...) FROM scope()`), not as a
    table source (`FROM artifact_set(...)`). Confirmed against a live server:
    the plugin-style call compiles to zero rows with no exception at all —
    _run_vql's error-log check is what actually catches this class of bug now.
    """
    try:
        rows = _run_vql(
            server,
            "SELECT artifact_set(prefix='Rulezet', definition=ArtifactYAML) AS Result FROM scope()",
            env={'ArtifactYAML': artifact_yaml},
        )
        name = rows[0].get('Result', {}).get('name') if rows else None
        if not name:
            raise RuntimeError("artifact_set() did not return a registered artifact name.")

        server.last_push_at = datetime.datetime.now(datetime.timezone.utc)
        server.artifacts_pushed = (server.artifacts_pushed or 0) + 1
        server.last_error = None
        db.session.commit()
        return True, f"Artifact '{name}' registered on {server.name}."
    except ImportError:
        msg = "pyvelociraptor is not installed on this server — run `pip install -r requirements.txt`."
        server.last_error = msg
        db.session.commit()
        return False, msg
    except Exception as e:
        server.last_error = str(e)
        db.session.commit()
        return False, f"Push failed: {e}"


def trigger_push(server: VelociraptorServer, rule_id: int, triggered_by: int) -> object | None:
    """Queue a background job that generates the artifact for `rule_id` and
    pushes it to `server`."""
    if not server.is_active:
        return None

    # Fetched here (not by the route) so rule_uuid/title can be attached to the
    # history entry — lets the server's history timeline link straight back to
    # the pushed rule instead of only showing its opaque integer id.
    from app.features.rule import rule_core as RuleModel
    rule = RuleModel.get_rule(rule_id)

    job = create_job(
        job_type='velociraptor_push',
        payload={'server_id': server.id, 'rule_id': rule_id},
        label=f"Push artifact to Velociraptor server '{server.name}'",
        created_by=triggered_by,
    )
    if job:
        extra = {'rule_id': rule_id, 'job_uuid': job.uuid}
        if rule:
            extra['rule_uuid'] = rule.uuid
            extra['rule_title'] = rule.title
        log_activity('velociraptor.push_triggered',
                     f"Triggered artifact push to Velociraptor server '{server.name}'"
                     + (f" for rule '{rule.title}'" if rule else ''),
                     target_type='velociraptor_server', target_id=server.id, target_uuid=server.uuid,
                     extra=extra)
    return job
