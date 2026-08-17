"""
misp_connector_core.py — Business logic for the MISP connector feature.

All DB interactions stay here. Blueprints and job handlers call these
functions and never touch the session directly.

Pushes a Rulezet-generated MISP Object or MISP Event (see
app/features/misp/rule/misp_object.py) into a live MISP instance over its
REST API via PyMISP's ExpandedPyMISP client, authenticated with a bearer
API key.

PyMISP's add_object() requires an *existing* remote event to attach a bare
object to — there is no way to push a standalone Object without a container.
So both "push Object" and "push Event" ultimately call add_event(): pushing
"Object" sends the lean event get_rule_misp_object_base() already builds
(just the rulezet-metadata + content objects, no tags/vulnerabilities),
pushing "Event" sends the richer get_rule_misp_event_object() (adds tags +
CVE attributes). See job_handlers.py's handle_misp_push for the dispatch.
"""

import base64
import datetime
import hashlib
import uuid as uuid_mod

from app import db
from app.core.db_class.db import ActivityLog, MispServer
from app.core.utils.activity_log import log_activity
from app.features.jobs.jobs_core import create_job


# ─── Encryption at rest ────────────────────────────────────────────────────────
# A MISP API key grants full API access to that instance — genuinely
# sensitive, unlike Connector.api_key_outbound — so it's encrypted here with
# Fernet rather than matching that plaintext precedent, the same departure
# already established for VelociraptorServer's client cert/key.

def _get_fernet():
    from cryptography.fernet import Fernet
    from flask import current_app

    key = current_app.config.get('MISP_ENCRYPTION_KEY')
    if not key:
        # Zero-config fallback: derive a stable key from SECRET_KEY so this
        # works out of the box. Set MISP_ENCRYPTION_KEY explicitly in
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
    """Return all configured MISP servers (admin-only feature — no per-owner
    filtering, matching how the blueprint's before_request hook gates the
    whole feature to admins)."""
    return MispServer.query.order_by(MispServer.created_at.desc()).all()


def get_server_by_uuid(server_uuid: str) -> MispServer | None:
    return MispServer.query.filter_by(uuid=server_uuid).first()


def get_server_history(server: MispServer) -> list:
    """Return the last 30 activity log entries for this server (server
    create/update/delete, connection tests, push triggered/done)."""
    entries = (ActivityLog.query
               .filter(
                   ActivityLog.target_type == 'misp_server',
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


def create_server(added_by_id: int, name: str, url: str, api_key: str,
                  verify_tls: bool = True, description: str = None) -> MispServer | None:
    try:
        server = MispServer(
            uuid=str(uuid_mod.uuid4()),
            name=name.strip(),
            description=description,
            url=url.strip().rstrip('/'),
            api_key_encrypted=_encrypt(api_key.strip()),
            verify_tls=bool(verify_tls),
            added_by_id=added_by_id,
        )
        db.session.add(server)
        db.session.commit()

        log_activity('misp.server_create',
                     f"Added MISP server '{server.name}' ({server.url})",
                     target_type='misp_server', target_id=server.id, target_uuid=server.uuid)
        return server
    except Exception as e:
        db.session.rollback()
        print(f"[misp_connector_core] create_server error: {e}")
        return None


def update_server(server: MispServer, data: dict) -> bool:
    """Partial update of a server's fields. The API key is only touched when a
    new value is actually provided — it's never round-tripped back to the
    client (to_json() never exposes it), so the edit form leaves it blank by
    default and "blank" must mean "keep the existing value", not "erase it".
    """
    try:
        connection_changed = False

        if data.get('name'):
            server.name = data['name'].strip()
        if 'description' in data:
            server.description = data.get('description') or None
        if data.get('url'):
            new_url = data['url'].strip().rstrip('/')
            if new_url != server.url:
                server.url = new_url
                connection_changed = True
        if data.get('api_key'):
            server.api_key_encrypted = _encrypt(data['api_key'].strip())
            connection_changed = True
        if 'verify_tls' in data and bool(data['verify_tls']) != server.verify_tls:
            server.verify_tls = bool(data['verify_tls'])
            connection_changed = True

        # Credentials/connection changed — the last test result no longer
        # reflects reality.
        if connection_changed:
            server.is_verified = False
            server.last_error = None

        db.session.commit()
        log_activity('misp.server_update', f"Updated MISP server '{server.name}'",
                     target_type='misp_server', target_id=server.id, target_uuid=server.uuid)
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[misp_connector_core] update_server error: {e}")
        return False


def delete_server(server: MispServer) -> bool:
    try:
        name, sid, suuid = server.name, server.id, server.uuid
        db.session.delete(server)
        db.session.commit()
        log_activity('misp.server_delete', f"Deleted MISP server '{name}'",
                     extra={'server_uuid': suuid})
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[misp_connector_core] delete_server error: {e}")
        return False


def set_server_active(server: MispServer, is_active: bool) -> bool:
    try:
        server.is_active = is_active
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[misp_connector_core] set_server_active error: {e}")
        return False


# ─── REST connection ────────────────────────────────────────────────────────────

def _build_client(server: MispServer, timeout: int = 10):
    """Build an ExpandedPyMISP REST client for this server, decrypting its
    API key. Imported lazily so a missing pymisp install only breaks this
    code path, not the whole app."""
    from pymisp import ExpandedPyMISP
    return ExpandedPyMISP(server.url, _decrypt(server.api_key_encrypted),
                          ssl=server.verify_tls, timeout=timeout)


def test_server_connection(server: MispServer) -> tuple[bool, str]:
    """Confirm the stored URL/API key actually reach and authenticate against
    the instance by reading its version. Returns (success, message)."""
    try:
        client = _build_client(server)
        version_info = client.misp_instance_version
        now = datetime.datetime.now(datetime.timezone.utc)
        server.last_test_at = now
        version = (version_info or {}).get('version') if isinstance(version_info, dict) else None
        if version:
            server.is_verified = True
            server.last_error = None
            db.session.commit()
            return True, f"Connected to MISP {version}."
        server.last_error = "Could not read the instance version."
        db.session.commit()
        return False, "Connected, but could not read the instance version."
    except ImportError:
        msg = "pymisp is not installed on this server — run `pip install -r requirements.txt`."
        server.last_error = msg
        db.session.commit()
        return False, msg
    except Exception as e:
        server.last_error = str(e)
        db.session.commit()
        return False, f"Connection failed: {e}"


def push_to_misp(server: MispServer, event) -> tuple[bool, str]:
    """Push a MISPEvent to the server via add_event(). Returns (success, message).

    add_event(pythonify=True) returns the created MISPEvent instance on
    success, or a plain dict (containing an 'errors' key) on failure — PyMISP
    doesn't raise for a rejected event, so the return type is the only
    reliable success signal.
    """
    try:
        from pymisp import MISPEvent
        client = _build_client(server)
        result = client.add_event(event, pythonify=True)

        if isinstance(result, MISPEvent):
            server.last_push_at = datetime.datetime.now(datetime.timezone.utc)
            server.pushes_count = (server.pushes_count or 0) + 1
            server.last_error = None
            db.session.commit()
            return True, f"Event '{result.info}' created on {server.name} ({result.uuid})."

        error_msg = str(result.get('errors', result)) if isinstance(result, dict) else str(result)
        server.last_error = error_msg
        db.session.commit()
        return False, f"Push failed: {error_msg}"
    except ImportError:
        msg = "pymisp is not installed on this server — run `pip install -r requirements.txt`."
        server.last_error = msg
        db.session.commit()
        return False, msg
    except Exception as e:
        server.last_error = str(e)
        db.session.commit()
        return False, f"Push failed: {e}"


def trigger_push(server: MispServer, push_type: str, triggered_by: int,
                  rule_id: int = None, bundle_id: int = None) -> object | None:
    """Queue a background job that builds the MISP Object/Event for `rule_id`
    or the MISP Event for `bundle_id` and pushes it to `server`.
    `push_type` is 'object' or 'event' for a rule; bundles only support 'event'."""
    if not server.is_active:
        return None
    if not rule_id and not bundle_id:
        return None

    payload = {'server_id': server.id, 'push_type': push_type}
    extra   = {'push_type': push_type}
    target_label = None

    if bundle_id:
        # Fetched here (not by the route) so bundle_uuid/name can be attached to
        # the history entry — lets the server's history timeline link straight
        # back to the pushed bundle instead of only showing its opaque integer id.
        from app.features.bundle import bundle_core as BundleModel
        bundle = BundleModel.get_bundle_by_id(bundle_id)
        payload['bundle_id'] = bundle_id
        if bundle:
            extra['bundle_id']    = bundle_id
            extra['bundle_uuid']  = bundle.uuid
            extra['bundle_title'] = bundle.name
            target_label = bundle.name
    else:
        # Same reasoning as above, for a rule push.
        from app.features.rule import rule_core as RuleModel
        rule = RuleModel.get_rule(rule_id)
        payload['rule_id'] = rule_id
        if rule:
            extra['rule_id']    = rule_id
            extra['rule_uuid']  = rule.uuid
            extra['rule_title'] = rule.title
            target_label = rule.title

    job = create_job(
        job_type='misp_push',
        payload=payload,
        label=f"Push MISP {push_type} to server '{server.name}'" + (f" ({target_label})" if target_label else ''),
        created_by=triggered_by,
    )
    if job:
        extra['job_uuid'] = job.uuid
        log_activity('misp.push_triggered',
                     f"Triggered MISP {push_type} push to server '{server.name}'"
                     + (f" for '{target_label}'" if target_label else ''),
                     target_type='misp_server', target_id=server.id, target_uuid=server.uuid,
                     actor_id=triggered_by,
                     extra=extra)
    return job
