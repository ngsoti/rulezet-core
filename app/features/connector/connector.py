"""
connector.py — Blueprint for the Connector feature (UI routes).
All DB logic lives in connector_core.py.
Access is restricted to admin users only.
"""

from urllib.parse import urlparse

from flask import Blueprint, abort, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import app.features.connector.connector_core as ConnectorModel
from app.core.utils.activity_log import log_activity

connector_blueprint = Blueprint(
    'connector',
    __name__,
    template_folder='templates',
)


@connector_blueprint.before_request
def _require_admin():
    if not current_user.is_authenticated:
        return redirect(url_for('account.login'))
    if not current_user.is_admin():
        abort(403)


# ─── List ─────────────────────────────────────────────────────────────────────

@connector_blueprint.route('/list', methods=['GET'])
def connector_list():
    return render_template('connector/connector_list.html')


@connector_blueprint.route('/how-it-works', methods=['GET'])
def connector_how_it_works():
    return render_template('connector/connector_how_it_works.html')


# ─── CRUD (JSON API used by the Vue app) ──────────────────────────────────────

def _is_self(instance_url: str) -> bool:
    """Return True if instance_url resolves to this very instance (same host AND port)."""
    try:
        remote_netloc = urlparse(instance_url).netloc.lower()
        local_netloc  = request.host.lower()
        return remote_netloc == local_netloc
    except Exception:
        return False


@connector_blueprint.route('/get', methods=['GET'])
def get_connectors():
    connectors = ConnectorModel.get_connectors(current_user.id)
    result = []
    for c in connectors:
        d = c.to_json()
        d['is_self'] = _is_self(c.instance_url)
        result.append(d)
    return jsonify(result), 200


@connector_blueprint.route('/create', methods=['POST'])
def create_connector():
    data = request.get_json() or {}
    name         = (data.get('name') or '').strip()
    instance_url = (data.get('instance_url') or '').strip()
    if not name or not instance_url:
        return jsonify({'success': False, 'error': 'Name and URL are required.'}), 400
    _parsed_url = urlparse(instance_url)
    if _parsed_url.scheme not in ('http', 'https') or not _parsed_url.netloc:
        return jsonify({'success': False, 'error': 'URL must start with http:// or https://'}), 400

    connector = ConnectorModel.create_connector(
        owner_id=current_user.id,
        name=name,
        instance_url=instance_url,
        connector_type=data.get('connector_type', 'rulezet'),
        api_key_outbound=data.get('api_key_outbound') or None,
        description=data.get('description') or None,
        icon=data.get('icon') or None,
        sync_rules=data.get('sync_rules', True),
        sync_bundles=data.get('sync_bundles', False),
        owner_mode=data.get('owner_mode', 'shadow'),
    )
    if not connector:
        return jsonify({'success': False, 'error': 'Could not create connector.'}), 500

    log_activity('connector.create', f"Created connector '{connector.name}' ({connector.instance_url})",
                 target_type='connector', target_id=connector.id, target_uuid=connector.uuid)
    return jsonify({'success': True, 'connector': connector.to_json()}), 200


@connector_blueprint.route('/update/<string:connector_uuid>', methods=['POST'])
def update_connector(connector_uuid):
    connector = ConnectorModel.get_connector_by_uuid(connector_uuid)
    if not connector:
        return jsonify({'success': False, 'error': 'Not found.'}), 404
    if connector.is_system:
        return jsonify({'success': False, 'error': 'System connectors cannot be modified.'}), 403

    data = request.get_json() or {}
    new_url = (data.get('instance_url') or '').strip()
    if new_url:
        _pu = urlparse(new_url)
        if _pu.scheme not in ('http', 'https') or not _pu.netloc:
            return jsonify({'success': False, 'error': 'URL must start with http:// or https://'}), 400
    ok = ConnectorModel.update_connector(connector, data)
    if ok:
        log_activity('connector.update', f"Updated connector '{connector.name}'",
                     target_type='connector', target_id=connector.id, target_uuid=connector.uuid)
    return jsonify({'success': ok}), 200 if ok else 500


@connector_blueprint.route('/delete/<string:connector_uuid>', methods=['POST'])
def delete_connector(connector_uuid):
    connector = ConnectorModel.get_connector_by_uuid(connector_uuid)
    if not connector:
        return jsonify({'success': False, 'error': 'Not found.'}), 404
    if connector.is_system:
        return jsonify({'success': False, 'error': 'System connectors cannot be deleted.'}), 403

    name, conn_id = connector.name, connector.id
    ok = ConnectorModel.delete_connector(connector)
    if ok:
        log_activity('connector.delete', f"Deleted connector '{name}'",
                     target_type='connector', target_id=conn_id, target_uuid=connector_uuid)
    return jsonify({'success': ok}), 200 if ok else 500


# ─── Actions ──────────────────────────────────────────────────────────────────

@connector_blueprint.route('/test/<string:connector_uuid>', methods=['POST'])
def test_connector(connector_uuid):
    connector = ConnectorModel.get_connector_by_uuid(connector_uuid)
    if not connector:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    ok, msg, stats = ConnectorModel.test_connector(connector)
    if ok:
        log_activity('connector.test_ok', f"Connection test passed for '{connector.name}'",
                     target_type='connector', target_id=connector.id, target_uuid=connector.uuid)
    return jsonify({'success': ok, 'message': msg, 'stats': stats}), 200


@connector_blueprint.route('/history/<string:connector_uuid>', methods=['GET'])
def connector_history(connector_uuid):
    connector = ConnectorModel.get_connector_by_uuid(connector_uuid)
    if not connector:
        return jsonify({'success': False, 'error': 'Not found.'}), 404
    return jsonify(ConnectorModel.get_connector_history(connector)), 200


@connector_blueprint.route('/import_tag_families', methods=['POST'])
def import_tag_families():
    """Import one or more tag families from the MISP taxonomy/galaxy submodules.

    Body: { "families": ["tlp", "pap", "misp-galaxy:threat-actor", ...] }
    """
    data     = request.get_json(silent=True) or {}
    families = data.get('families', [])
    if not families or not isinstance(families, list):
        return jsonify({'success': False, 'error': 'families must be a non-empty list.'}), 400

    results = ConnectorModel.import_tag_families(families, current_user)
    all_ok  = all(r['ok'] for r in results)
    return jsonify({'success': True, 'results': results, 'all_ok': all_ok}), 200


@connector_blueprint.route('/preview/<string:connector_uuid>', methods=['GET'])
def preview_connector(connector_uuid):
    """Fetch the count of rules matching a CVE filter on the remote without importing."""
    import requests as http_requests

    connector = ConnectorModel.get_connector_by_uuid(connector_uuid)
    if not connector:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    cve = request.args.get('cve', '').strip()
    if not cve:
        return jsonify({'success': False, 'error': 'No CVE specified.'}), 400

    headers = {'Accept': 'application/json'}
    if connector.api_key_outbound:
        headers['X-API-KEY'] = connector.api_key_outbound
    try:
        resp = http_requests.get(
            f"{connector.instance_url}/api/sync/rules?cve={cve}&count_only=true",
            headers=headers, timeout=10,
        )
        if resp.status_code == 200:
            data  = resp.json()
            count = data.get('count', data.get('total', 0))
            return jsonify({'success': True, 'count': count, 'cve': cve}), 200
        return jsonify({'success': False, 'error': f'Remote returned HTTP {resp.status_code}'}), 502
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@connector_blueprint.route('/pull/<string:connector_uuid>', methods=['POST'])
def pull_connector(connector_uuid):
    connector = ConnectorModel.get_connector_by_uuid(connector_uuid)
    if not connector:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    if _is_self(connector.instance_url):
        return jsonify({'success': False, 'error': 'Cannot pull from this instance — that would sync with yourself.'}), 400

    if not connector.is_active:
        return jsonify({'success': False, 'error': 'Connector is disabled.'}), 400

    data         = request.get_json(silent=True) or {}
    sync_rules   = data.get('sync_rules',   connector.sync_rules)
    sync_bundles = data.get('sync_bundles', connector.sync_bundles)
    filters      = data.get('filters') or {}

    if not sync_rules and not sync_bundles:
        return jsonify({'success': False, 'error': 'Nothing to pull — select rules and/or bundles.'}), 400

    job = ConnectorModel.trigger_pull(connector, triggered_by=current_user.id,
                                      sync_rules=sync_rules, sync_bundles=sync_bundles,
                                      filters=filters if filters else None)
    if not job:
        return jsonify({'success': False, 'error': 'Could not queue pull job.'}), 500

    what = ' + '.join(filter(None, ['rules' if sync_rules else '', 'bundles' if sync_bundles else '']))
    log_activity('connector.pull_triggered', f"Triggered pull ({what}) from connector '{connector.name}'",
                 target_type='connector', target_id=connector.id, target_uuid=connector.uuid)
    return jsonify({
        'success': True,
        'message': f'Pull queued ({what}) as background job.',
        'job_uuid': job.uuid,
    }), 200
