"""
misp.py — Blueprint for the MISP connector feature (UI routes).
All DB logic lives in misp_connector_core.py.
Access is restricted to admin users only.
"""

from flask import Blueprint, abort, jsonify, redirect, render_template, request, url_for
from flask_login import current_user

import app.features.misp.misp_connector_core as MispModel
from app.core.utils.activity_log import log_activity

misp_blueprint = Blueprint(
    'misp',
    __name__,
    template_folder='templates',
)


@misp_blueprint.before_request
def _require_admin():
    if not current_user.is_authenticated:
        return redirect(url_for('account.login'))
    if not current_user.is_admin():
        abort(403)


# ─── List ─────────────────────────────────────────────────────────────────────

@misp_blueprint.route('/list', methods=['GET'])
def misp_list():
    return render_template('misp/misp_list.html')


@misp_blueprint.route('/how-it-works', methods=['GET'])
def misp_how_it_works():
    return render_template('misp/misp_how_it_works.html')


# ─── CRUD (JSON API used by the Vue app) ──────────────────────────────────────

@misp_blueprint.route('/get', methods=['GET'])
def get_servers():
    servers = MispModel.get_servers()
    return jsonify([s.to_json() for s in servers]), 200


@misp_blueprint.route('/create', methods=['POST'])
def create_server():
    data        = request.get_json() or {}
    name        = (data.get('name') or '').strip()
    url_        = (data.get('url') or '').strip()
    api_key     = (data.get('api_key') or '').strip()
    verify_tls  = data.get('verify_tls', True)

    if not name or not url_ or not api_key:
        return jsonify({
            'success': False,
            'error': 'Name, URL and API key are all required.',
        }), 400

    server = MispModel.create_server(
        added_by_id=current_user.id,
        name=name,
        url=url_,
        api_key=api_key,
        verify_tls=verify_tls,
        description=data.get('description') or None,
    )

    if not server:
        return jsonify({'success': False, 'error': 'Could not create the server connection.'}), 500

    return jsonify({'success': True, 'server': server.to_json()}), 200


@misp_blueprint.route('/history/<string:server_uuid>', methods=['GET'])
def server_history(server_uuid):
    server = MispModel.get_server_by_uuid(server_uuid)
    if not server:
        return jsonify({'success': False, 'error': 'Not found.'}), 404
    return jsonify(MispModel.get_server_history(server)), 200


@misp_blueprint.route('/update/<string:server_uuid>', methods=['POST'])
def update_server(server_uuid):
    server = MispModel.get_server_by_uuid(server_uuid)
    if not server:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    data = request.get_json() or {}
    ok = MispModel.update_server(server, data)

    return jsonify({'success': ok, 'server': server.to_json() if ok else None}), 200 if ok else 500


@misp_blueprint.route('/delete/<string:server_uuid>', methods=['POST'])
def delete_server(server_uuid):
    server = MispModel.get_server_by_uuid(server_uuid)
    if not server:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    name, sid = server.name, server.id
    ok = MispModel.delete_server(server)
    if ok:
        log_activity('misp.server_delete', f"Deleted MISP server '{name}'",
                     target_type='misp_server', target_id=sid, target_uuid=server_uuid)
    return jsonify({'success': ok}), 200 if ok else 500


@misp_blueprint.route('/toggle_active/<string:server_uuid>', methods=['POST'])
def toggle_active(server_uuid):
    server = MispModel.get_server_by_uuid(server_uuid)
    if not server:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    ok = MispModel.set_server_active(server, not server.is_active)
    return jsonify({'success': ok, 'is_active': server.is_active}), 200 if ok else 500


@misp_blueprint.route('/test/<string:server_uuid>', methods=['POST'])
def test_server(server_uuid):
    server = MispModel.get_server_by_uuid(server_uuid)
    if not server:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    ok, msg = MispModel.test_server_connection(server)
    if ok:
        log_activity('misp.test_ok', f"Connection test passed for '{server.name}'",
                     target_type='misp_server', target_id=server.id, target_uuid=server.uuid)
    return jsonify({'success': ok, 'message': msg}), 200


@misp_blueprint.route('/push', methods=['POST'])
def push_rule():
    data        = request.get_json() or {}
    rule_id     = data.get('rule_id')
    bundle_id   = data.get('bundle_id')
    server_uuid = data.get('server_uuid')
    push_type   = data.get('push_type', 'object')

    if not server_uuid or (not rule_id and not bundle_id):
        return jsonify({'success': False, 'error': 'rule_id or bundle_id, and server_uuid are required.'}), 400
    if rule_id and bundle_id:
        return jsonify({'success': False, 'error': 'Provide either rule_id or bundle_id, not both.'}), 400
    if push_type not in ('object', 'event'):
        return jsonify({'success': False, 'error': "push_type must be 'object' or 'event'."}), 400
    if bundle_id and push_type != 'event':
        return jsonify({'success': False, 'error': "A bundle can only be pushed as an 'event'."}), 400

    server = MispModel.get_server_by_uuid(server_uuid)
    if not server:
        return jsonify({'success': False, 'error': 'Server not found.'}), 404
    if not server.is_active:
        return jsonify({'success': False, 'error': 'This server connection is disabled.'}), 400

    job = MispModel.trigger_push(server, push_type=push_type, triggered_by=current_user.id,
                                  rule_id=rule_id, bundle_id=bundle_id)
    if not job:
        return jsonify({'success': False, 'error': 'Could not queue the push job.'}), 500

    return jsonify({
        'success': True,
        'message': f"Push to '{server.name}' queued as background job.",
        'job_uuid': job.uuid,
    }), 200
