"""
velociraptor.py — Blueprint for the Velociraptor connector feature (UI routes).
All DB logic lives in velociraptor_core.py.
Access is restricted to admin users only.
"""

from flask import Blueprint, abort, jsonify, redirect, render_template, request, url_for
from flask_login import current_user

import app.features.velociraptor.velociraptor_core as VelociraptorModel
from app.core.utils.activity_log import log_activity

velociraptor_blueprint = Blueprint(
    'velociraptor',
    __name__,
    template_folder='templates',
)


@velociraptor_blueprint.before_request
def _require_admin():
    if not current_user.is_authenticated:
        return redirect(url_for('account.login'))
    if not current_user.is_admin():
        abort(403)


# ─── List ─────────────────────────────────────────────────────────────────────

@velociraptor_blueprint.route('/list', methods=['GET'])
def velociraptor_list():
    return render_template('velociraptor/velociraptor_list.html')


@velociraptor_blueprint.route('/how-it-works', methods=['GET'])
def velociraptor_how_it_works():
    return render_template('velociraptor/velociraptor_how_it_works.html')


# ─── CRUD (JSON API used by the Vue app) ──────────────────────────────────────

@velociraptor_blueprint.route('/get', methods=['GET'])
def get_servers():
    servers = VelociraptorModel.get_servers()
    return jsonify([s.to_json() for s in servers]), 200


@velociraptor_blueprint.route('/create', methods=['POST'])
def create_server():
    data = request.get_json() or {}
    name                   = (data.get('name') or '').strip()
    api_connection_string  = (data.get('api_connection_string') or '').strip()
    ca_certificate         = (data.get('ca_certificate') or '').strip()
    client_cert            = (data.get('client_cert') or '').strip()
    client_key              = (data.get('client_key') or '').strip()

    if not name or not api_connection_string or not ca_certificate or not client_cert or not client_key:
        return jsonify({
            'success': False,
            'error': 'Name, connection string, CA certificate, client certificate and client key are all required.',
        }), 400

    try:
        server = VelociraptorModel.create_server(
            added_by_id=current_user.id,
            name=name,
            api_connection_string=api_connection_string,
            ca_certificate=ca_certificate,
            client_cert=client_cert,
            client_key=client_key,
            description=data.get('description') or None,
        )
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400

    if not server:
        return jsonify({'success': False, 'error': 'Could not create the server connection.'}), 500

    return jsonify({'success': True, 'server': server.to_json()}), 200


@velociraptor_blueprint.route('/history/<string:server_uuid>', methods=['GET'])
def server_history(server_uuid):
    server = VelociraptorModel.get_server_by_uuid(server_uuid)
    if not server:
        return jsonify({'success': False, 'error': 'Not found.'}), 404
    return jsonify(VelociraptorModel.get_server_history(server)), 200


@velociraptor_blueprint.route('/update/<string:server_uuid>', methods=['POST'])
def update_server(server_uuid):
    server = VelociraptorModel.get_server_by_uuid(server_uuid)
    if not server:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    data = request.get_json() or {}
    try:
        ok = VelociraptorModel.update_server(server, data)
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400

    return jsonify({'success': ok, 'server': server.to_json() if ok else None}), 200 if ok else 500


@velociraptor_blueprint.route('/delete/<string:server_uuid>', methods=['POST'])
def delete_server(server_uuid):
    server = VelociraptorModel.get_server_by_uuid(server_uuid)
    if not server:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    name, sid = server.name, server.id
    ok = VelociraptorModel.delete_server(server)
    if ok:
        log_activity('velociraptor.server_delete', f"Deleted Velociraptor server '{name}'",
                     target_type='velociraptor_server', target_id=sid, target_uuid=server_uuid)
    return jsonify({'success': ok}), 200 if ok else 500


@velociraptor_blueprint.route('/toggle_active/<string:server_uuid>', methods=['POST'])
def toggle_active(server_uuid):
    server = VelociraptorModel.get_server_by_uuid(server_uuid)
    if not server:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    ok = VelociraptorModel.set_server_active(server, not server.is_active)
    return jsonify({'success': ok, 'is_active': server.is_active}), 200 if ok else 500


@velociraptor_blueprint.route('/test/<string:server_uuid>', methods=['POST'])
def test_server(server_uuid):
    server = VelociraptorModel.get_server_by_uuid(server_uuid)
    if not server:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    ok, msg = VelociraptorModel.test_server_connection(server)
    if ok:
        log_activity('velociraptor.test_ok', f"Connection test passed for '{server.name}'",
                     target_type='velociraptor_server', target_id=server.id, target_uuid=server.uuid)
    return jsonify({'success': ok, 'message': msg}), 200


@velociraptor_blueprint.route('/push', methods=['POST'])
def push_rule():
    data        = request.get_json() or {}
    rule_id     = data.get('rule_id')
    server_uuid = data.get('server_uuid')

    if not rule_id or not server_uuid:
        return jsonify({'success': False, 'error': 'rule_id and server_uuid are required.'}), 400

    server = VelociraptorModel.get_server_by_uuid(server_uuid)
    if not server:
        return jsonify({'success': False, 'error': 'Server not found.'}), 404
    if not server.is_active:
        return jsonify({'success': False, 'error': 'This server connection is disabled.'}), 400

    job = VelociraptorModel.trigger_push(server, rule_id=rule_id, triggered_by=current_user.id)
    if not job:
        return jsonify({'success': False, 'error': 'Could not queue the push job.'}), 500

    return jsonify({
        'success': True,
        'message': f"Push to '{server.name}' queued as background job.",
        'job_uuid': job.uuid,
    }), 200
