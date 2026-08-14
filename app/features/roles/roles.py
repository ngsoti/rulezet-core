"""
roles.py — Blueprint for the Roles & Permissions admin feature (UI routes).
All DB logic lives in roles_core.py.
Access is restricted to admin users only.
"""

from flask import Blueprint, abort, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import app.features.roles.roles_core as RolesModel
from app.core.utils.activity_log import log_activity

roles_blueprint = Blueprint(
    'roles',
    __name__,
    template_folder='templates',
)


@roles_blueprint.before_request
def _require_admin():
    if not current_user.is_authenticated:
        return redirect(url_for('account.login'))
    if not current_user.is_admin():
        abort(403)


# ─── Pages ───────────────────────────────────────────────────────────────────

@roles_blueprint.route('/list', methods=['GET'])
def role_list():
    return render_template('roles/role_list.html')


@roles_blueprint.route('/detail/<int:role_id>', methods=['GET'])
def role_detail(role_id):
    role = RolesModel.get_role(role_id)
    if not role:
        abort(404)
    return render_template('roles/role_detail.html', role=role.to_json())


# ─── Roles CRUD ──────────────────────────────────────────────────────────────

@roles_blueprint.route('/all', methods=['GET'])
def all_roles():
    """Unpaginated, compact role list — used by the user-list role picker
    (needs every role available at once, not a data-table page)."""
    roles = RolesModel.get_all_roles()
    return jsonify({"success": True, "roles": [{"id": r.id, "name": r.name} for r in roles]})


@roles_blueprint.route('/data_table', methods=['GET'])
def roles_data_table():
    """DataTable-compatible listing ({ items, total, total_pages })."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '', type=str)
    sort = request.args.get('sort', 'name', type=str)
    dir = request.args.get('dir', 'asc', type=str)
    return jsonify(RolesModel.list_roles_paginated(page, per_page, search, sort, dir))


@roles_blueprint.route('/get_all_permissions', methods=['GET'])
def get_all_permissions():
    perms = RolesModel.get_all_permissions()
    return jsonify({"success": True, "permissions": [p.to_json() for p in perms]})


@roles_blueprint.route('/create', methods=['POST'])
def create_role():
    data = request.get_json() or {}
    role, err = RolesModel.create_role(data.get('name'), data.get('description'))
    if err:
        return jsonify({"success": False, "message": err}), 400
    log_activity("role.create", f"Created role '{role.name}'",
                 target_type="role", target_id=role.id, is_public=False)
    return jsonify({"success": True, "role": role.to_json()}), 201


@roles_blueprint.route('/<int:role_id>/update', methods=['POST'])
def update_role(role_id):
    data = request.get_json() or {}
    role, err = RolesModel.update_role(role_id, data.get('name'), data.get('description'))
    if err:
        return jsonify({"success": False, "message": err}), 400
    log_activity("role.update", f"Updated role '{role.name}'",
                 target_type="role", target_id=role.id, is_public=False)
    return jsonify({"success": True, "role": role.to_json()})


@roles_blueprint.route('/<int:role_id>/delete', methods=['POST'])
def delete_role(role_id):
    role = RolesModel.get_role(role_id)
    name = role.name if role else None
    success, err = RolesModel.delete_role(role_id)
    if not success:
        return jsonify({"success": False, "message": err}), 400
    log_activity("role.delete", f"Deleted role '{name}'",
                 target_type="role", target_id=role_id, is_public=False)
    return jsonify({"success": True})


@roles_blueprint.route('/bulk_delete', methods=['POST'])
def bulk_delete_roles():
    data = request.get_json() or {}
    role_ids = data.get('role_ids')  # None = every role (select-all-pages)
    deleted, skipped = RolesModel.bulk_delete_roles(role_ids)
    log_activity("role.bulk_delete", f"Bulk-deleted {deleted} role(s), skipped {skipped} system role(s)",
                 is_public=False)
    message = f"Deleted {deleted} role(s)."
    if skipped:
        message += f" Skipped {skipped} system role(s)."
    return jsonify({"success": True, "deleted": deleted, "skipped": skipped, "message": message})


@roles_blueprint.route('/<int:role_id>/set_permissions', methods=['POST'])
def set_role_permissions(role_id):
    data = request.get_json() or {}
    success, err = RolesModel.set_role_permissions(role_id, data.get('permission_ids', []))
    if not success:
        return jsonify({"success": False, "message": err}), 400
    role = RolesModel.get_role(role_id)
    log_activity("role.set_permissions", f"Updated permissions for role '{role.name}'",
                 target_type="role", target_id=role_id, is_public=False)
    return jsonify({"success": True, "role": role.to_json()})


# ─── User assignment ─────────────────────────────────────────────────────────

@roles_blueprint.route('/<int:role_id>/users', methods=['GET'])
def role_users(role_id):
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    return jsonify(RolesModel.get_role_users(role_id, page, per_page))


@roles_blueprint.route('/<int:role_id>/users/search', methods=['GET'])
def role_users_search(role_id):
    search = request.args.get('search', '')
    results = RolesModel.search_assignable_users(role_id, search)
    return jsonify({"success": True, "users": results})


@roles_blueprint.route('/<int:role_id>/users/add', methods=['POST'])
def role_users_add(role_id):
    data = request.get_json() or {}
    user_id = data.get('user_id')
    success, err = RolesModel.add_user_to_role(role_id, user_id, current_user.id)
    if not success:
        return jsonify({"success": False, "message": err}), 400
    role = RolesModel.get_role(role_id)
    log_activity("role.assign_user", f"Assigned role '{role.name}' to user id={user_id}",
                 target_type="role", target_id=role_id, extra={"user_id": user_id}, is_public=False)
    return jsonify({"success": True})


@roles_blueprint.route('/<int:role_id>/users/remove', methods=['POST'])
def role_users_remove(role_id):
    data = request.get_json() or {}
    user_id = data.get('user_id')
    success, err = RolesModel.remove_user_from_role(role_id, user_id)
    if not success:
        return jsonify({"success": False, "message": err}), 400
    role = RolesModel.get_role(role_id)
    log_activity("role.unassign_user", f"Removed role '{role.name}' from user id={user_id}",
                 target_type="role", target_id=role_id, extra={"user_id": user_id}, is_public=False)
    return jsonify({"success": True})
