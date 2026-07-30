from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from .pivotick_core import (
    GRAPH_TYPES, get_default_style, get_style_config,
    save_style_config, reset_style_config,
)

pivotick_blueprint = Blueprint('pivotick', __name__)


# ── Public: style config used by the graph renderers (rule/bundle/attack pages) ──

@pivotick_blueprint.route('/pivotick/style/<graph_type>', methods=['GET'])
def pivotick_style_get(graph_type):
    """Anyone (including anonymous visitors viewing a public rule/bundle) can
    fetch the active render config — it's just node/edge visual styling."""
    config = get_style_config(graph_type)
    if config is None:
        return jsonify({'message': 'Unknown graph type'}), 404
    return jsonify({'graph_type': graph_type, 'config': config})


# ── Admin: config page + save/reset ───────────────────────────────────────────

@pivotick_blueprint.route('/admin/pivotick')
@login_required
def pivotick_admin_page():
    if not current_user.is_admin():
        return jsonify({'message': 'Admin only'}), 403
    configs = {gt: get_style_config(gt) for gt in GRAPH_TYPES}
    defaults = {gt: get_default_style(gt) for gt in GRAPH_TYPES}
    return render_template('pivotick/admin_style.html', configs=configs, defaults=defaults)


@pivotick_blueprint.route('/admin/pivotick/style/<graph_type>', methods=['POST'])
@login_required
def pivotick_style_save(graph_type):
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Admin only'}), 403
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    config, msg = save_style_config(graph_type, data, current_user.id)
    if not config:
        return jsonify({'success': False, 'message': msg}), 400
    return jsonify({'success': True, 'message': msg, 'config': config})


@pivotick_blueprint.route('/admin/pivotick/style/<graph_type>/reset', methods=['POST'])
@login_required
def pivotick_style_reset(graph_type):
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Admin only'}), 403
    config, msg = reset_style_config(graph_type)
    if not config:
        return jsonify({'success': False, 'message': msg}), 400
    return jsonify({'success': True, 'message': msg, 'config': config})
