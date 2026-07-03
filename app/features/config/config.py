from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user

from .config_core import (
    get_user_config, update_config_core,
    get_all_custom_themes, get_valid_theme_keys,
    list_pivotick_backgrounds, save_pivotick_background, delete_pivotick_background,
)

config_blueprint = Blueprint('config', __name__)


@config_blueprint.route('/admin/jobs/list')
@login_required
def admin_jobs_list():
    if not current_user.is_admin():
        abort(403)
    from app.core.db_class.db import BackgroundJob
    running_count = BackgroundJob.query.filter(BackgroundJob.status == 'running').count()
    return render_template('jobs/admin_list.html', running_jobs_count=running_count)


@config_blueprint.route('/settings')
@login_required
def settings():
    config        = get_user_config()
    is_admin      = current_user.is_admin()
    custom_themes = get_all_custom_themes() if is_admin else []
    return render_template(
        'config/settings.html',
        config=config,
        is_admin=is_admin,
        custom_themes=custom_themes,
    )


@config_blueprint.route('/config/themes-data')
@login_required
def themes_data():
    themes = get_all_custom_themes(admin_view=current_user.is_admin())
    return jsonify({'themes': [t.to_json() for t in themes]})


@config_blueprint.route('/config/update', methods=['POST'])
@login_required
def update():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'message': 'No data provided'}), 400
    if 'theme' not in data:
        return jsonify({'message': 'No valid field provided'}), 400

    config, msg = update_config_core({'theme': data['theme']})
    if not config:
        return jsonify({'message': msg}), 400
    return jsonify({'message': msg, 'config': config.to_json()}), 200


# ── PivoTick background gallery ───────────────────────────────────────────────

@config_blueprint.route('/config/pivotick_backgrounds', methods=['GET'])
@login_required
def pivotick_backgrounds_list():
    """Public (any authenticated user) — list available background images to pick from."""
    backgrounds = list_pivotick_backgrounds()
    return jsonify({'backgrounds': [b.to_json() for b in backgrounds]})


@config_blueprint.route('/config/pivotick_backgrounds', methods=['POST'])
@login_required
def pivotick_backgrounds_upload():
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Admin only'}), 403
    image_file = request.files.get('image')
    name       = request.form.get('name', '')
    bg, msg = save_pivotick_background(image_file, name, current_user.id)
    if not bg:
        return jsonify({'success': False, 'message': msg}), 400
    return jsonify({'success': True, 'message': msg, 'background': bg.to_json()}), 200


@config_blueprint.route('/config/pivotick_backgrounds/<int:bg_id>', methods=['DELETE'])
@login_required
def pivotick_backgrounds_delete(bg_id):
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Admin only'}), 403
    ok, msg = delete_pivotick_background(bg_id)
    return jsonify({'success': ok, 'message': msg}), 200 if ok else 404
