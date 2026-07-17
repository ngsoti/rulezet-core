from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required

from . import dashboard_core as DashboardModel

dashboard_blueprint = Blueprint('dashboard', __name__)


@dashboard_blueprint.route('/')
@login_required
def dashboard():
    return render_template('dashboard/dashboard.html')


@dashboard_blueprint.route('/layout', methods=['GET'])
@login_required
def get_layout():
    return jsonify(DashboardModel.get_dashboard_layout())


@dashboard_blueprint.route('/layout', methods=['POST'])
@login_required
def save_layout():
    data = request.get_json(force=True) or {}
    ok, msg = DashboardModel.save_dashboard_layout(data)
    if not ok:
        return jsonify({'success': False, 'message': msg}), 400
    return jsonify({'success': True, 'message': msg})
