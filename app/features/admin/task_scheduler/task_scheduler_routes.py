"""
task_scheduler_routes.py — admin-only Blueprint for the generalized Admin
Task Scheduler (CRUD + registry + pickers + manual run). Tasks always live
inside a Workflow (create the workflow first, then assign tasks into it —
modeled on a GitHub Actions workflow file containing several jobs). All
DB/business logic lives in task_scheduler_core.py; execution happens
through the existing generic BackgroundJob pipeline (job_worker.py), exactly
like every other admin bulk action. See docs/design/admin_task_scheduler.md.
"""
from flask import Blueprint, abort, jsonify, redirect, render_template, request, url_for
from flask_login import current_user

from app.core.db_class.db import Connector, Rule
from app.core.utils.activity_log import log_activity
from app.features.admin.task_scheduler import task_scheduler_core as TaskSchedulerModel
from app.features.admin.task_scheduler.task_types import serialize_task_types
from app.features.rule.rule_core import _active

task_scheduler_blueprint = Blueprint(
    'task_scheduler',
    __name__,
    template_folder='templates',
)


@task_scheduler_blueprint.before_request
def _require_admin():
    if not current_user.is_authenticated:
        return redirect(url_for('account.login'))
    if not current_user.is_admin():
        abort(403)


def _workflow_or_none(workflow_uuid):
    return TaskSchedulerModel.get_workflow_by_uuid(workflow_uuid) if workflow_uuid else None


@task_scheduler_blueprint.route('/', methods=['GET'])
def admin_panel():
    return render_template('admin/task_scheduler.html')


@task_scheduler_blueprint.route('/types', methods=['GET'])
def task_types():
    return jsonify(serialize_task_types()), 200


@task_scheduler_blueprint.route('/formats', methods=['GET'])
def formats():
    """Distinct rule formats — feeds the 'format_filter_only' target picker."""
    rows = _active().with_entities(Rule.format).distinct().all()
    values = sorted({r[0] for r in rows if r[0]})
    return jsonify({"formats": values}), 200


@task_scheduler_blueprint.route('/connectors', methods=['GET'])
def connectors():
    """Feeds the 'connector_select' target picker — badges is_system so an
    admin can tell an official-instance connector from a custom one."""
    rows = Connector.query.order_by(Connector.name.asc()).all()
    return jsonify({
        "connectors": [
            {"id": c.id, "name": c.name, "is_system": c.is_system, "is_active": c.is_active,
             "instance_url": c.instance_url}
            for c in rows
        ]
    }), 200


# ─── Workflows (JSON API used by the Vue app) ─────────────────────────────────

@task_scheduler_blueprint.route('/workflows', methods=['GET'])
def list_workflows():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '', type=str).strip()
    sort = request.args.get('sort', 'created_at', type=str)
    direction = request.args.get('dir', 'desc', type=str)

    pagination = TaskSchedulerModel.get_workflow_list_page(page, per_page, search, sort, direction)
    return jsonify({
        "workflows": [w.to_json() for w in pagination.items],
        "total": pagination.total,
        "total_pages": pagination.pages,
    }), 200


@task_scheduler_blueprint.route('/workflows/<uuid>', methods=['GET'])
def get_workflow(uuid):
    workflow = _workflow_or_none(uuid)
    if not workflow:
        return jsonify({"message": "Workflow not found.", "toast_class": "danger-subtle"}), 404
    return jsonify({"workflow": workflow.to_json()}), 200


@task_scheduler_blueprint.route('/workflows/create', methods=['POST'])
def create_workflow():
    data = request.get_json(silent=True) or {}
    workflow, err = TaskSchedulerModel.create_workflow(data, current_user)
    if err:
        return jsonify({"message": err, "toast_class": "danger-subtle"}), 400

    log_activity("admin.workflow_created",
                 f"Created workflow '{workflow.title}'",
                 target_type="admin_workflow",
                 target_uuid=workflow.uuid,
                 icon="fa-solid fa-diagram-project")
    return jsonify({
        "message": "Workflow created.",
        "toast_class": "success-subtle",
        "workflow": workflow.to_json(),
    }), 201


@task_scheduler_blueprint.route('/workflows/<uuid>/update', methods=['POST'])
def update_workflow(uuid):
    data = request.get_json(silent=True) or {}
    workflow, err = TaskSchedulerModel.update_workflow(uuid, data)
    if err:
        status = 404 if err == "Workflow not found." else 400
        return jsonify({"message": err, "toast_class": "danger-subtle"}), status

    log_activity("admin.workflow_updated",
                 f"Updated workflow '{workflow.title}'",
                 target_type="admin_workflow",
                 target_uuid=workflow.uuid,
                 icon="fa-solid fa-diagram-project")
    return jsonify({
        "message": "Workflow updated.",
        "toast_class": "success-subtle",
        "workflow": workflow.to_json(),
    }), 200


@task_scheduler_blueprint.route('/workflows/<uuid>/delete', methods=['POST'])
def delete_workflow(uuid):
    ok = TaskSchedulerModel.delete_workflow(uuid)
    if not ok:
        return jsonify({"message": "Workflow not found.", "toast_class": "danger-subtle"}), 404

    log_activity("admin.workflow_deleted",
                 "Deleted a workflow (and its tasks)",
                 target_type="admin_workflow",
                 target_uuid=uuid,
                 icon="fa-solid fa-diagram-project")
    return jsonify({"message": "Workflow and its tasks deleted.", "toast_class": "success-subtle"}), 200


# ─── Tasks — always scoped to a workflow (JSON API used by the Vue app) ────────

@task_scheduler_blueprint.route('/list', methods=['GET'])
def list_schedules():
    workflow = _workflow_or_none(request.args.get('workflow_uuid'))
    if not workflow:
        return jsonify({"message": "Workflow not found.", "toast_class": "danger-subtle"}), 404

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '', type=str).strip()
    sort = request.args.get('sort', 'created_at', type=str)
    direction = request.args.get('dir', 'desc', type=str)
    task_type = request.args.get('task_type', None, type=str)

    pagination = TaskSchedulerModel.get_schedule_list_page(workflow.id, page, per_page, search, sort, direction, task_type)
    return jsonify({
        "schedules": [s.to_json() for s in pagination.items],
        "total": pagination.total,
        "total_pages": pagination.pages,
    }), 200


@task_scheduler_blueprint.route('/picker', methods=['GET'])
def picker():
    """Lightweight list for the 'after which task' dependency select, scoped
    to one workflow — excludes exclude_uuid (the task being edited) so it
    can't depend on itself in the dropdown (the server still re-validates
    on save)."""
    from app.core.db_class.db import AdminTaskSchedule
    workflow = _workflow_or_none(request.args.get('workflow_uuid'))
    if not workflow:
        return jsonify({"message": "Workflow not found.", "toast_class": "danger-subtle"}), 404

    exclude_uuid = request.args.get('exclude_uuid')
    query = AdminTaskSchedule.query.filter_by(workflow_id=workflow.id).order_by(AdminTaskSchedule.title.asc())
    if exclude_uuid:
        query = query.filter(AdminTaskSchedule.uuid != exclude_uuid)
    return jsonify({
        "schedules": [{"id": s.id, "uuid": s.uuid, "title": s.title, "task_type": s.task_type} for s in query.all()]
    }), 200


@task_scheduler_blueprint.route('/create', methods=['POST'])
def create():
    data = request.get_json(silent=True) or {}
    schedule, err = TaskSchedulerModel.create_schedule(data, current_user)
    if err:
        return jsonify({"message": err, "toast_class": "danger-subtle"}), 400

    log_activity("admin.task_schedule_created",
                 f"Created scheduled task '{schedule.title}' ({schedule.task_type})",
                 target_type="admin_task_schedule",
                 target_uuid=schedule.uuid,
                 icon="fa-solid fa-list-check")
    return jsonify({
        "message": "Task created.",
        "toast_class": "success-subtle",
        "schedule": schedule.to_json(),
    }), 201


@task_scheduler_blueprint.route('/<uuid>/update', methods=['POST'])
def update(uuid):
    data = request.get_json(silent=True) or {}
    schedule, err = TaskSchedulerModel.update_schedule(uuid, data)
    if err:
        status = 404 if err == "Schedule not found." else 400
        return jsonify({"message": err, "toast_class": "danger-subtle"}), status

    log_activity("admin.task_schedule_updated",
                 f"Updated scheduled task '{schedule.title}'",
                 target_type="admin_task_schedule",
                 target_uuid=schedule.uuid,
                 icon="fa-solid fa-list-check")
    return jsonify({
        "message": "Task updated.",
        "toast_class": "success-subtle",
        "schedule": schedule.to_json(),
    }), 200


@task_scheduler_blueprint.route('/<uuid>/delete', methods=['POST'])
def delete(uuid):
    ok = TaskSchedulerModel.delete_schedule(uuid)
    if not ok:
        return jsonify({"message": "Schedule not found.", "toast_class": "danger-subtle"}), 404

    log_activity("admin.task_schedule_deleted",
                 "Deleted a scheduled task",
                 target_type="admin_task_schedule",
                 target_uuid=uuid,
                 icon="fa-solid fa-list-check")
    return jsonify({"message": "Task deleted.", "toast_class": "success-subtle"}), 200


@task_scheduler_blueprint.route('/bulk_delete', methods=['POST'])
def bulk_delete():
    data = request.get_json(silent=True) or {}
    workflow = _workflow_or_none(data.get('workflow_uuid'))
    if not workflow:
        return jsonify({"message": "Workflow not found.", "toast_class": "danger-subtle"}), 404

    mode = data.get('mode', 'partial')
    count = TaskSchedulerModel.bulk_delete_schedules(
        workflow.id, mode, data.get('filters'), data.get('selected_uuids'), data.get('excluded_uuids')
    )

    log_activity("admin.task_schedule_bulk_deleted",
                 f"Bulk-deleted {count} scheduled task(s)",
                 extra={"count": count, "mode": mode},
                 icon="fa-solid fa-list-check")
    return jsonify({"message": f"{count} task(s) deleted.", "toast_class": "success-subtle", "count": count}), 200


@task_scheduler_blueprint.route('/bulk_set_active', methods=['POST'])
def bulk_set_active():
    data = request.get_json(silent=True) or {}
    workflow = _workflow_or_none(data.get('workflow_uuid'))
    if not workflow:
        return jsonify({"message": "Workflow not found.", "toast_class": "danger-subtle"}), 404

    mode = data.get('mode', 'partial')
    is_active = bool(data.get('is_active', True))
    count = TaskSchedulerModel.bulk_set_active_schedules(
        workflow.id, mode, data.get('filters'), data.get('selected_uuids'), data.get('excluded_uuids'), is_active
    )

    verb = 'activated' if is_active else 'paused'
    log_activity("admin.task_schedule_bulk_set_active",
                 f"Bulk-{verb} {count} scheduled task(s)",
                 extra={"count": count, "mode": mode, "is_active": is_active},
                 icon="fa-solid fa-list-check")
    return jsonify({"message": f"{count} task(s) {verb}.", "toast_class": "success-subtle", "count": count}), 200


@task_scheduler_blueprint.route('/<uuid>/run_now', methods=['POST'])
def run_now(uuid):
    ok, err = TaskSchedulerModel.run_schedule_now(uuid)
    if not ok:
        return jsonify({"message": err, "toast_class": "danger-subtle"}), 400

    log_activity("admin.task_schedule_run_now",
                 "Manually triggered a scheduled task run",
                 target_type="admin_task_schedule",
                 target_uuid=uuid,
                 icon="fa-solid fa-list-check")
    return jsonify({"message": "Run started.", "toast_class": "success-subtle"}), 202
