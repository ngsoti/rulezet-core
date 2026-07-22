"""
sync_schedule_routes.py — admin-only Blueprint for recurring GitHub Sync
Schedules (CRUD + repo picker + manual run + multi-repo report page).
All DB/business logic lives in sync_schedule_core.py; execution lives in the
'github_sync_schedule_run' BackgroundJob handler (job_handlers.py).
"""
from flask import Blueprint, abort, jsonify, redirect, render_template, request, url_for
from flask_login import current_user

import app.features.rule.rule_core as RuleModel
from app.core.db_class.db import GithubSyncRun
from app.core.utils.activity_log import log_activity
from app.features.rule.rule_from_github.sync_schedule import sync_schedule_core as SyncScheduleModel

sync_schedule_blueprint = Blueprint(
    'sync_schedule',
    __name__,
    template_folder='templates',
)


@sync_schedule_blueprint.before_request
def _require_admin():
    if not current_user.is_authenticated:
        return redirect(url_for('account.login'))
    if not current_user.is_admin():
        abort(403)


# ─── CRUD (JSON API used by the Vue app) ──────────────────────────────────────

@sync_schedule_blueprint.route('/schedule/list', methods=['GET'])
def schedule_list():
    if not current_user.is_admin():
        return jsonify({"message": "Access denied", "toast_class": "danger-subtle"}), 403

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '', type=str).strip()
    sort = request.args.get('sort', 'created_at', type=str)
    direction = request.args.get('dir', 'desc', type=str)

    pagination = SyncScheduleModel.get_schedule_list_page(page, per_page, search, sort, direction)
    return jsonify({
        "schedules": [s.to_json() for s in pagination.items],
        "total": pagination.total,
        "total_pages": pagination.pages,
    }), 200


@sync_schedule_blueprint.route('/schedule/create', methods=['POST'])
def schedule_create():
    if not current_user.is_admin():
        return jsonify({"message": "Access denied", "toast_class": "danger-subtle"}), 403

    data = request.get_json(silent=True) or {}
    schedule, err = SyncScheduleModel.create_schedule(data, current_user)
    if err:
        return jsonify({"message": err, "toast_class": "danger-subtle"}), 400

    log_activity("github.sync_schedule_created",
                 f"Created Sync Schedule '{schedule.title}' ({len(schedule.repos)} repo(s))",
                 target_type="github_sync_schedule",
                 target_uuid=schedule.uuid,
                 icon="fa-brands fa-github")
    return jsonify({
        "message": "Sync Schedule created.",
        "toast_class": "success-subtle",
        "schedule": schedule.to_json(),
    }), 201


@sync_schedule_blueprint.route('/schedule/<uuid>/update', methods=['POST'])
def schedule_update(uuid):
    if not current_user.is_admin():
        return jsonify({"message": "Access denied", "toast_class": "danger-subtle"}), 403

    data = request.get_json(silent=True) or {}
    schedule, err = SyncScheduleModel.update_schedule(uuid, data)
    if err:
        status = 404 if err == "Schedule not found." else 400
        return jsonify({"message": err, "toast_class": "danger-subtle"}), status

    log_activity("github.sync_schedule_updated",
                 f"Updated Sync Schedule '{schedule.title}'",
                 target_type="github_sync_schedule",
                 target_uuid=schedule.uuid,
                 icon="fa-brands fa-github")
    return jsonify({
        "message": "Sync Schedule updated.",
        "toast_class": "success-subtle",
        "schedule": schedule.to_json(),
    }), 200


@sync_schedule_blueprint.route('/schedule/<uuid>/delete', methods=['POST'])
def schedule_delete(uuid):
    if not current_user.is_admin():
        return jsonify({"message": "Access denied", "toast_class": "danger-subtle"}), 403

    ok = SyncScheduleModel.delete_schedule(uuid)
    if not ok:
        return jsonify({"message": "Schedule not found.", "toast_class": "danger-subtle"}), 404

    log_activity("github.sync_schedule_deleted",
                 "Deleted a Sync Schedule",
                 target_type="github_sync_schedule",
                 target_uuid=uuid,
                 icon="fa-brands fa-github")
    return jsonify({"message": "Sync Schedule deleted.", "toast_class": "success-subtle"}), 200


@sync_schedule_blueprint.route('/schedule/bulk_delete', methods=['POST'])
def schedule_bulk_delete():
    if not current_user.is_admin():
        return jsonify({"message": "Access denied", "toast_class": "danger-subtle"}), 403

    data = request.get_json(silent=True) or {}
    mode = data.get('mode', 'partial')
    count = SyncScheduleModel.bulk_delete_schedules(
        mode, data.get('filters'), data.get('selected_uuids'), data.get('excluded_uuids')
    )

    log_activity("github.sync_schedule_bulk_deleted",
                 f"Bulk-deleted {count} Sync Schedule(s)",
                 extra={"count": count, "mode": mode},
                 icon="fa-brands fa-github")
    return jsonify({
        "message": f"{count} Sync Schedule(s) deleted.",
        "toast_class": "success-subtle",
        "count": count,
    }), 200


@sync_schedule_blueprint.route('/schedule/bulk_set_active', methods=['POST'])
def schedule_bulk_set_active():
    if not current_user.is_admin():
        return jsonify({"message": "Access denied", "toast_class": "danger-subtle"}), 403

    data = request.get_json(silent=True) or {}
    mode = data.get('mode', 'partial')
    is_active = bool(data.get('is_active', True))
    count = SyncScheduleModel.bulk_set_active_schedules(
        mode, data.get('filters'), data.get('selected_uuids'), data.get('excluded_uuids'), is_active
    )

    verb = 'activated' if is_active else 'paused'
    log_activity("github.sync_schedule_bulk_set_active",
                 f"Bulk-{verb} {count} Sync Schedule(s)",
                 extra={"count": count, "mode": mode, "is_active": is_active},
                 icon="fa-brands fa-github")
    return jsonify({
        "message": f"{count} Sync Schedule(s) {verb}.",
        "toast_class": "success-subtle",
        "count": count,
    }), 200


@sync_schedule_blueprint.route('/schedule/<uuid>/run_now', methods=['POST'])
def schedule_run_now(uuid):
    if not current_user.is_admin():
        return jsonify({"message": "Access denied", "toast_class": "danger-subtle"}), 403

    ok, err = SyncScheduleModel.run_schedule_now(uuid)
    if not ok:
        return jsonify({"message": err, "toast_class": "danger-subtle"}), 400

    log_activity("github.sync_schedule_run_now",
                 "Manually triggered a Sync Schedule run",
                 target_type="github_sync_schedule",
                 target_uuid=uuid,
                 icon="fa-brands fa-github")
    return jsonify({"message": "Run started.", "toast_class": "success-subtle"}), 202


# ─── Repo picker (reuses the same query list_github_url already uses) ─────────

@sync_schedule_blueprint.route('/schedule/repo_candidates', methods=['GET'])
def repo_candidates():
    if not current_user.is_admin():
        return jsonify({"message": "Access denied", "toast_class": "danger-subtle"}), 403

    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', None, type=str)
    search_field = request.args.get('search_field', 'url', type=str)
    format_filter = request.args.get('format', None, type=str)
    author_filter = request.args.get('author', None, type=str)

    github_data, total, total_pages = RuleModel.get_optimized_github_data(
        page=page, search=search, search_field=search_field,
        format_filter=format_filter, author_filter=author_filter,
    )
    return jsonify({"repos": github_data, "total": total, "total_pages": total_pages}), 200


# ─── Multi-repo report page ────────────────────────────────────────────────────

@sync_schedule_blueprint.route('/sync_run/<uuid>', methods=['GET'])
def sync_run_detail(uuid):
    if not current_user.is_admin():
        abort(403)
    run = GithubSyncRun.query.filter_by(uuid=uuid).first()
    if not run:
        abort(404)
    return render_template('rule/github_sync/sync_run.html', run_uuid=uuid)


@sync_schedule_blueprint.route('/sync_run/<uuid>/status', methods=['GET'])
def sync_run_status(uuid):
    if not current_user.is_admin():
        return jsonify({"message": "Access denied", "toast_class": "danger-subtle"}), 403

    from app import db
    db.session.expire_all()  # avoid stale progress — job_worker mutates this row on another thread

    run = GithubSyncRun.query.filter_by(uuid=uuid).first()
    if not run:
        return jsonify({"message": "Run not found.", "toast_class": "danger-subtle"}), 404

    payload = run.to_json()
    if run.job_uuid:
        from app.features.jobs.jobs_core import get_job_by_uuid
        job = get_job_by_uuid(run.job_uuid)
        if job:
            payload["job"] = {"done": job.done, "total": job.total, "status": job.status}

    # Enrich each repo entry with its UpdateResult summary (found/updated/
    # not_found/skipped/new_rules_count) — reuses the exact same serializer
    # the single-repo update_loading page already uses, no new shape invented.
    for repo_entry in payload.get("repos", []):
        repo_entry["update_summary"] = None
        if repo_entry.get("update_result_uuid"):
            result = RuleModel.get_updater_result(repo_entry["update_result_uuid"])
            if result:
                repo_entry["update_summary"] = result.to_json_list()

    return jsonify(payload), 200
