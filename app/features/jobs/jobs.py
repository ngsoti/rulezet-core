"""
jobs.py — Blueprint for background job management.
Routes only. All DB logic in jobs_core.py.
"""

import datetime

from flask import Blueprint, jsonify, render_template, request, abort
from flask_login import current_user, login_required

import app.features.jobs.jobs_core as JobsModel
from app.core.db_class.db import BackgroundJob
from app.core.utils.activity_log import log_activity
from app import db

jobs_blueprint = Blueprint(
    'jobs',
    __name__,
    template_folder='templates',
)


def _get_job_or_403(job_uuid):
    job = JobsModel.get_job_by_uuid(job_uuid)
    if not job:
        return None, (jsonify({"error": "Job not found."}), 404)
    if job.created_by != current_user.id and not current_user.is_admin():
        return None, (jsonify({"error": "Forbidden."}), 403)
    return job, None


def _job_to_table_row(j, is_admin=False):
    """Adapt a BackgroundJob to the DataTable row format (flask-launchpad compatible)."""
    duration = None
    if j.started_at:
        end = j.finished_at or datetime.datetime.now(datetime.timezone.utc)
        # ensure both are offset-aware for subtraction
        started = j.started_at
        if started.tzinfo is None:
            started = started.replace(tzinfo=datetime.timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=datetime.timezone.utc)
        duration = (end - started).total_seconds()

    row = {
        "id":          j.id,
        "uuid":        j.uuid,
        "title":       j.label or j.job_type,
        "type":        j.job_type,
        "status":      j.status,
        "progress":    j.progress_pct,
        "duration":    round(duration, 1) if duration is not None else None,
        "error":       j.error,
        "created_at":  j.created_at.strftime('%Y-%m-%dT%H:%M:%S') if j.created_at else None,
        "started_at":  j.started_at.strftime('%Y-%m-%dT%H:%M:%S') if j.started_at else None,
        "finished_at": j.finished_at.strftime('%Y-%m-%dT%H:%M:%S') if j.finished_at else None,
    }
    if is_admin:
        u = j.user
        row['author'] = {
            'id':       u.id if u else None,
            'username': u.get_username() if u else f'#{j.created_by}',
            'avatar':   u.get_avatar_url() if u else None,
        } if u else {
            'id':       None,
            'username': f'#{j.created_by}',
            'avatar':   None,
        }
    return row


def _job_to_detail(j):
    """Full job detail including logs for the detail page."""
    duration = None
    if j.started_at:
        end = j.finished_at or datetime.datetime.now(datetime.timezone.utc)
        started = j.started_at
        if started.tzinfo is None:
            started = started.replace(tzinfo=datetime.timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=datetime.timezone.utc)
        duration = round((end - started).total_seconds(), 1)

    logs = []
    for log in j.logs:
        logs.append({
            "ts":    log.created_at.strftime('%Y-%m-%dT%H:%M:%S') if log.created_at else None,
            "level": log.level or 'info',
            "msg":   log.message or '',
        })

    return {
        "id":          j.id,
        "uuid":        j.uuid,
        "title":       j.label or j.job_type,
        "type":        j.job_type,
        "status":      j.status,
        "progress":    j.progress_pct,
        "duration":    duration,
        "error":       j.error,
        "meta":        j.payload or {},
        "result":      None,
        "logs":        logs,
        "created_at":  j.created_at.strftime('%Y-%m-%dT%H:%M:%S') if j.created_at else None,
        "started_at":  j.started_at.strftime('%Y-%m-%dT%H:%M:%S') if j.started_at else None,
        "finished_at": j.finished_at.strftime('%Y-%m-%dT%H:%M:%S') if j.finished_at else None,
    }


# ─── UI pages ─────────────────────────────────────────────────────────────────

def _running_jobs_count():
    return BackgroundJob.query.filter(BackgroundJob.status == 'running').count()


@jobs_blueprint.route('/list', methods=['GET'])
@login_required
def list_jobs():
    return render_template('jobs/list.html',
                           running_jobs_count=_running_jobs_count(),
                           admin_view=False)



@jobs_blueprint.route('/detail/<string:job_uuid>', methods=['GET'])
@login_required
def job_detail_page(job_uuid):
    job, err = _get_job_or_403(job_uuid)
    if err:
        abort(404)
    return render_template('jobs/detail.html', job=job, running_jobs_count=_running_jobs_count())


# ─── DataTable API ─────────────────────────────────────────────────────────────

@jobs_blueprint.route('/api/list', methods=['GET'])
@login_required
def api_list_jobs():
    """Paginated job list for the DataTable component."""
    is_admin   = current_user.is_admin()
    mine_only  = request.args.get('mine_only', 'false').lower() == 'true'
    admin_view = request.args.get('admin', 'false').lower() == 'true' and is_admin
    if not is_admin or mine_only:
        query = BackgroundJob.query.filter_by(created_by=current_user.id)
    else:
        query = BackgroundJob.query

    status = request.args.get('status', '').strip()
    if status:
        query = query.filter(BackgroundJob.status == status)

    search = request.args.get('search', '').strip()
    if search:
        like = f"%{search}%"
        query = query.filter(
            db.or_(BackgroundJob.label.ilike(like), BackgroundJob.job_type.ilike(like))
        )

    sort_map = {
        'title':      BackgroundJob.label,
        'type':       BackgroundJob.job_type,
        'status':     BackgroundJob.status,
        'created_at': BackgroundJob.created_at,
    }
    sort_field = sort_map.get(request.args.get('sort', 'created_at'), BackgroundJob.created_at)
    sort_dir   = request.args.get('dir', 'desc')
    query = query.order_by(sort_field.asc() if sort_dir == 'asc' else sort_field.desc())

    page     = max(1, request.args.get('page', 1, type=int))
    per_page = min(100, max(1, request.args.get('per_page', 10, type=int)))
    total    = query.count()
    items    = query.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "items":       [_job_to_table_row(j, is_admin=admin_view) for j in items],
        "total":       total,
        "total_pages": max(1, -(-total // per_page)),
    }), 200


@jobs_blueprint.route('/api/<string:job_uuid>', methods=['GET'])
@login_required
def api_job_detail(job_uuid):
    job, err = _get_job_or_403(job_uuid)
    if err:
        return err
    db.session.expire_all()
    job = JobsModel.get_job_by_uuid(job_uuid)
    return jsonify(_job_to_detail(job)), 200


@jobs_blueprint.route('/api/alerts', methods=['GET'])
@login_required
def api_job_alerts():
    """Return jobs with errors (failed / error field set) and warnings (cancelled mid-run)."""
    is_admin = current_user.is_admin()
    base = BackgroundJob.query if is_admin else BackgroundJob.query.filter_by(created_by=current_user.id)

    error_jobs = (
        base.filter(db.or_(BackgroundJob.status == 'failed', BackgroundJob.error.isnot(None)))
        .order_by(BackgroundJob.created_at.desc())
        .limit(25)
        .all()
    )

    warning_jobs = (
        base.filter(
            BackgroundJob.status == 'cancelled',
            BackgroundJob.started_at.isnot(None),
        )
        .order_by(BackgroundJob.created_at.desc())
        .limit(10)
        .all()
    )

    return jsonify({
        "errors":   [_job_to_table_row(j, is_admin) for j in error_jobs],
        "warnings": [_job_to_table_row(j, is_admin) for j in warning_jobs],
    }), 200


@jobs_blueprint.route('/api/<string:job_uuid>/cancel', methods=['POST'])
@login_required
def api_cancel_job(job_uuid):
    job, err = _get_job_or_403(job_uuid)
    if err:
        return err
    ok, msg = JobsModel.cancel_job(job)
    if ok:
        log_activity("job.cancel", f"Cancelled job '{job.label}' (uuid={job_uuid})",
                     target_type="job", target_id=job.id, target_uuid=job_uuid)
    return jsonify({"message": msg}), 200 if ok else 400


@jobs_blueprint.route('/api/<string:job_uuid>/pause', methods=['POST'])
@login_required
def api_pause_job(job_uuid):
    job, err = _get_job_or_403(job_uuid)
    if err:
        return err
    ok, msg = JobsModel.pause_job(job)
    if ok:
        log_activity("job.pause", f"Paused job '{job.label}' (uuid={job_uuid})",
                     target_type="job", target_id=job.id, target_uuid=job_uuid)
    return jsonify({"message": msg}), 200 if ok else 400


@jobs_blueprint.route('/api/<string:job_uuid>/resume', methods=['POST'])
@login_required
def api_resume_job(job_uuid):
    job, err = _get_job_or_403(job_uuid)
    if err:
        return err
    ok, msg = JobsModel.resume_job(job)
    if ok:
        log_activity("job.resume", f"Resumed job '{job.label}' (uuid={job_uuid})",
                     target_type="job", target_id=job.id, target_uuid=job_uuid)
    return jsonify({"message": msg}), 200 if ok else 400


@jobs_blueprint.route('/api/<string:job_uuid>', methods=['DELETE'])
@login_required
def api_delete_job(job_uuid):
    job, err = _get_job_or_403(job_uuid)
    if err:
        return err
    job_label = job.label
    ok, msg = JobsModel.delete_job(job)
    if ok:
        log_activity("job.delete", f"Deleted job '{job_label}' (uuid={job_uuid})",
                     extra={"job_uuid": job_uuid})
    return jsonify({"message": msg}), 200 if ok else 400


def _resolve_job(ref):
    """Resolve a job by integer ID or UUID string — the DataTable sends integer IDs."""
    try:
        return db.session.get(BackgroundJob, int(ref))
    except (ValueError, TypeError):
        return JobsModel.get_job_by_uuid(str(ref))


@jobs_blueprint.route('/api/bulk', methods=['POST'])
@login_required
def api_bulk_jobs():
    data   = request.json or {}
    action = data.get('action')
    refs   = data.get('uuids', [])   # may be int IDs or UUID strings

    if action not in ('cancel', 'delete'):
        return jsonify({"message": "Unknown action."}), 400
    if not refs:
        return jsonify({"message": "No jobs selected."}), 400

    ok_count = fail_count = 0
    for ref in refs:
        job = _resolve_job(ref)
        if not job:
            fail_count += 1
            continue
        if job.created_by != current_user.id and not current_user.is_admin():
            fail_count += 1
            continue
        if action == 'cancel':
            ok, _ = JobsModel.cancel_job(job)
        else:
            ok, _ = JobsModel.delete_job(job)
        if ok:
            ok_count += 1
        else:
            fail_count += 1

    verb = 'cancelled' if action == 'cancel' else 'deleted'
    return jsonify({
        "message": f"{ok_count} job(s) {verb}, {fail_count} failed.",
        "success": ok_count,
        "failed":  fail_count,
    }), 200


@jobs_blueprint.route('/get_jobs', methods=['GET'])
@login_required
def get_jobs():
    is_admin = current_user.is_admin()
    items, total, page, per_page = JobsModel.get_jobs_for_user(
        current_user.id, request.args, is_admin=is_admin)
    jobs = []
    for j in items:
        d = j.to_json()
        if is_admin:
            # owner column only exists for admins — never exposed to plain users
            d['owner'] = (f"{j.user.first_name} {j.user.last_name or ''}".strip()
                          if j.user else f"user #{j.created_by}")
        jobs.append(d)
    return jsonify({
        "jobs":       jobs,
        "total":      total,
        "page":       page,
        "per_page":   per_page,
        "total_pages": max(1, -(-total // per_page)),  # ceil division
    }), 200


@jobs_blueprint.route('/errors', methods=['GET'])
@login_required
def job_errors():
    """Recent error/warning log lines across all jobs — admin only."""
    if not current_user.is_admin():
        return jsonify({"error": "Forbidden."}), 403
    limit = min(300, request.args.get('limit', 100, type=int))
    return jsonify(JobsModel.get_job_error_logs(limit=limit)), 200


@jobs_blueprint.route('/zombies', methods=['GET'])
@login_required
def get_zombies():
    if not current_user.is_admin():
        return jsonify({"error": "Forbidden."}), 403
    zombies = JobsModel.get_zombie_jobs()
    return jsonify([j.to_json() for j in zombies]), 200


@jobs_blueprint.route('/kill_zombies', methods=['POST'])
@login_required
def kill_zombies():
    if not current_user.is_admin():
        return jsonify({"error": "Forbidden."}), 403
    ok, count, msg = JobsModel.kill_all_zombies()
    return jsonify({"message": msg, "killed": count}), 200 if ok else 500


@jobs_blueprint.route('/status/<string:job_uuid>', methods=['GET'])
@login_required
def job_status(job_uuid):
    job, err = _get_job_or_403(job_uuid)
    if err: return err
    return jsonify(job.to_json()), 200


@jobs_blueprint.route('/logs/<string:job_uuid>', methods=['GET'])
@login_required
def job_logs(job_uuid):
    """Return log lines for a job. Pass ?since_id=N to get only new lines."""
    job, err = _get_job_or_403(job_uuid)
    if err: return err
    since_id = request.args.get('since_id', 0, type=int)
    logs = JobsModel.get_job_logs(job_uuid, since_id=since_id)
    return jsonify([l.to_json() for l in logs]), 200


# Job types a non-admin holding rule.tag_any may create via /jobs/create —
# every other job_type reachable through that endpoint (packages, submodules,
# connector pulls, trash purge, db backup, ...) stays admin-only.
_TAG_MANAGER_JOB_TYPES = {'bulk_add_tag_to_rules', 'bulk_remove_tag_from_rules'}


@jobs_blueprint.route('/create', methods=['POST'])
@login_required
def create_job():
    data     = request.json or {}
    job_type = data.get('job_type')
    payload  = data.get('payload', {})
    label    = data.get('label', job_type)

    if not job_type:
        return jsonify({"error": "job_type is required."}), 400

    # Job types reachable from this endpoint are administrative by default —
    # user-level jobs are created server-side by their own gated routes,
    # never through here. The one narrow exception: a non-admin holding
    # rule.tag_any may create the two tag job types, matching what the
    # rule.tag_any-gated /rule/bulk_tag page itself is allowed to do.
    is_tag_manager_job = job_type in _TAG_MANAGER_JOB_TYPES and current_user.has_permission('rule.tag_any')
    if not current_user.is_admin() and not is_tag_manager_job:
        return jsonify({"error": "Forbidden."}), 403

    payload['user_id'] = current_user.id

    job = JobsModel.create_job(
        job_type=job_type,
        payload=payload,
        label=label,
        created_by=current_user.id,
    )
    if not job:
        return jsonify({"error": "Failed to create job."}), 500

    log_activity("job.create", f"Created job '{label}' (type={job_type})",
                 target_type="job", target_id=job.id, target_uuid=job.uuid)
    return jsonify({"job": job.to_json(), "message": "Job queued."}), 200


@jobs_blueprint.route('/cancel/<string:job_uuid>', methods=['POST'])
@login_required
def cancel_job(job_uuid):
    job, err = _get_job_or_403(job_uuid)
    if err: return err
    ok, msg = JobsModel.cancel_job(job)
    if ok:
        log_activity("job.cancel", f"Cancelled job '{job.label}' (uuid={job_uuid})",
                     target_type="job", target_id=job.id, target_uuid=job_uuid)
    return jsonify({"message": msg}), 200 if ok else 400


@jobs_blueprint.route('/pause/<string:job_uuid>', methods=['POST'])
@login_required
def pause_job(job_uuid):
    job, err = _get_job_or_403(job_uuid)
    if err: return err
    ok, msg = JobsModel.pause_job(job)
    if ok:
        log_activity("job.pause", f"Paused job '{job.label}' (uuid={job_uuid})",
                     target_type="job", target_id=job.id, target_uuid=job_uuid)
    return jsonify({"message": msg}), 200 if ok else 400


@jobs_blueprint.route('/resume/<string:job_uuid>', methods=['POST'])
@login_required
def resume_job(job_uuid):
    job, err = _get_job_or_403(job_uuid)
    if err: return err
    ok, msg = JobsModel.resume_job(job)
    if ok:
        log_activity("job.resume", f"Resumed job '{job.label}' (uuid={job_uuid})",
                     target_type="job", target_id=job.id, target_uuid=job_uuid)
    return jsonify({"message": msg}), 200 if ok else 400


@jobs_blueprint.route('/my_active', methods=['GET'])
@login_required
def my_active_jobs():
    """Active jobs + recently completed jobs for the current user — used by the widget.

    Returns pending/running/paused jobs plus 'done' jobs finished in the last 30 seconds
    so the widget can briefly display 100% before the job disappears.
    """
    from datetime import datetime, timedelta, timezone
    from app.core.db_class.db import BackgroundJob
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=30)
    jobs = (BackgroundJob.query
            .filter(
                BackgroundJob.created_by == current_user.id,
                db.or_(
                    BackgroundJob.status.in_(['pending', 'running', 'paused']),
                    db.and_(
                        BackgroundJob.status == 'done',
                        BackgroundJob.finished_at >= cutoff,
                    ),
                )
            )
            .order_by(BackgroundJob.created_at.desc())
            .limit(20).all())
    return jsonify([j.to_json() for j in jobs]), 200


@jobs_blueprint.route('/delete/<string:job_uuid>', methods=['POST'])
@login_required
def delete_job(job_uuid):
    job, err = _get_job_or_403(job_uuid)
    if err: return err
    job_label = job.label
    ok, msg = JobsModel.delete_job(job)
    if ok:
        log_activity("job.delete", f"Deleted job '{job_label}' (uuid={job_uuid})",
                     extra={"job_uuid": job_uuid})
    return jsonify({"message": msg}), 200 if ok else 400