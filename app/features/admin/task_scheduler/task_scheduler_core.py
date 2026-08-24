"""
task_scheduler_core.py — CRUD + validation for AdminTaskSchedule (the
generalized Admin Task Scheduler). Modeled directly on
sync_schedule_core.py: keeps the live APScheduler trigger in lockstep with
the DB row on every mutation so a restart is never needed to pick up a
change. See docs/design/admin_task_scheduler.md for the full design.
"""
import datetime
import re
import uuid as _uuid_mod

from flask import current_app

from app import db
from app.core.db_class.db import AdminTaskSchedule, AdminWorkflow
from app.features.admin.task_scheduler.task_types import TASK_TYPES
from app.features.admin.task_scheduler.scheduler_engine import _creates_cycle

VALID_TRIGGER_MODES = ('once', 'daily', 'weekly', 'monthly', 'cron', 'after_task')

_EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')


def _clean_notify_emails(raw):
    """Defense-in-depth: drop anything that isn't a plausible single email
    address before it ever reaches Message(recipients=...) — Flask-Mail
    already rejects CRLF in a header value, but this feature shouldn't rely
    on that alone."""
    if not raw:
        return []
    return [e.strip() for e in raw if isinstance(e, str) and _EMAIL_RE.match(e.strip())]


# ─── Workflows — the container an admin creates first, then assigns tasks into ──

def get_workflow_list_page(page=1, per_page=20, search='', sort='created_at', direction='desc'):
    per_page = max(1, min(per_page or 20, 100))
    query = AdminWorkflow.query
    if search:
        query = query.filter(AdminWorkflow.title.ilike(f"%{search}%"))
    sort_col = {
        'title': AdminWorkflow.title,
        'created_at': AdminWorkflow.created_at,
        'updated_at': AdminWorkflow.updated_at,
    }.get(sort, AdminWorkflow.created_at)
    query = query.order_by(sort_col.asc() if direction == 'asc' else sort_col.desc())
    return query.paginate(page=page, per_page=per_page, max_per_page=100)


def get_workflow_by_uuid(workflow_uuid):
    return AdminWorkflow.query.filter_by(uuid=workflow_uuid).first()


def create_workflow(data, editor):
    title = (data.get('title') or '').strip()
    if not title:
        return None, "Title is required."

    workflow = AdminWorkflow(
        uuid=str(_uuid_mod.uuid4()),
        title=title,
        description=data.get('description'),
        editor_id=editor.id,
        is_active=bool(data.get('is_active', True)),
        notify_on_failure=bool(data.get('notify_on_failure', True)),
        notify_on_success=bool(data.get('notify_on_success', False)),
        notify_emails=_clean_notify_emails(data.get('notify_emails')),
    )
    db.session.add(workflow)
    db.session.commit()
    return workflow, None


def update_workflow(workflow_uuid, data):
    workflow = AdminWorkflow.query.filter_by(uuid=workflow_uuid).first()
    if not workflow:
        return None, "Workflow not found."

    title = (data.get('title') or '').strip()
    if not title:
        return None, "Title is required."

    workflow.title = title
    workflow.description = data.get('description')
    workflow.is_active = bool(data.get('is_active', workflow.is_active))
    workflow.notify_on_failure = bool(data.get('notify_on_failure', workflow.notify_on_failure))
    workflow.notify_on_success = bool(data.get('notify_on_success', workflow.notify_on_success))
    if 'notify_emails' in data:
        workflow.notify_emails = _clean_notify_emails(data.get('notify_emails'))
    db.session.commit()
    return workflow, None


def delete_workflow(workflow_uuid):
    from app.features.admin.task_scheduler.scheduler_engine import unregister_schedule
    workflow = AdminWorkflow.query.filter_by(uuid=workflow_uuid).first()
    if not workflow:
        return False
    for task in workflow.tasks:
        unregister_schedule(task.uuid)
    db.session.delete(workflow)  # cascades to its tasks (AdminWorkflow.tasks relationship)
    db.session.commit()
    return True


# ─── Tasks — always scoped to a workflow ───────────────────────────────────────

def _validate_trigger(data, schedule_id=None, workflow_id=None):
    mode = data.get('trigger_mode')
    if mode not in VALID_TRIGGER_MODES:
        return False, f"Invalid trigger_mode: {mode!r}"

    if mode == 'once':
        if not data.get('run_once_at'):
            return False, "run_once_at is required when trigger_mode is 'once'."
        try:
            datetime.datetime.fromisoformat(data['run_once_at'])
        except ValueError:
            return False, "run_once_at must be an ISO datetime string."
        return True, None

    if mode == 'after_task':
        depends_on_id = data.get('depends_on_schedule_id')
        if not depends_on_id:
            return False, "depends_on_schedule_id is required when trigger_mode is 'after_task'."
        parent = AdminTaskSchedule.query.get(depends_on_id)
        if not parent:
            return False, "The parent task to depend on was not found."
        if workflow_id is not None and parent.workflow_id != workflow_id:
            return False, "A task can only depend on another task within the same workflow."
        if depends_on_id == schedule_id:
            return False, "A task cannot depend on itself."
        if _creates_cycle(schedule_id, depends_on_id):
            return False, "This dependency would create a cycle between tasks."
        if data.get('depends_on_condition') not in ('success', 'failure', 'always'):
            return False, "depends_on_condition must be 'success', 'failure', or 'always'."
        return True, None

    if mode == 'weekly':
        dow = data.get('days_of_week') or []
        if not isinstance(dow, list) or not dow or not all(isinstance(d, int) and 0 <= d <= 6 for d in dow):
            return False, "days_of_week must be a non-empty list of integers 0-6 (0 = Monday)."

    if mode == 'monthly':
        dom = data.get('day_of_month')
        if dom is None or not (dom == -1 or 1 <= dom <= 31):
            return False, "day_of_month must be 1-31, or -1 for the last day of the month."

    if mode == 'cron':
        cron_expr = data.get('cron_expr')
        if not cron_expr:
            return False, "cron_expr is required when trigger_mode is 'cron'."
        try:
            from apscheduler.triggers.cron import CronTrigger
            CronTrigger.from_crontab(cron_expr, timezone=data.get('timezone') or 'UTC')
        except Exception as e:
            return False, f"Invalid cron expression: {e}"

    hour = data.get('hour', 3)
    minute = data.get('minute', 0)
    if not isinstance(hour, int) or not (0 <= hour <= 23):
        return False, "hour must be an integer 0-23."
    if not isinstance(minute, int) or not (0 <= minute <= 59):
        return False, "minute must be an integer 0-59."

    return True, None


def _apply_trigger_fields(schedule, data):
    mode = data.get('trigger_mode')
    schedule.trigger_mode = mode

    schedule.run_once_at = None
    schedule.days_of_week = None
    schedule.day_of_month = None
    schedule.cron_expr = None
    schedule.depends_on_schedule_id = None
    schedule.depends_on_condition = 'success'

    if mode == 'once':
        schedule.run_once_at = datetime.datetime.fromisoformat(data['run_once_at'])
        return
    if mode == 'after_task':
        schedule.depends_on_schedule_id = data.get('depends_on_schedule_id')
        schedule.depends_on_condition = data.get('depends_on_condition', 'success')
        return

    if mode == 'weekly':
        schedule.days_of_week = ','.join(str(d) for d in data.get('days_of_week', []))
    elif mode == 'monthly':
        schedule.day_of_month = data.get('day_of_month')
    elif mode == 'cron':
        schedule.cron_expr = data.get('cron_expr')

    schedule.hour = data.get('hour', 3)
    schedule.minute = data.get('minute', 0)
    schedule.timezone = data.get('timezone') or 'UTC'


def _build_target_payload(task_type, target_payload):
    """Merge in any registry-level fixed_payload (e.g. activity_log_purge
    always forces delete_all=True) — client-supplied keys never override
    these, since they express a deliberate scheduling-safety choice, not a
    per-run preference."""
    task_def = TASK_TYPES[task_type]
    payload = dict(target_payload or {})
    payload.update(task_def.get('fixed_payload', {}))
    return payload


def _register_live(schedule):
    from app.features.admin.task_scheduler.scheduler_engine import register_schedule
    register_schedule(current_app._get_current_object(), schedule)
    db.session.commit()


def get_schedule_list_page(workflow_id, page=1, per_page=20, search='', sort='created_at', direction='desc', task_type=None):
    per_page = max(1, min(per_page or 20, 100))
    query = AdminTaskSchedule.query.filter_by(workflow_id=workflow_id)
    if search:
        query = query.filter(AdminTaskSchedule.title.ilike(f"%{search}%"))
    if task_type:
        query = query.filter(AdminTaskSchedule.task_type == task_type)
    sort_col = {
        'title': AdminTaskSchedule.title,
        'next_run_at': AdminTaskSchedule.next_run_at,
        'last_run_at': AdminTaskSchedule.last_run_at,
        'created_at': AdminTaskSchedule.created_at,
    }.get(sort, AdminTaskSchedule.created_at)
    query = query.order_by(sort_col.asc() if direction == 'asc' else sort_col.desc())
    return query.paginate(page=page, per_page=per_page, max_per_page=100)


def create_schedule(data, editor):
    workflow = AdminWorkflow.query.filter_by(uuid=data.get('workflow_uuid')).first()
    if not workflow:
        return None, "Workflow not found."

    task_type = data.get('task_type')
    if task_type not in TASK_TYPES:
        return None, f"Unknown task_type: {task_type!r}"

    ok, err = _validate_trigger(data, workflow_id=workflow.id)
    if not ok:
        return None, err

    title = (data.get('title') or '').strip()
    if not title:
        return None, "Title is required."

    schedule = AdminTaskSchedule(
        uuid=str(_uuid_mod.uuid4()),
        title=title,
        description=data.get('description'),
        editor_id=editor.id,
        workflow_id=workflow.id,
        task_type=task_type,
        target_payload=_build_target_payload(task_type, data.get('target_payload')),
        is_active=bool(data.get('is_active', True)),
    )
    _apply_trigger_fields(schedule, data)
    db.session.add(schedule)
    db.session.flush()
    db.session.commit()

    _register_live(schedule)
    return schedule, None


def update_schedule(schedule_uuid, data):
    schedule = AdminTaskSchedule.query.filter_by(uuid=schedule_uuid).first()
    if not schedule:
        return None, "Schedule not found."

    task_type = data.get('task_type', schedule.task_type)
    if task_type not in TASK_TYPES:
        return None, f"Unknown task_type: {task_type!r}"

    # A task's workflow is fixed at creation — Phase 1 does not support
    # moving a task between workflows (a cross-workflow depends_on would
    # need to be untangled first).
    ok, err = _validate_trigger(data, schedule_id=schedule.id, workflow_id=schedule.workflow_id)
    if not ok:
        return None, err

    title = (data.get('title') or '').strip()
    if not title:
        return None, "Title is required."

    schedule.title = title
    schedule.description = data.get('description')
    schedule.is_active = bool(data.get('is_active', schedule.is_active))
    schedule.task_type = task_type
    if 'target_payload' in data:
        schedule.target_payload = _build_target_payload(task_type, data.get('target_payload'))
    _apply_trigger_fields(schedule, data)

    db.session.commit()
    _register_live(schedule)
    return schedule, None


def delete_schedule(schedule_uuid):
    from app.features.admin.task_scheduler.scheduler_engine import unregister_schedule
    schedule = AdminTaskSchedule.query.filter_by(uuid=schedule_uuid).first()
    if not schedule:
        return False
    unregister_schedule(schedule.uuid)
    # Any child schedule depending on this one loses its parent — surface
    # that in the UI (depends_on_schedule_title becomes null) rather than
    # silently leaving a dangling reference.
    AdminTaskSchedule.query.filter_by(depends_on_schedule_id=schedule.id).update(
        {"depends_on_schedule_id": None, "is_active": False}
    )
    db.session.delete(schedule)
    db.session.commit()
    return True


def _resolve_bulk_targets(workflow_id, mode, filters, selected_uuids, excluded_uuids):
    filters = filters or {}
    query = AdminTaskSchedule.query.filter_by(workflow_id=workflow_id)
    if filters.get('search'):
        query = query.filter(AdminTaskSchedule.title.ilike(f"%{filters['search']}%"))

    if mode == 'all':
        excluded = set(excluded_uuids or [])
        return [s for s in query.all() if s.uuid not in excluded]
    return query.filter(AdminTaskSchedule.uuid.in_(selected_uuids or [])).all()


def bulk_delete_schedules(workflow_id, mode, filters, selected_uuids, excluded_uuids):
    from app.features.admin.task_scheduler.scheduler_engine import unregister_schedule
    targets = _resolve_bulk_targets(workflow_id, mode, filters, selected_uuids, excluded_uuids)

    count = 0
    for schedule in targets:
        unregister_schedule(schedule.uuid)
        AdminTaskSchedule.query.filter_by(depends_on_schedule_id=schedule.id).update(
            {"depends_on_schedule_id": None, "is_active": False}
        )
        db.session.delete(schedule)
        count += 1
    db.session.commit()
    return count


def bulk_set_active_schedules(workflow_id, mode, filters, selected_uuids, excluded_uuids, is_active):
    targets = _resolve_bulk_targets(workflow_id, mode, filters, selected_uuids, excluded_uuids)

    count = 0
    for schedule in targets:
        schedule.is_active = is_active
        _register_live(schedule)
        count += 1
    db.session.commit()
    return count


def run_schedule_now(schedule_uuid):
    """Manually trigger one run immediately, outside its normal cadence —
    reuses the exact same _fire_schedule the scheduler/chaining itself
    calls, so a manual run creates an identical AdminTaskRun + BackgroundJob.
    Returns the new run's job_uuid (still truthy, like the old `True`) so the
    caller can jump straight to that job's detail instead of waiting for the
    next live-status poll to discover it."""
    from app.core.db_class.db import AdminTaskRun
    from app.features.admin.task_scheduler.scheduler_engine import _fire_schedule
    schedule = AdminTaskSchedule.query.filter_by(uuid=schedule_uuid).first()
    if not schedule:
        return False, "Schedule not found."
    if not schedule.is_active:
        return False, "Task is paused — activate it before running it manually."
    _fire_schedule(current_app._get_current_object(), schedule.uuid)
    run = AdminTaskRun.query.filter_by(schedule_id=schedule.id).order_by(AdminTaskRun.started_at.desc()).first()
    return (run.job_uuid if run else True), None


def run_workflow_now(workflow_uuid, triggered_by=None):
    """Fire every 'root' task in the workflow (one not triggered by another
    task's completion) right now — the rest of the chain follows on its own
    via on_job_finished() as each root's job completes. Lets an admin launch
    the whole pipeline with one click instead of running its first task.
    Records one AdminWorkflowRun for the launch-history table; the chain's
    workflow_run_id is propagated to every task it triggers, directly or
    through on_job_finished()."""
    from app.core.db_class.db import AdminWorkflowRun
    from app.features.admin.task_scheduler.scheduler_engine import _fire_schedule
    workflow = AdminWorkflow.query.filter_by(uuid=workflow_uuid).first()
    if not workflow:
        return False, "Workflow not found."

    roots = [t for t in workflow.tasks if t.trigger_mode != 'after_task' and t.is_active]
    if not roots:
        return False, "This workflow has no independently-triggered (non-paused) task to start from."

    workflow_run = AdminWorkflowRun(
        uuid=str(_uuid_mod.uuid4()), workflow_id=workflow.id,
        triggered_by_id=triggered_by.id if triggered_by else None,
    )
    db.session.add(workflow_run)
    db.session.commit()

    app = current_app._get_current_object()
    for task in roots:
        _fire_schedule(app, task.uuid, workflow_run_id=workflow_run.id)

    try:
        from app.features.notification.notification_core import notify_admins_workflow_run_started
        notify_admins_workflow_run_started(workflow_run)
    except Exception as e:
        current_app.logger.warning(f"notify_admins_workflow_run_started failed: {e}")

    try:
        from app.features.admin.task_scheduler.notifications import maybe_send_workflow_run_alert
        maybe_send_workflow_run_alert(workflow, 'started')
    except Exception as e:
        current_app.logger.warning(f"maybe_send_workflow_run_alert(started) failed: {e}")

    return workflow_run, None


def stop_workflow_jobs(workflow_uuid):
    """Cancel every currently pending/running job among this workflow's
    tasks — the 'Stop Workflow' button. Cooperative like every other cancel
    in the app: a handler only actually halts at its next _is_cancelled()
    checkpoint (see job_worker.py), it isn't a hard kill. Cancelling a job
    directly (not via job_worker's own completion path) does NOT trigger
    on_job_finished(), so the chain simply stops — no child task fires from
    a cancelled run, which is exactly the intent of stopping a workflow."""
    from app.core.db_class.db import AdminTaskRun, BackgroundJob
    from app.features.jobs.jobs_core import cancel_job

    workflow = AdminWorkflow.query.filter_by(uuid=workflow_uuid).first()
    if not workflow:
        return None, "Workflow not found."

    stopped = 0
    touched_run_ids = set()
    for task in workflow.tasks:
        run = (AdminTaskRun.query.filter_by(schedule_id=task.id)
               .order_by(AdminTaskRun.started_at.desc()).first())
        if not run or not run.job_uuid:
            continue
        job = BackgroundJob.query.filter_by(uuid=run.job_uuid).first()
        if job and job.status in ('pending', 'running', 'paused'):
            ok, _ = cancel_job(job)
            if ok:
                stopped += 1
                touched_run_ids.add(run.workflow_run_id)

    for run_id in touched_run_ids:
        _finalize_workflow_run_if_done(run_id)

    return stopped, None


def _finalize_workflow_run_if_done(workflow_run_id):
    """Fire the one 'workflow run finished' notification for a launch once
    every task run tied to it has reached a terminal state — called after
    each settling task (see on_job_finished in scheduler_engine.py) and
    after Stop Workflow, since a cancelled job never goes through
    on_job_finished on its own. Idempotent: skips if already notified."""
    if not workflow_run_id:
        return
    from app.core.db_class.db import AdminTaskRun, AdminWorkflowRun, BackgroundJob, Notification

    workflow_run = AdminWorkflowRun.query.get(workflow_run_id)
    if not workflow_run:
        return

    task_runs = AdminTaskRun.query.filter_by(workflow_run_id=workflow_run_id).all()
    if not task_runs:
        return

    statuses = []
    for tr in task_runs:
        job = BackgroundJob.query.filter_by(uuid=tr.job_uuid).first() if tr.job_uuid else None
        statuses.append(job.status if job else tr.status)

    if any(s in ('pending', 'running', 'paused') for s in statuses):
        return  # still in flight — a chained child may still fire

    already_notified = Notification.query.filter_by(
        job_uuid=workflow_run.uuid, notif_type='workflow_run_finished').first()
    if already_notified:
        return

    done_count = sum(1 for s in statuses if s == 'done')
    failed_count = sum(1 for s in statuses if s == 'failed')
    cancelled_count = sum(1 for s in statuses if s == 'cancelled')

    try:
        from app.features.notification.notification_core import notify_admins_workflow_run_finished
        notify_admins_workflow_run_finished(
            workflow_run, done_count=done_count, failed_count=failed_count,
            cancelled_count=cancelled_count, task_count=len(statuses),
        )
    except Exception as e:
        current_app.logger.warning(f"notify_admins_workflow_run_finished failed: {e}")

    # One email for the whole launch, not one per task — cancelled-with-no-
    # failures was a deliberate Stop Workflow, not an outcome worth emailing.
    if failed_count or (done_count and not cancelled_count):
        try:
            from app.features.admin.task_scheduler.notifications import maybe_send_workflow_run_alert
            summary = f"{done_count}/{len(statuses)} task(s) done" + (f", {failed_count} failed" if failed_count else "")
            maybe_send_workflow_run_alert(workflow_run.workflow, 'failure' if failed_count else 'success', summary)
        except Exception as e:
            current_app.logger.warning(f"maybe_send_workflow_run_alert(finished) failed: {e}")


def get_workflow_runs_page(workflow_uuid, page=1, per_page=10):
    """Launch history — one row per 'Run Workflow' click, each summarizing
    every task run it directly fired or chained afterwards."""
    from app.core.db_class.db import AdminWorkflowRun
    workflow = AdminWorkflow.query.filter_by(uuid=workflow_uuid).first()
    if not workflow:
        return None
    return (AdminWorkflowRun.query.filter_by(workflow_id=workflow.id)
            .order_by(AdminWorkflowRun.started_at.desc())
            .paginate(page=page, per_page=min(per_page or 10, 50), max_per_page=50))


def bulk_delete_workflow_runs(workflow_uuid, run_uuids):
    """Delete one or more launch-history entries. Only removes the
    bookkeeping row — the AdminTaskRun rows it grouped keep existing (their
    workflow_run_id is set to NULL by the FK's ON DELETE SET NULL), so a
    task's own last_run_status/logs are unaffected."""
    from app.core.db_class.db import AdminWorkflowRun
    workflow = AdminWorkflow.query.filter_by(uuid=workflow_uuid).first()
    if not workflow:
        return None, "Workflow not found."

    targets = AdminWorkflowRun.query.filter(
        AdminWorkflowRun.workflow_id == workflow.id,
        AdminWorkflowRun.uuid.in_(run_uuids or []),
    ).all()
    count = len(targets)
    for run in targets:
        db.session.delete(run)
    db.session.commit()
    return count, None


def serialize_workflow_run(run):
    from app.core.db_class.db import AdminTaskRun, BackgroundJob

    db.session.expire_all()
    task_runs = AdminTaskRun.query.filter_by(workflow_run_id=run.id).order_by(AdminTaskRun.started_at.asc()).all()
    tasks = []
    for tr in task_runs:
        job = BackgroundJob.query.filter_by(uuid=tr.job_uuid).first() if tr.job_uuid else None
        job_status = job.status if job else tr.status
        tasks.append({
            "task_uuid": tr.schedule.uuid,
            "task_title": tr.schedule.title,
            "job_uuid": tr.job_uuid,
            "status": job_status,
        })

    statuses = [t["status"] for t in tasks]
    if any(s in ('pending', 'running') for s in statuses):
        overall = 'running'
    elif any(s == 'failed' for s in statuses):
        overall = 'failed'
    elif any(s == 'cancelled' for s in statuses):
        overall = 'cancelled'
    elif statuses:
        overall = 'done'
    else:
        overall = 'pending'

    return {
        "uuid": run.uuid,
        "started_at": run.started_at.strftime('%Y-%m-%d %H:%M') if run.started_at else None,
        "triggered_by": {
            "id": run.triggered_by.id,
            "name": f"{run.triggered_by.first_name} {run.triggered_by.last_name}".strip(),
            "avatar": run.triggered_by.get_avatar_url(),
        } if run.triggered_by else None,
        "status": overall,
        "task_count": len(tasks),
        "done_count": sum(1 for s in statuses if s == 'done'),
        "failed_count": sum(1 for s in statuses if s == 'failed'),
        "tasks": tasks,
    }


def get_workflow_live_status(workflow_uuid):
    """One row per task in the workflow, describing its most recent run's
    live BackgroundJob state — feeds the graph view's running/done/failed
    node highlighting and the 'Live runs' log panel while a workflow is in
    flight. Returns None if the workflow doesn't exist."""
    from app.core.db_class.db import AdminTaskRun, BackgroundJob

    workflow = AdminWorkflow.query.filter_by(uuid=workflow_uuid).first()
    if not workflow:
        return None

    db.session.expire_all()  # avoid stale progress — job_worker mutates jobs on another thread
    result = []
    for task in workflow.tasks:
        run = (AdminTaskRun.query.filter_by(schedule_id=task.id)
               .order_by(AdminTaskRun.started_at.desc()).first())
        job = BackgroundJob.query.filter_by(uuid=run.job_uuid).first() if (run and run.job_uuid) else None
        result.append({
            "task_uuid": task.uuid,
            "job_uuid": job.uuid if job else None,
            "job_status": job.status if job else None,
            "job_label": job.label if job else None,
            "done": job.done if job else 0,
            "total": job.total if job else 0,
        })
    return result


# ─── Canvas view — free-form node positions + drag-to-connect ─────────────────

def set_task_position(schedule_uuid, x, y):
    """Persist where this task's node sits on the workflow's Canvas view.
    No validation beyond existence — position is purely cosmetic, never
    read by the scheduler engine."""
    schedule = AdminTaskSchedule.query.filter_by(uuid=schedule_uuid).first()
    if not schedule:
        return None, "Task not found."
    schedule.position_x = float(x)
    schedule.position_y = float(y)
    db.session.commit()
    return schedule, None


def set_task_dependency(schedule_uuid, depends_on_schedule_id, depends_on_condition):
    """Surgical version of update_schedule() that only ever touches the
    trigger — used by the Canvas view's drag-to-connect: dragging from one
    node to another must not silently reset the target's title, task_type,
    target_payload, etc. the way re-submitting the full edit form would if
    those fields weren't carried along. Reuses the exact same validation
    (cycle guard, same-workflow check) as the modal-based flow."""
    schedule = AdminTaskSchedule.query.filter_by(uuid=schedule_uuid).first()
    if not schedule:
        return None, "Task not found."

    data = {
        'trigger_mode': 'after_task',
        'depends_on_schedule_id': depends_on_schedule_id,
        'depends_on_condition': depends_on_condition,
    }
    ok, err = _validate_trigger(data, schedule_id=schedule.id, workflow_id=schedule.workflow_id)
    if not ok:
        return None, err

    _apply_trigger_fields(schedule, data)
    db.session.commit()
    _register_live(schedule)
    return schedule, None


def clear_task_dependency(schedule_uuid):
    """Remove an existing dependency (Canvas view: click an edge, choose
    'Remove connection'). A task can't be left with no trigger at all, so it
    falls back to a safe, inert default — daily at 03:00, paused — rather
    than guessing a schedule the admin never asked for; they re-enable it
    with a real cadence via Edit once they've decided what it should be."""
    schedule = AdminTaskSchedule.query.filter_by(uuid=schedule_uuid).first()
    if not schedule:
        return None, "Task not found."
    if schedule.trigger_mode != 'after_task':
        return None, "This task has no dependency to remove."

    data = {'trigger_mode': 'daily', 'hour': 3, 'minute': 0, 'timezone': schedule.timezone or 'UTC'}
    _apply_trigger_fields(schedule, data)
    schedule.is_active = False
    db.session.commit()
    _register_live(schedule)
    return schedule, None
