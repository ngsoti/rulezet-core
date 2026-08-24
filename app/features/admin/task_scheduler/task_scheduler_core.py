"""
task_scheduler_core.py — CRUD + validation for AdminTaskSchedule (the
generalized Admin Task Scheduler). Modeled directly on
sync_schedule_core.py: keeps the live APScheduler trigger in lockstep with
the DB row on every mutation so a restart is never needed to pick up a
change. See docs/design/admin_task_scheduler.md for the full design.
"""
import datetime
import uuid as _uuid_mod

from flask import current_app

from app import db
from app.core.db_class.db import AdminTaskSchedule
from app.features.admin.task_scheduler.task_types import TASK_TYPES
from app.features.admin.task_scheduler.scheduler_engine import _creates_cycle

VALID_TRIGGER_MODES = ('once', 'daily', 'weekly', 'monthly', 'cron', 'after_task')


def _validate_trigger(data, schedule_id=None):
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
        if not AdminTaskSchedule.query.get(depends_on_id):
            return False, "The parent task to depend on was not found."
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


def get_schedule_list_page(page=1, per_page=20, search='', sort='created_at', direction='desc', task_type=None):
    per_page = max(1, min(per_page or 20, 100))
    query = AdminTaskSchedule.query
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
    task_type = data.get('task_type')
    if task_type not in TASK_TYPES:
        return None, f"Unknown task_type: {task_type!r}"

    ok, err = _validate_trigger(data)
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

    ok, err = _validate_trigger(data, schedule_id=schedule.id)
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


def _resolve_bulk_targets(mode, filters, selected_uuids, excluded_uuids):
    filters = filters or {}
    query = AdminTaskSchedule.query
    if filters.get('search'):
        query = query.filter(AdminTaskSchedule.title.ilike(f"%{filters['search']}%"))

    if mode == 'all':
        excluded = set(excluded_uuids or [])
        return [s for s in query.all() if s.uuid not in excluded]
    return AdminTaskSchedule.query.filter(AdminTaskSchedule.uuid.in_(selected_uuids or [])).all()


def bulk_delete_schedules(mode, filters, selected_uuids, excluded_uuids):
    from app.features.admin.task_scheduler.scheduler_engine import unregister_schedule
    targets = _resolve_bulk_targets(mode, filters, selected_uuids, excluded_uuids)

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


def bulk_set_active_schedules(mode, filters, selected_uuids, excluded_uuids, is_active):
    targets = _resolve_bulk_targets(mode, filters, selected_uuids, excluded_uuids)

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
    calls, so a manual run creates an identical AdminTaskRun + BackgroundJob."""
    from app.features.admin.task_scheduler.scheduler_engine import _fire_schedule
    schedule = AdminTaskSchedule.query.filter_by(uuid=schedule_uuid).first()
    if not schedule:
        return False, "Schedule not found."
    if not schedule.is_active:
        return False, "Task is paused — activate it before running it manually."
    _fire_schedule(current_app._get_current_object(), schedule.uuid)
    return True, None
