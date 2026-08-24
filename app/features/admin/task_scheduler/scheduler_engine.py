"""
scheduler_engine.py — the "when" half of the generalized Admin Task
Scheduler (see docs/design/admin_task_scheduler.md). Modeled directly on
app/features/rule/rule_from_github/sync_schedule/scheduler_engine.py: the
`AdminTaskSchedule` rows in Postgres are the single source of truth,
APScheduler only holds live triggers in memory, and firing a trigger does
the minimum possible work synchronously (create one AdminTaskRun + one
BackgroundJob row and commit) — job_worker.py's poll loop does the actual
work. Runs its own independent BackgroundScheduler instance rather than
sharing the GitHub Sync one, per the "coexistence" decision in §8 of the
design doc: the two systems stay fully independent for now.
"""
import datetime
import uuid as _uuid_mod

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger

_scheduler = None


def build_trigger(schedule):
    """schedule: an AdminTaskSchedule row. Returns an APScheduler trigger, or
    None for 'after_task' (fired by chaining, not by the scheduler)."""
    tz = schedule.timezone or "UTC"
    mode = schedule.trigger_mode
    if mode == 'once':
        return DateTrigger(run_date=schedule.run_once_at, timezone=tz)
    if mode == 'after_task':
        return None
    if mode == 'daily':
        return CronTrigger(hour=schedule.hour, minute=schedule.minute, timezone=tz)
    if mode == 'weekly':
        dow = schedule.days_of_week_list() or [0]
        return CronTrigger(day_of_week=','.join(str(d) for d in dow),
                            hour=schedule.hour, minute=schedule.minute, timezone=tz)
    if mode == 'monthly':
        day = schedule.day_of_month or 1
        return CronTrigger(day=('last' if day == -1 else day),
                            hour=schedule.hour, minute=schedule.minute, timezone=tz)
    if mode == 'cron':
        return CronTrigger.from_crontab(schedule.cron_expr, timezone=tz)
    raise ValueError(f"Unknown trigger_mode: {mode}")


def get_scheduler():
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(daemon=True)
        _scheduler.start()
    return _scheduler


def _creates_cycle(schedule_id, depends_on_schedule_id):
    """Walk the depends_on chain starting at depends_on_schedule_id — if we
    ever reach schedule_id, adding this edge would create a cycle. schedule_id
    may be None for a brand-new schedule (nothing to walk into yet)."""
    from app.core.db_class.db import AdminTaskSchedule

    seen = set()
    current_id = depends_on_schedule_id
    while current_id is not None:
        if current_id == schedule_id:
            return True
        if current_id in seen:
            return False  # pre-existing cycle elsewhere — not this call's problem
        seen.add(current_id)
        parent = AdminTaskSchedule.query.get(current_id)
        if not parent:
            return False
        current_id = parent.depends_on_schedule_id
    return False


def _fire_schedule(app, schedule_uuid):
    """Runs in the APScheduler thread (or synchronously for a manual
    run_now/chained fire). Only ever creates an AdminTaskRun + BackgroundJob
    row — the real work happens later on job_worker's thread."""
    from app import db
    from app.core.db_class.db import AdminTaskSchedule, AdminTaskRun
    from app.features.jobs.jobs_core import create_job
    from app.features.admin.task_scheduler.task_types import TASK_TYPES

    with app.app_context():
        try:
            schedule = AdminTaskSchedule.query.filter_by(uuid=schedule_uuid, is_active=True).first()
            if not schedule:
                return

            task_def = TASK_TYPES.get(schedule.task_type)
            if not task_def:
                print(f"[task_scheduler] Unknown task_type '{schedule.task_type}' for schedule {schedule_uuid} — skipping.")
                return

            run = AdminTaskRun(uuid=str(_uuid_mod.uuid4()), schedule_id=schedule.id, status='pending')
            db.session.add(run)
            db.session.flush()

            job = create_job(
                job_type=task_def['job_type'],
                payload=schedule.target_payload or {},
                label=f"{schedule.title} — {task_def['label']}",
                created_by=schedule.editor_id,
            )
            if job is None:
                db.session.rollback()
                return

            run.job_uuid = job.uuid
            schedule.last_run_at = datetime.datetime.utcnow()
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"[task_scheduler] _fire_schedule error for {schedule_uuid}: {e}")


def register_schedule(app, schedule):
    """(Re)register one schedule's trigger with the live scheduler and store
    its computed next_run_at for display. Call at boot for every active
    schedule, and again on create/update/toggle from the CRUD routes."""
    if not schedule.is_active or schedule.trigger_mode == 'after_task':
        unregister_schedule(schedule.uuid)
        schedule.next_run_at = None
        return

    scheduler = get_scheduler()
    trigger = build_trigger(schedule)
    scheduler.add_job(
        _fire_schedule,
        trigger=trigger,
        args=[app, schedule.uuid],
        id=schedule.uuid,
        replace_existing=True,
        misfire_grace_time=3600,
    )
    job = scheduler.get_job(schedule.uuid)
    if job and job.next_run_time:
        schedule.next_run_at = job.next_run_time.astimezone(datetime.timezone.utc).replace(tzinfo=None)


def unregister_schedule(schedule_uuid):
    scheduler = get_scheduler()
    try:
        scheduler.remove_job(schedule_uuid)
    except Exception:
        pass  # job was never registered (e.g. schedule is 'after_task' or was inactive) — fine


def start_scheduler(app):
    """Boot-time loader — call once from create_app(), alongside the GitHub
    Sync Schedule's own start_scheduler() and start_worker. Rebuilds the
    exact trigger set from the DB."""
    from app import db
    from app.core.db_class.db import AdminTaskSchedule

    with app.app_context():
        try:
            schedules = AdminTaskSchedule.query.filter_by(is_active=True).all()
        except Exception:
            # Table doesn't exist yet — a brand-new install/test DB before
            # `flask db upgrade` / db.create_all() has run.
            return
        for schedule in schedules:
            try:
                register_schedule(app, schedule)
            except Exception as e:
                print(f"[task_scheduler] failed to register schedule {schedule.uuid}: {e}")
        db.session.commit()


def on_job_finished(job):
    """Called from job_worker.py right after a job's status is finalized to
    'done' or 'failed'. Phase 1: single-parent chaining only — walks the one
    depends_on_schedule_id/depends_on_condition pair. Multi-parent AND/OR
    (AdminTaskDependency) is a Phase 3 addition, see §4bis of the design doc."""
    from app import db
    from app.core.db_class.db import AdminTaskSchedule, AdminTaskRun

    run = AdminTaskRun.query.filter_by(job_uuid=job.uuid).first()
    if not run:
        return  # this job wasn't launched via an AdminTaskSchedule — nothing to do

    run.status = 'done' if job.status == 'done' else 'failed'
    run.finished_at = datetime.datetime.utcnow()
    db.session.commit()

    candidates = AdminTaskSchedule.query.filter_by(
        trigger_mode='after_task', is_active=True, depends_on_schedule_id=run.schedule_id,
    ).all()
    for candidate in candidates:
        condition = candidate.depends_on_condition
        condition_met = (
            condition == 'always' or
            (condition == 'success' and run.status == 'done') or
            (condition == 'failure' and run.status == 'failed')
        )
        if condition_met:
            from flask import current_app
            _fire_schedule(current_app._get_current_object(), candidate.uuid)
