"""
scheduler_engine.py — the "when" half of recurring GitHub Sync Schedules.

The `GithubSyncSchedule` rows in Postgres are the single source of truth —
exactly like `BackgroundJob` rows already are for one-shot jobs. APScheduler
only holds live `CronTrigger`s in an in-memory job store; nothing it knows is
trusted to survive on its own. At boot, `start_scheduler()` rebuilds the exact
same trigger set from the DB, so a restart never loses or duplicates a
schedule. Whenever a schedule is created/updated/toggled/deleted through the
CRUD routes, call `register_schedule()`/`unregister_schedule()` again so the
in-memory trigger set stays in sync without needing a restart.

Firing a trigger does the minimum possible work synchronously: create one
`GithubSyncRun` + one `BackgroundJob` row and commit. The existing
`job_worker.py` poll loop picks it up like any other job — this keeps the
APScheduler thread itself tiny and crash-resistant.
"""
import datetime
import uuid as _uuid_mod

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

_scheduler = None


def build_trigger(schedule):
    """schedule: a GithubSyncSchedule row. Returns an APScheduler CronTrigger."""
    tz = schedule.timezone or "UTC"
    if schedule.frequency == 'daily':
        return CronTrigger(hour=schedule.hour, minute=schedule.minute, timezone=tz)
    if schedule.frequency == 'weekly':
        dow = schedule.days_of_week_list() or [0]
        return CronTrigger(day_of_week=','.join(str(d) for d in dow),
                            hour=schedule.hour, minute=schedule.minute, timezone=tz)
    if schedule.frequency == 'monthly':
        day = schedule.day_of_month or 1
        return CronTrigger(day=('last' if day == -1 else day),
                            hour=schedule.hour, minute=schedule.minute, timezone=tz)
    if schedule.frequency == 'cron':
        return CronTrigger.from_crontab(schedule.cron_expr, timezone=tz)
    raise ValueError(f"Unknown schedule frequency: {schedule.frequency}")


def get_scheduler():
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(daemon=True)
        _scheduler.start()
    return _scheduler


def _fire_schedule(app, schedule_uuid):
    """Runs in the APScheduler thread. Only ever creates a GithubSyncRun +
    BackgroundJob row — the real work happens later on job_worker's thread."""
    from app import db
    from app.core.db_class.db import GithubSyncSchedule, GithubSyncRun
    from app.features.jobs.jobs_core import create_job

    with app.app_context():
        try:
            schedule = GithubSyncSchedule.query.filter_by(uuid=schedule_uuid, is_active=True).first()
            if not schedule or not schedule.repos:
                return

            run = GithubSyncRun(uuid=str(_uuid_mod.uuid4()), schedule_id=schedule.id, status='pending')
            db.session.add(run)
            db.session.flush()

            job = create_job(
                job_type='github_sync_schedule_run',
                payload={"schedule_uuid": schedule.uuid, "run_uuid": run.uuid},
                label=f'Sync Schedule — {schedule.title}',
                created_by=schedule.editor_id,
                total=len(schedule.repos),
            )
            if job is None:
                db.session.rollback()
                return

            run.job_uuid = job.uuid
            schedule.last_run_at = datetime.datetime.utcnow()
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"[sync_schedule] _fire_schedule error for {schedule_uuid}: {e}")


def register_schedule(app, schedule):
    """(Re)register one schedule's trigger with the live scheduler and store
    its computed next_run_at for display. Call at boot for every active
    schedule, and again on create/update/toggle from the CRUD routes."""
    if not schedule.is_active:
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
        pass  # job was never registered (e.g. schedule was already inactive) — fine


def start_scheduler(app):
    """Boot-time loader — call once from create_app(), alongside start_worker
    and _start_telemetry. Rebuilds the exact trigger set from the DB."""
    from app import db
    from app.core.db_class.db import GithubSyncSchedule

    with app.app_context():
        try:
            schedules = GithubSyncSchedule.query.filter_by(is_active=True).all()
        except Exception:
            # Table doesn't exist yet — a brand-new install/test DB before
            # `flask db upgrade` / db.create_all() has run. Same defensive
            # pattern as seed_official_connector()/seed_default_themes()
            # just above in create_app(): nothing to register yet, and the
            # app must still boot cleanly either way.
            return
        for schedule in schedules:
            try:
                register_schedule(app, schedule)
            except Exception as e:
                print(f"[sync_schedule] failed to register schedule {schedule.uuid}: {e}")
        db.session.commit()
