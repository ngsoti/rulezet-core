"""
job_worker.py
Background thread that picks up pending jobs and executes them.

Start once at app startup:
    from app.features.jobs.job_worker import start_worker
    start_worker(app)
"""

import threading
import time
import datetime

_HANDLERS = {}


def register_handler(job_type):
    """Decorator to register a job handler function."""
    def decorator(fn):
        _HANDLERS[job_type] = fn
        return fn
    return decorator


def _log(job, db, BackgroundJobLog, message, level='info', event=None):
    """Write a system-level log line from the worker."""
    try:
        db.session.add(BackgroundJobLog(
            job_id=job.id,
            level=level,
            event=event,
            message=message,
            created_at=datetime.datetime.now(datetime.timezone.utc),
        ))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[worker] failed to write log: {e}")


def _worker_loop(app):
    """Runs in a background daemon thread. Picks one pending job at a time."""
    with app.app_context():
        from app import db
        from app.core.db_class.db import BackgroundJob, BackgroundJobLog

        # ── Recover jobs interrupted by a server restart ──────────────────────
        interrupted = BackgroundJob.query.filter_by(status='running').all()
        if interrupted:
            for job in interrupted:
                job.status     = 'pending'
                job.started_at = None
                _log(job, db, BackgroundJobLog,
                     "Server was restarted while this job was running — "
                     "automatically queued to resume from last saved offset.",
                     level='warning', event='recovered')
            db.session.commit()
            print(f"[worker] Recovered {len(interrupted)} interrupted job(s) → pending.")

        while True:
            try:
                db.session.expire_all()

                job = (
                    BackgroundJob.query
                    .filter(BackgroundJob.status.in_(['pending']))
                    .order_by(BackgroundJob.created_at.asc())
                    .first()
                )

                if job is None:
                    time.sleep(2)
                    continue

                handler = _HANDLERS.get(job.job_type)
                if handler is None:
                    # Put back to pending so it's retried after a server restart
                    # that loads the missing handler.
                    job.status = 'pending'
                    _log(job, db, BackgroundJobLog,
                         f"No handler for type '{job.job_type}' — requeueing (restart may be needed).",
                         level='warning', event='requeued')
                    db.session.commit()
                    time.sleep(5)
                    continue

                job.status     = 'running'
                job.started_at = datetime.datetime.now(datetime.timezone.utc)
                db.session.commit()

                _log(job, db, BackgroundJobLog,
                     f"Worker picked up job — starting execution.",
                     level='info', event='picked_up')

                print(f"[worker] Starting job {job.uuid} type={job.job_type} done={job.done}")

                try:
                    job_uuid = job.uuid  # save uuid before handler runs
                    handler(job, app)

                    # reload from DB by uuid — the handler may have spawned its own
                    # app_context (e.g. delete_github_rules) which closes its session,
                    # leaving the worker's object stale/detached
                    db.session.expire_all()
                    job = BackgroundJob.query.filter_by(uuid=job_uuid).first()
                    if not job:
                        print(f"[worker] Job {job_uuid} disappeared after handler.")
                        continue

                    if job.status not in ('cancelled', 'failed', 'paused'):
                        job.status      = 'done'
                        job.finished_at = datetime.datetime.now(datetime.timezone.utc)
                        if job.payload and '_resume_offset' in job.payload:
                            payload = dict(job.payload)
                            del payload['_resume_offset']
                            job.payload = payload
                        db.session.commit()

                    print(f"[worker] Job {job.uuid} finished with status={job.status}")

                    if job.status in ('done', 'failed'):
                        try:
                            from app.features.admin.task_scheduler.scheduler_engine import on_job_finished
                            on_job_finished(job)
                        except Exception as e:
                            print(f"[task_scheduler] on_job_finished error: {e}")

                    # Update notification so bell shows final state
                    try:
                        from app.features.notification.notification_core import update_job_notification
                        update_job_notification(job)
                    except Exception:
                        pass

                except Exception as e:
                    db.session.rollback()
                    try:
                        job = BackgroundJob.query.filter_by(uuid=job_uuid).first()
                        if job:
                            job.status      = 'failed'
                            job.error       = str(e)
                            job.finished_at = datetime.datetime.now(datetime.timezone.utc)
                            db.session.commit()
                            _log(job, db, BackgroundJobLog,
                                 f"Unexpected error: {str(e)}",
                                 level='error', event='failed')
                            try:
                                from app.features.notification.notification_core import update_job_notification
                                update_job_notification(job)
                            except Exception:
                                pass
                            try:
                                from app.features.admin.task_scheduler.scheduler_engine import on_job_finished
                                on_job_finished(job)
                            except Exception as hook_err:
                                print(f"[task_scheduler] on_job_finished error: {hook_err}")
                    except Exception:
                        pass
                    print(f"[worker] Job {job_uuid} failed: {e}")

            except Exception as e:
                print(f"[worker] Unexpected error in worker loop: {e}")
                try:
                    db.session.rollback()
                except Exception:
                    pass
                time.sleep(5)


def start_worker(app):
    """Start the background worker thread. Call once at app startup."""
    t = threading.Thread(
        target=_worker_loop,
        args=(app,),
        daemon=True,
        name='job-worker'
    )
    t.start()
    print("[worker] Background job worker started.")
    return t