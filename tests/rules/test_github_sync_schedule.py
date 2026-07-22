"""
Tests for the recurring GitHub Sync Schedule feature (PLAN_MANAGE_GITHUB_SYNC.md):
- CRUD permissions (admin-only, enforced server-side)
- Recurrence validation
- True bulk delete
- Scheduler engine restart-safety (DB is the source of truth, not APScheduler's
  own in-memory job store)
- The execution handler never auto-accepts an invalid-syntax update, even
  when auto_accept_update is enabled
- Notification preference is respected
"""
import datetime
import uuid

import pytest

from app import db
from app.core.db_class.db import (
    User, Rule, GithubSyncSchedule, GithubSyncScheduleRepo, GithubSyncRun,
    GithubSyncRunRepo, BackgroundJob, RuleStatus, UpdateResult, RuleUpdateHistory, Notification,
    NotificationPreference,
)
from app.features.rule.rule_from_github.sync_schedule import sync_schedule_core as SyncScheduleModel
from app.features.rule.rule_from_github.sync_schedule import scheduler_engine


def _login(client, email):
    user = User.query.filter_by(email=email).first()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True
    return user


def _admin(client):
    return _login(client, "admin@admin.admin")


def _plain_user(client):
    return _login(client, "t@t.t")


# ─────────────────────────────────────────────────────────────────────────────
#  CRUD permissions
# ─────────────────────────────────────────────────────────────────────────────

def test_non_admin_cannot_list_or_create(client, app):
    with app.app_context():
        _plain_user(client)

    res = client.get("/rule/github/schedule/list")
    assert res.status_code == 403

    res = client.post("/rule/github/schedule/create", json={"title": "x", "frequency": "daily"})
    assert res.status_code == 403


def test_admin_full_crud_cycle(client, app):
    with app.app_context():
        _admin(client)

    payload = {
        "title": "Nightly sync",
        "description": "test schedule",
        "is_active": True,
        "frequency": "daily",
        "hour": 3,
        "minute": 30,
        "timezone": "UTC",
        "repo_mode": "partial",
        "selected_repo_urls": ["https://github.com/rulezet/rulezet-sample-rules"],
        "repo_settings": [{
            "repo_url": "https://github.com/rulezet/rulezet-sample-rules",
            "auto_accept_update": True,
            "auto_add_new_rule": False,
        }],
    }
    res = client.post("/rule/github/schedule/create", json=payload)
    assert res.status_code == 201, res.get_json()
    sched = res.get_json()["schedule"]
    assert sched["repo_count"] == 1
    assert sched["frequency"] == "daily"
    assert sched["next_run_at"] is not None  # scheduler computed + persisted a real next run

    sched_uuid = sched["uuid"]

    res = client.get("/rule/github/schedule/list")
    assert res.status_code == 200
    assert res.get_json()["total"] == 1

    res = client.post(f"/rule/github/schedule/{sched_uuid}/update", json={**payload, "title": "Renamed"})
    assert res.status_code == 200
    assert res.get_json()["schedule"]["title"] == "Renamed"

    res = client.post(f"/rule/github/schedule/{sched_uuid}/delete")
    assert res.status_code == 200

    with app.app_context():
        assert GithubSyncSchedule.query.filter_by(uuid=sched_uuid).first() is None


def test_create_requires_at_least_one_valid_repo(client, app):
    with app.app_context():
        _admin(client)

    res = client.post("/rule/github/schedule/create", json={
        "title": "No repos", "frequency": "daily", "hour": 3, "minute": 0,
        "repo_mode": "partial", "selected_repo_urls": [],
    })
    assert res.status_code == 400
    assert "repository" in res.get_json()["message"].lower()


# ─────────────────────────────────────────────────────────────────────────────
#  Recurrence validation
# ─────────────────────────────────────────────────────────────────────────────

def test_weekly_requires_days_of_week(app):
    with app.app_context():
        ok, err = SyncScheduleModel._validate_recurrence({
            "frequency": "weekly", "days_of_week": [], "hour": 3, "minute": 0,
        })
        assert not ok
        assert "days_of_week" in err


def test_monthly_last_day_is_valid(app):
    with app.app_context():
        ok, err = SyncScheduleModel._validate_recurrence({
            "frequency": "monthly", "day_of_month": -1, "hour": 3, "minute": 0,
        })
        assert ok, err


def test_cron_frequency_rejects_bad_expression(app):
    with app.app_context():
        ok, err = SyncScheduleModel._validate_recurrence({
            "frequency": "cron", "cron_expr": "not a cron expression!!", "hour": 3, "minute": 0,
        })
        assert not ok
        assert "cron" in err.lower()


def test_cron_frequency_accepts_valid_expression(app):
    with app.app_context():
        ok, err = SyncScheduleModel._validate_recurrence({
            "frequency": "cron", "cron_expr": "0 3 * * 1", "hour": 3, "minute": 0,
        })
        assert ok, err


# ─────────────────────────────────────────────────────────────────────────────
#  Bulk delete — true "select all matching filter, minus excluded"
# ─────────────────────────────────────────────────────────────────────────────

def test_bulk_delete_partial_mode(client, app):
    with app.app_context():
        admin = _admin(client)
        uuids = []
        for i in range(3):
            sched = GithubSyncSchedule(
                uuid=str(uuid.uuid4()), title=f"Sched {i}", editor_id=admin.id,
                frequency="daily", hour=3, minute=0, timezone="UTC", is_active=False,
            )
            db.session.add(sched)
            db.session.commit()
            uuids.append(sched.uuid)

    res = client.post("/rule/github/schedule/bulk_delete", json={
        "mode": "partial", "selected_uuids": uuids[:2],
    })
    assert res.status_code == 200
    assert res.get_json()["count"] == 2

    with app.app_context():
        assert GithubSyncSchedule.query.count() == 1


def test_bulk_delete_all_mode_minus_excluded(client, app):
    with app.app_context():
        admin = _admin(client)
        uuids = []
        for i in range(3):
            sched = GithubSyncSchedule(
                uuid=str(uuid.uuid4()), title=f"BulkAll {i}", editor_id=admin.id,
                frequency="daily", hour=3, minute=0, timezone="UTC", is_active=False,
            )
            db.session.add(sched)
            db.session.commit()
            uuids.append(sched.uuid)

    res = client.post("/rule/github/schedule/bulk_delete", json={
        "mode": "all", "filters": {"search": "BulkAll"}, "excluded_uuids": [uuids[0]],
    })
    assert res.status_code == 200
    assert res.get_json()["count"] == 2

    with app.app_context():
        remaining = GithubSyncSchedule.query.filter(GithubSyncSchedule.uuid.in_(uuids)).all()
        assert len(remaining) == 1
        assert remaining[0].uuid == uuids[0]


# ─────────────────────────────────────────────────────────────────────────────
#  Scheduler restart-safety
# ─────────────────────────────────────────────────────────────────────────────

def test_scheduler_survives_repeated_boot(app):
    """Simulates two process boots against the same DB: the registered
    trigger set must match the active schedules exactly both times — no
    duplicates, no drops. This is the guarantee that a server restart never
    loses or duplicates a Sync Schedule."""
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        active_uuids = set()
        for i in range(3):
            sched = GithubSyncSchedule(
                uuid=str(uuid.uuid4()), title=f"Boot {i}", editor_id=admin.id,
                frequency="daily", hour=3, minute=0, timezone="UTC", is_active=True,
            )
            db.session.add(sched)
            db.session.commit()
            active_uuids.add(sched.uuid)
        inactive = GithubSyncSchedule(
            uuid=str(uuid.uuid4()), title="Paused", editor_id=admin.id,
            frequency="daily", hour=3, minute=0, timezone="UTC", is_active=False,
        )
        db.session.add(inactive)
        db.session.commit()

        scheduler_engine._scheduler = None  # force a fresh scheduler, like a real restart would

        scheduler_engine.start_scheduler(app)
        job_ids_first_boot = {j.id for j in scheduler_engine.get_scheduler().get_jobs()}
        assert job_ids_first_boot == active_uuids
        assert inactive.uuid not in job_ids_first_boot

        # "Restart" — rebuild from the DB again against the SAME scheduler,
        # exactly like start_scheduler would be called again on a real reboot.
        scheduler_engine.start_scheduler(app)
        job_ids_second_boot = {j.id for j in scheduler_engine.get_scheduler().get_jobs()}
        assert job_ids_second_boot == active_uuids  # no duplicates, no drops


# ─────────────────────────────────────────────────────────────────────────────
#  Execution handler — never auto-accept invalid syntax
# ─────────────────────────────────────────────────────────────────────────────

class _FakeSaveDone:
    def wait(self, timeout=None):
        return True


class _FakeUpdateSession:
    """Stands in for Update_class: .start() is a no-op, uuid is pre-baked to
    point at an UpdateResult the test has already seeded, so the handler
    exercises its real accept/add logic against real DB rows."""
    def __init__(self, uuid_):
        self.uuid = uuid_
        self._save_done = _FakeSaveDone()

    def start(self):
        pass


def test_auto_accept_never_accepts_invalid_syntax(app, monkeypatch):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()

        result = UpdateResult(
            uuid=str(uuid.uuid4()), user_id=str(admin.id), mode="by_url",
            info='{"repo_url": "https://github.com/rulezet/rulezet-sample-rules"}',
            repo_sources='["https://github.com/rulezet/rulezet-sample-rules"]',
            found=2, updated=0, not_found=0, skipped=0, total=2,
            query_date=datetime.datetime.utcnow(),
        )
        db.session.add(result)
        db.session.commit()

        good_rule = Rule(uuid=str(uuid.uuid4()), format="yara", title="good", source="test",
                          user_id=admin.id, version=1, vote_up=0, vote_down=0,
                          to_string="rule good {}", is_deleted=False)
        bad_rule = Rule(uuid=str(uuid.uuid4()), format="yara", title="bad", source="test",
                         user_id=admin.id, version=1, vote_up=0, vote_down=0,
                         to_string="rule bad {}", is_deleted=False)
        db.session.add_all([good_rule, bad_rule])
        db.session.commit()

        # accept_all_update looks up a RuleUpdateHistory row via each
        # RuleStatus.history_id and aborts the WHOLE batch (leaving later
        # rows completely untouched) if that lookup misses — exactly what a
        # real update scan always creates alongside a RuleStatus, so both
        # rows need one here too or this test would only be exercising that
        # abort path instead of the real accept/reject-on-syntax behavior.
        good_history = RuleUpdateHistory(rule_id=good_rule.id, rule_title="good", success=True,
                                          analyzed_by_user_id=admin.id, analyzed_at=datetime.datetime.utcnow())
        bad_history = RuleUpdateHistory(rule_id=bad_rule.id, rule_title="bad", success=True,
                                         analyzed_by_user_id=admin.id, analyzed_at=datetime.datetime.utcnow())
        db.session.add_all([good_history, bad_history])
        db.session.commit()

        good_status = RuleStatus(uuid=str(uuid.uuid4()), update_result_id=result.id,
                                  name_rule="good", rule_id=str(good_rule.id), history_id=str(good_history.id),
                                  found=True, update_available=True, rule_syntax_valid=True,
                                  date=datetime.datetime.utcnow())
        bad_status = RuleStatus(uuid=str(uuid.uuid4()), update_result_id=result.id,
                                 name_rule="bad", rule_id=str(bad_rule.id), history_id=str(bad_history.id),
                                 found=True, update_available=True, rule_syntax_valid=False,
                                 date=datetime.datetime.utcnow())
        db.session.add_all([good_status, bad_status])
        db.session.commit()

        schedule = GithubSyncSchedule(
            uuid=str(uuid.uuid4()), title="Auto-accept test", editor_id=admin.id,
            frequency="daily", hour=3, minute=0, timezone="UTC", is_active=True,
        )
        db.session.add(schedule)
        db.session.flush()
        repo_cfg = GithubSyncScheduleRepo(
            schedule_id=schedule.id, repo_url="https://github.com/rulezet/rulezet-sample-rules",
            auto_accept_update=True, auto_add_new_rule=False,
        )
        db.session.add(repo_cfg)
        db.session.commit()

        run = GithubSyncRun(uuid=str(uuid.uuid4()), schedule_id=schedule.id, status="pending")
        db.session.add(run)
        db.session.commit()

        job = BackgroundJob(uuid=str(uuid.uuid4()), created_by=admin.id, job_type="github_sync_schedule_run",
                             status="running", total=1, done=0,
                             payload={"schedule_uuid": schedule.uuid, "run_uuid": run.uuid})
        db.session.add(job)
        db.session.commit()

        fake_session = _FakeUpdateSession(result.uuid)
        monkeypatch.setattr(
            "app.features.rule.rule_from_github.update_rule.update_class.Update_class",
            lambda *a, **kw: fake_session
        )
        monkeypatch.setattr(
            "app.features.rule.rule_from_github.update_rule.update_class.sessions", []
        )

        from app.features.jobs.job_handlers import handle_github_sync_schedule_run
        handle_github_sync_schedule_run(job, app)

        db.session.refresh(good_status)
        db.session.refresh(bad_status)

        # The valid-syntax update was really auto-accepted...
        assert good_status.update_available is False
        assert good_status.message == "Updated successfully"
        # ...but the invalid-syntax one was force-rejected, never accepted,
        # by accept_all_update's own per-row syntax gate — this is the
        # guarantee the whole feature was built around.
        assert bad_status.update_available is False
        assert "Rejected" in bad_status.message and "Invalide syntax" in bad_status.message

        run_repo = GithubSyncRunRepo.query.filter_by(run_id=run.id).first()
        assert run_repo.status == "done"
        assert run_repo.auto_accepted == 1
        assert run_repo.auto_rejected == 1


# ─────────────────────────────────────────────────────────────────────────────
#  Notification preference respected
# ─────────────────────────────────────────────────────────────────────────────

def test_sync_run_notification_respects_preference(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        pref = NotificationPreference.query.filter_by(user_id=admin.id).first()
        if not pref:
            pref = NotificationPreference(user_id=admin.id)
            db.session.add(pref)
        pref.pref_sync_run_finished = False
        db.session.commit()

        schedule = GithubSyncSchedule(
            uuid=str(uuid.uuid4()), title="Notif test", editor_id=admin.id,
            frequency="daily", hour=3, minute=0, timezone="UTC", is_active=True,
        )
        db.session.add(schedule)
        db.session.flush()
        run = GithubSyncRun(uuid=str(uuid.uuid4()), schedule_id=schedule.id, status="done")
        db.session.add(run)
        db.session.commit()

        before = Notification.query.filter_by(notif_type="sync_run_finished").count()

        from app.features.notification.notification_core import notify_admins_sync_run_finished
        notify_admins_sync_run_finished(run)

        after = Notification.query.filter_by(notif_type="sync_run_finished").count()
        assert after == before  # opted out — no notification created

        pref.pref_sync_run_finished = True
        db.session.commit()
        notify_admins_sync_run_finished(run)
        after_opt_in = Notification.query.filter_by(notif_type="sync_run_finished").count()
        assert after_opt_in == before + 1
