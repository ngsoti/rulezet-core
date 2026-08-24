"""
Tests for the generalized Admin Task Scheduler (docs/design/admin_task_scheduler.md),
Phase 1: workflows (the container an admin creates first), registry, task
CRUD scoped to a workflow, run_now, single-parent dependency chaining within
a workflow, and the cycle guard.
"""
import datetime

import pytest

from app import db
from app.core.db_class.db import User, AdminWorkflow, AdminTaskSchedule, AdminTaskRun, BackgroundJob
from app.features.admin.task_scheduler import task_scheduler_core as TaskSchedulerModel
from app.features.admin.task_scheduler import scheduler_engine
from app.features.admin.task_scheduler.task_types import TASK_TYPES
from app.features.jobs.job_worker import _HANDLERS
import app.features.jobs.job_handlers  # noqa: ensures @register_handler side effects ran


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


def _make_workflow(admin, title="Test workflow"):
    workflow, err = TaskSchedulerModel.create_workflow({"title": title}, admin)
    assert err is None
    return workflow


# ─────────────────────────────────────────────────────────────────────────────
#  Registry sanity
# ─────────────────────────────────────────────────────────────────────────────

def test_every_registered_task_type_points_at_a_real_handler():
    for key, task_def in TASK_TYPES.items():
        assert task_def['job_type'] in _HANDLERS, (
            f"task type '{key}' references job_type '{task_def['job_type']}' "
            f"which has no @register_handler"
        )


def test_admin_panel_renders(client, app):
    with app.app_context():
        _admin(client)
    res = client.get("/admin/tasks/")
    assert res.status_code == 200


def test_admin_panel_workflow_renders_for_existing_workflow(client, app):
    with app.app_context():
        admin = _admin(client)
        workflow_uuid = _make_workflow(admin).uuid
    res = client.get(f"/admin/tasks/{workflow_uuid}")
    assert res.status_code == 200


def test_admin_panel_workflow_404s_for_unknown_uuid(client, app):
    with app.app_context():
        _admin(client)
    res = client.get("/admin/tasks/00000000-0000-0000-0000-000000000000")
    assert res.status_code == 404


def test_legacy_query_param_redirects_to_path_based_url(client, app):
    with app.app_context():
        admin = _admin(client)
        workflow_uuid = _make_workflow(admin).uuid
    res = client.get(f"/admin/tasks/?workflow={workflow_uuid}")
    assert res.status_code == 302
    assert res.headers["Location"].endswith(f"/admin/tasks/{workflow_uuid}")


def test_config_endpoint_reports_mail_status(client, app):
    with app.app_context():
        _admin(client)
    res = client.get("/admin/tasks/config")
    assert res.status_code == 200
    assert "mail_configured" in res.get_json()


# ─────────────────────────────────────────────────────────────────────────────
#  Workflow CRUD permissions
# ─────────────────────────────────────────────────────────────────────────────

def test_non_admin_cannot_list_or_create(client, app):
    with app.app_context():
        _plain_user(client)

    res = client.get("/admin/tasks/workflows")
    assert res.status_code == 403

    res = client.post("/admin/tasks/workflows/create", json={"title": "x"})
    assert res.status_code == 403

    res = client.post("/admin/tasks/create", json={"title": "x", "task_type": "db_backup"})
    assert res.status_code == 403


def test_admin_workflow_crud_cycle(client, app):
    with app.app_context():
        admin = _admin(client)

        res = client.post("/admin/tasks/workflows/create", json={"title": "Nightly maintenance"})
        assert res.status_code == 201, res.get_json()
        workflow_uuid = res.get_json()["workflow"]["uuid"]

        workflow = AdminWorkflow.query.filter_by(uuid=workflow_uuid).first()
        assert workflow is not None
        assert workflow.editor_id == admin.id
        assert workflow.to_json()["task_count"] == 0

        res = client.post(f"/admin/tasks/workflows/{workflow_uuid}/update", json={"title": "Nightly maintenance (renamed)"})
        assert res.status_code == 200
        db.session.refresh(workflow)
        assert workflow.title == "Nightly maintenance (renamed)"

        res = client.post(f"/admin/tasks/workflows/{workflow_uuid}/delete")
        assert res.status_code == 200
        assert AdminWorkflow.query.filter_by(uuid=workflow_uuid).first() is None


def test_task_requires_a_valid_workflow(client, app):
    with app.app_context():
        _admin(client)

    res = client.post("/admin/tasks/create", json={
        "title": "orphan task", "task_type": "db_backup", "trigger_mode": "daily",
        "hour": 3, "minute": 0, "workflow_uuid": "does-not-exist",
    })
    assert res.status_code == 400


def test_deleting_workflow_cascades_to_its_tasks(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        schedule, err = TaskSchedulerModel.create_schedule({
            "title": "Backup", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        assert err is None

        ok = TaskSchedulerModel.delete_workflow(workflow.uuid)
        assert ok
        assert AdminTaskSchedule.query.filter_by(uuid=schedule.uuid).first() is None


# ─────────────────────────────────────────────────────────────────────────────
#  Task CRUD (scoped to a workflow)
# ─────────────────────────────────────────────────────────────────────────────

def test_admin_full_crud_cycle(client, app):
    with app.app_context():
        admin = _admin(client)
        workflow = _make_workflow(admin, "CRUD workflow")

        res = client.post("/admin/tasks/create", json={
            "title": "Nightly DB backup",
            "task_type": "db_backup",
            "target_payload": {},
            "trigger_mode": "daily",
            "hour": 3,
            "minute": 0,
            "workflow_uuid": workflow.uuid,
        })
        assert res.status_code == 201, res.get_json()
        schedule_uuid = res.get_json()["schedule"]["uuid"]

        schedule = AdminTaskSchedule.query.filter_by(uuid=schedule_uuid).first()
        assert schedule is not None
        assert schedule.task_type == "db_backup"
        assert schedule.workflow_id == workflow.id
        assert schedule.editor_id == admin.id
        assert schedule.next_run_at is not None  # scheduler computed it

        res = client.get(f"/admin/tasks/list?workflow_uuid={workflow.uuid}")
        assert res.status_code == 200
        assert res.get_json()["total"] == 1

        res = client.post(f"/admin/tasks/{schedule_uuid}/update", json={
            "title": "Nightly DB backup (renamed)",
            "task_type": "db_backup",
            "target_payload": {},
            "trigger_mode": "daily",
            "hour": 4,
            "minute": 30,
        })
        assert res.status_code == 200
        db.session.refresh(schedule)
        assert schedule.title == "Nightly DB backup (renamed)"
        assert schedule.hour == 4

        res = client.post(f"/admin/tasks/{schedule_uuid}/delete")
        assert res.status_code == 200
        assert AdminTaskSchedule.query.filter_by(uuid=schedule_uuid).first() is None


def test_create_rejects_unknown_task_type(client, app):
    with app.app_context():
        admin = _admin(client)
        workflow_uuid = _make_workflow(admin).uuid

        res = client.post("/admin/tasks/create", json={
            "title": "bogus",
            "task_type": "not_a_real_task_type",
            "trigger_mode": "daily",
            "workflow_uuid": workflow_uuid,
        })
        assert res.status_code == 400


# ─────────────────────────────────────────────────────────────────────────────
#  run_now → AdminTaskRun + BackgroundJob
# ─────────────────────────────────────────────────────────────────────────────

def test_run_now_creates_run_and_background_job(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        schedule, err = TaskSchedulerModel.create_schedule({
            "title": "Attack parser sweep",
            "task_type": "attack_parser",
            "target_payload": {"format": "sigma"},
            "trigger_mode": "once",
            "run_once_at": (datetime.datetime.utcnow() + datetime.timedelta(days=1)).isoformat(),
            "workflow_uuid": workflow.uuid,
        }, admin)
        assert err is None

        ok, err = TaskSchedulerModel.run_schedule_now(schedule.uuid)
        assert ok, err

        run = AdminTaskRun.query.filter_by(schedule_id=schedule.id).first()
        assert run is not None
        assert run.job_uuid is not None

        job = BackgroundJob.query.filter_by(uuid=run.job_uuid).first()
        assert job is not None
        assert job.job_type == "bulk_parse_attack_rules"
        assert job.payload == {"format": "sigma"}


def test_run_schedule_now_returns_the_new_jobs_uuid(app):
    """The frontend seeds its live-status display straight from this so the
    log panel jumps to the new run immediately, instead of waiting on the
    next live-status poll to discover it."""
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        schedule, err = TaskSchedulerModel.create_schedule({
            "title": "Task", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        assert err is None

        job_uuid, err = TaskSchedulerModel.run_schedule_now(schedule.uuid)
        assert err is None
        run = AdminTaskRun.query.filter_by(schedule_id=schedule.id).first()
        assert job_uuid == run.job_uuid


def test_activity_log_purge_fixed_payload_is_enforced(app):
    """The registry forces delete_all=True for a scheduled purge regardless
    of what the client sends — a client trying to sneak delete_all=False
    through must not succeed."""
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        schedule, err = TaskSchedulerModel.create_schedule({
            "title": "Purge old logs",
            "task_type": "activity_log_purge",
            "target_payload": {"delete_all": False, "action_filter": "rule."},
            "trigger_mode": "daily",
            "hour": 2, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        assert err is None
        assert schedule.target_payload["delete_all"] is True
        assert schedule.target_payload["action_filter"] == "rule."


# ─────────────────────────────────────────────────────────────────────────────
#  Dependency chaining (single-parent, Phase 1, scoped to one workflow) + guards
# ─────────────────────────────────────────────────────────────────────────────

def test_cycle_guard_rejects_self_dependency_chain(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        a, _ = TaskSchedulerModel.create_schedule({
            "title": "A", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 1, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        b, _ = TaskSchedulerModel.create_schedule({
            "title": "B", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "after_task",
            "depends_on_schedule_id": a.id, "depends_on_condition": "success",
            "workflow_uuid": workflow.uuid,
        }, admin)
        assert b.trigger_mode == "after_task"

        # A cannot now depend on B — that would form a 2-node cycle A -> B -> A.
        _, err = TaskSchedulerModel.update_schedule(a.uuid, {
            "title": "A", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "after_task",
            "depends_on_schedule_id": b.id, "depends_on_condition": "success",
        })
        assert err is not None
        assert "cycle" in err.lower()


def test_task_cannot_depend_on_a_task_in_another_workflow(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow_a = _make_workflow(admin, "Workflow A")
        workflow_b = _make_workflow(admin, "Workflow B")
        outside, _ = TaskSchedulerModel.create_schedule({
            "title": "Outside", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 1, "minute": 0,
            "workflow_uuid": workflow_a.uuid,
        }, admin)

        _, err = TaskSchedulerModel.create_schedule({
            "title": "Inside", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "after_task",
            "depends_on_schedule_id": outside.id, "depends_on_condition": "success",
            "workflow_uuid": workflow_b.uuid,
        }, admin)
        assert err is not None
        assert "same workflow" in err.lower()


def test_dependent_task_fires_when_parent_job_finishes_successfully(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        parent, _ = TaskSchedulerModel.create_schedule({
            "title": "Parent", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "once",
            "run_once_at": (datetime.datetime.utcnow() + datetime.timedelta(days=1)).isoformat(),
            "workflow_uuid": workflow.uuid,
        }, admin)
        child, _ = TaskSchedulerModel.create_schedule({
            "title": "Child", "task_type": "attack_update_data", "target_payload": {},
            "trigger_mode": "after_task",
            "depends_on_schedule_id": parent.id, "depends_on_condition": "success",
            "workflow_uuid": workflow.uuid,
        }, admin)

        ok, err = TaskSchedulerModel.run_schedule_now(parent.uuid)
        assert ok, err
        parent_run = AdminTaskRun.query.filter_by(schedule_id=parent.id).first()
        parent_job = BackgroundJob.query.filter_by(uuid=parent_run.job_uuid).first()

        # Simulate job_worker finishing the parent job successfully.
        parent_job.status = 'done'
        parent_job.finished_at = datetime.datetime.now(datetime.timezone.utc)
        db.session.commit()
        scheduler_engine.on_job_finished(parent_job)

        child_run = AdminTaskRun.query.filter_by(schedule_id=child.id).first()
        assert child_run is not None, "child task should have fired after its parent succeeded"
        child_job = BackgroundJob.query.filter_by(uuid=child_run.job_uuid).first()
        assert child_job.job_type == "update_attack_data"


def test_dependent_task_does_not_fire_on_condition_mismatch(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        parent, _ = TaskSchedulerModel.create_schedule({
            "title": "Parent2", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "once",
            "run_once_at": (datetime.datetime.utcnow() + datetime.timedelta(days=1)).isoformat(),
            "workflow_uuid": workflow.uuid,
        }, admin)
        child, _ = TaskSchedulerModel.create_schedule({
            "title": "OnlyOnFailure", "task_type": "attack_update_data", "target_payload": {},
            "trigger_mode": "after_task",
            "depends_on_schedule_id": parent.id, "depends_on_condition": "failure",
            "workflow_uuid": workflow.uuid,
        }, admin)

        ok, err = TaskSchedulerModel.run_schedule_now(parent.uuid)
        assert ok, err
        parent_run = AdminTaskRun.query.filter_by(schedule_id=parent.id).first()
        parent_job = BackgroundJob.query.filter_by(uuid=parent_run.job_uuid).first()

        parent_job.status = 'done'  # succeeded — child only wants 'failure'
        db.session.commit()
        scheduler_engine.on_job_finished(parent_job)

        assert AdminTaskRun.query.filter_by(schedule_id=child.id).first() is None


# ─────────────────────────────────────────────────────────────────────────────
#  Live workflow run — "Run Workflow" button + graph/log polling
# ─────────────────────────────────────────────────────────────────────────────

def test_run_workflow_now_fires_only_root_tasks(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        root, _ = TaskSchedulerModel.create_schedule({
            "title": "Root", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        child, _ = TaskSchedulerModel.create_schedule({
            "title": "Child", "task_type": "attack_update_data", "target_payload": {},
            "trigger_mode": "after_task",
            "depends_on_schedule_id": root.id, "depends_on_condition": "success",
            "workflow_uuid": workflow.uuid,
        }, admin)

        ok, err = TaskSchedulerModel.run_workflow_now(workflow.uuid)
        assert ok, err

        assert AdminTaskRun.query.filter_by(schedule_id=root.id).count() == 1
        # The child only fires once the root's job actually finishes (via
        # on_job_finished) — run_workflow_now must not fire it directly.
        assert AdminTaskRun.query.filter_by(schedule_id=child.id).count() == 0


def test_run_workflow_now_fails_when_every_root_is_paused(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        root, _ = TaskSchedulerModel.create_schedule({
            "title": "Root", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        root.is_active = False
        db.session.commit()

        ok, err = TaskSchedulerModel.run_workflow_now(workflow.uuid)
        assert not ok
        assert "paused" in err.lower()


def test_workflow_live_status_reports_job_progress(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        task, _ = TaskSchedulerModel.create_schedule({
            "title": "Backup", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)

        # Before any run, the task reports no job.
        live = TaskSchedulerModel.get_workflow_live_status(workflow.uuid)
        assert len(live) == 1
        assert live[0]["task_uuid"] == task.uuid
        assert live[0]["job_uuid"] is None

        TaskSchedulerModel.run_schedule_now(task.uuid)
        live = TaskSchedulerModel.get_workflow_live_status(workflow.uuid)
        entry = next(t for t in live if t["task_uuid"] == task.uuid)
        assert entry["job_uuid"] is not None
        assert entry["job_status"] == "pending"  # job_worker hasn't picked it up in this test


# ─────────────────────────────────────────────────────────────────────────────
#  Workflow-level email notifications (opt-in, per workflow)
# ─────────────────────────────────────────────────────────────────────────────

def _run_task_to_completion(admin, workflow, job_status):
    schedule, _ = TaskSchedulerModel.create_schedule({
        "title": "Notified task", "task_type": "db_backup", "target_payload": {},
        "trigger_mode": "once",
        "run_once_at": (datetime.datetime.utcnow() + datetime.timedelta(days=1)).isoformat(),
        "workflow_uuid": workflow.uuid,
    }, admin)
    TaskSchedulerModel.run_schedule_now(schedule.uuid)
    run = AdminTaskRun.query.filter_by(schedule_id=schedule.id).first()
    job = BackgroundJob.query.filter_by(uuid=run.job_uuid).first()
    job.status = job_status
    if job_status == 'failed':
        job.error = 'boom: backup script exploded'
    db.session.commit()
    scheduler_engine.on_job_finished(job)
    return schedule, job


def test_failure_email_sent_by_default(app, monkeypatch):
    from app.features.admin.task_scheduler import notifications

    sent = []
    monkeypatch.setattr(notifications.mail, 'send', lambda msg: sent.append(msg))

    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow, _ = TaskSchedulerModel.create_workflow({"title": "Notify me"}, admin)
        assert workflow.notify_on_failure is True
        assert workflow.notify_on_success is False

        _run_task_to_completion(admin, workflow, 'failed')

        assert len(sent) == 1
        assert admin.email in sent[0].recipients
        assert 'failed' in sent[0].subject.lower()
        assert 'boom' in sent[0].html


def test_success_email_not_sent_unless_opted_in(app, monkeypatch):
    from app.features.admin.task_scheduler import notifications

    sent = []
    monkeypatch.setattr(notifications.mail, 'send', lambda msg: sent.append(msg))

    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow, _ = TaskSchedulerModel.create_workflow({"title": "Quiet on success"}, admin)

        _run_task_to_completion(admin, workflow, 'done')
        assert len(sent) == 0

        workflow.notify_on_success = True
        db.session.commit()
        _run_task_to_completion(admin, workflow, 'done')
        assert len(sent) == 1
        assert 'succeeded' in sent[0].subject.lower()


def test_extra_notify_emails_are_included(app, monkeypatch):
    from app.features.admin.task_scheduler import notifications

    sent = []
    monkeypatch.setattr(notifications.mail, 'send', lambda msg: sent.append(msg))

    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow, _ = TaskSchedulerModel.create_workflow({
            "title": "Team workflow", "notify_emails": ["teammate@example.com"],
        }, admin)

        _run_task_to_completion(admin, workflow, 'failed')

        assert len(sent) == 1
        assert "teammate@example.com" in sent[0].recipients


def test_workflow_launch_sends_exactly_one_started_and_one_finished_email(app, monkeypatch):
    """A multi-task launch must email once at start and once at the end —
    never once per task — even though every task also goes through
    on_job_finished individually."""
    from app.features.admin.task_scheduler import notifications

    sent = []
    monkeypatch.setattr(notifications.mail, 'send', lambda msg: sent.append(msg))

    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow, _ = TaskSchedulerModel.create_workflow(
            {"title": "Multi-step", "notify_on_success": True}, admin)
        root, _ = TaskSchedulerModel.create_schedule({
            "title": "Root", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        child, _ = TaskSchedulerModel.create_schedule({
            "title": "Child", "task_type": "attack_update_data", "target_payload": {},
            "trigger_mode": "after_task",
            "depends_on_schedule_id": root.id, "depends_on_condition": "success",
            "workflow_uuid": workflow.uuid,
        }, admin)

        TaskSchedulerModel.run_workflow_now(workflow.uuid, triggered_by=admin)
        assert len(sent) == 1
        assert "launched" in sent[0].subject.lower()

        root_run = AdminTaskRun.query.filter_by(schedule_id=root.id).first()
        root_job = BackgroundJob.query.filter_by(uuid=root_run.job_uuid).first()
        root_job.status = 'done'
        db.session.commit()
        scheduler_engine.on_job_finished(root_job)
        assert len(sent) == 1, "no per-task email for a task that's part of a workflow launch"

        child_run = AdminTaskRun.query.filter_by(schedule_id=child.id).first()
        child_job = BackgroundJob.query.filter_by(uuid=child_run.job_uuid).first()
        child_job.status = 'done'
        db.session.commit()
        scheduler_engine.on_job_finished(child_job)

        assert len(sent) == 2
        assert "finished" in sent[1].subject.lower()
        assert "successfully" in sent[1].html.lower()


def test_workflow_launch_finish_email_reports_failure(app, monkeypatch):
    from app.features.admin.task_scheduler import notifications

    sent = []
    monkeypatch.setattr(notifications.mail, 'send', lambda msg: sent.append(msg))

    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow, _ = TaskSchedulerModel.create_workflow({"title": "Will fail"}, admin)
        TaskSchedulerModel.create_schedule({
            "title": "Root", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)

        TaskSchedulerModel.run_workflow_now(workflow.uuid, triggered_by=admin)
        root_run = AdminTaskRun.query.filter_by(schedule_id=workflow.tasks[0].id).first()
        root_job = BackgroundJob.query.filter_by(uuid=root_run.job_uuid).first()
        root_job.status = 'failed'
        root_job.error = 'boom'
        db.session.commit()
        scheduler_engine.on_job_finished(root_job)

        assert len(sent) == 2
        assert "finished" in sent[1].subject.lower()
        assert "errors" in sent[1].html.lower()


# ─────────────────────────────────────────────────────────────────────────────
#  Launch history — one AdminWorkflowRun per "Run Workflow" click
# ─────────────────────────────────────────────────────────────────────────────

def test_run_workflow_now_creates_a_launch_history_entry_covering_the_chain(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        root, _ = TaskSchedulerModel.create_schedule({
            "title": "Root", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        child, _ = TaskSchedulerModel.create_schedule({
            "title": "Child", "task_type": "attack_update_data", "target_payload": {},
            "trigger_mode": "after_task",
            "depends_on_schedule_id": root.id, "depends_on_condition": "success",
            "workflow_uuid": workflow.uuid,
        }, admin)

        ok, err = TaskSchedulerModel.run_workflow_now(workflow.uuid, triggered_by=admin)
        assert ok, err

        page = TaskSchedulerModel.get_workflow_runs_page(workflow.uuid)
        assert page.total == 1
        run = page.items[0]
        assert run.triggered_by_id == admin.id

        # Root is running (still 'pending' in test — job_worker never picked
        # it up), the chain hasn't reached the child yet.
        summary = TaskSchedulerModel.serialize_workflow_run(run)
        assert summary["status"] == "running"
        assert summary["task_count"] == 1
        assert summary["tasks"][0]["task_title"] == "Root"

        # Simulate the root's job finishing successfully — the child should
        # fire, inheriting the SAME workflow_run_id (propagated by
        # on_job_finished), and now show up in this run's history too.
        root_run = AdminTaskRun.query.filter_by(schedule_id=root.id).first()
        root_job = BackgroundJob.query.filter_by(uuid=root_run.job_uuid).first()
        root_job.status = 'done'
        db.session.commit()
        scheduler_engine.on_job_finished(root_job)

        summary = TaskSchedulerModel.serialize_workflow_run(run)
        assert summary["task_count"] == 2
        assert {t["task_title"] for t in summary["tasks"]} == {"Root", "Child"}
        assert summary["status"] == "running"  # child's job is still 'pending' in this test

        child_run = AdminTaskRun.query.filter_by(schedule_id=child.id).first()
        assert child_run.workflow_run_id == run.id


def test_single_task_run_now_does_not_create_launch_history(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        task, _ = TaskSchedulerModel.create_schedule({
            "title": "Solo", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)

        TaskSchedulerModel.run_schedule_now(task.uuid)

        page = TaskSchedulerModel.get_workflow_runs_page(workflow.uuid)
        assert page.total == 0


# ─────────────────────────────────────────────────────────────────────────────
#  Canvas view — free-form node positions + drag-to-connect
# ─────────────────────────────────────────────────────────────────────────────

def test_set_task_position_persists_coordinates(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        task, _ = TaskSchedulerModel.create_schedule({
            "title": "Node", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        assert task.position_x is None and task.position_y is None

        schedule, err = TaskSchedulerModel.set_task_position(task.uuid, 120.5, 340.25)
        assert err is None
        assert schedule.position_x == 120.5
        assert schedule.position_y == 340.25


def test_set_task_position_404s_for_unknown_task(app):
    with app.app_context():
        schedule, err = TaskSchedulerModel.set_task_position("00000000-0000-0000-0000-000000000000", 0, 0)
        assert schedule is None
        assert err == "Task not found."


def test_set_task_dependency_wires_two_existing_tasks_without_touching_other_fields(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        parent, _ = TaskSchedulerModel.create_schedule({
            "title": "Parent", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        child, _ = TaskSchedulerModel.create_schedule({
            "title": "Child", "task_type": "attack_update_data", "target_payload": {},
            "trigger_mode": "weekly", "days_of_week": [0], "hour": 4, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)

        updated, err = TaskSchedulerModel.set_task_dependency(child.uuid, parent.id, 'failure')
        assert err is None
        assert updated.trigger_mode == 'after_task'
        assert updated.depends_on_schedule_id == parent.id
        assert updated.depends_on_condition == 'failure'
        # Untouched by the connect action:
        assert updated.title == "Child"
        assert updated.task_type == "attack_update_data"


def test_set_task_dependency_rejects_cycle(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        a, _ = TaskSchedulerModel.create_schedule({
            "title": "A", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        b, _ = TaskSchedulerModel.create_schedule({
            "title": "B", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "after_task",
            "depends_on_schedule_id": a.id, "depends_on_condition": "success",
            "workflow_uuid": workflow.uuid,
        }, admin)

        _, err = TaskSchedulerModel.set_task_dependency(a.uuid, b.id, 'success')
        assert err is not None
        assert "cycle" in err.lower()


def test_set_task_dependency_rejects_cross_workflow_connection(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow_a = _make_workflow(admin, "A")
        workflow_b = _make_workflow(admin, "B")
        outside, _ = TaskSchedulerModel.create_schedule({
            "title": "Outside", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow_a.uuid,
        }, admin)
        inside, _ = TaskSchedulerModel.create_schedule({
            "title": "Inside", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 4, "minute": 0,
            "workflow_uuid": workflow_b.uuid,
        }, admin)

        _, err = TaskSchedulerModel.set_task_dependency(inside.uuid, outside.id, 'success')
        assert err is not None
        assert "same workflow" in err.lower()


def test_clear_task_dependency_falls_back_to_a_safe_paused_daily_trigger(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        parent, _ = TaskSchedulerModel.create_schedule({
            "title": "Parent", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        child, _ = TaskSchedulerModel.create_schedule({
            "title": "Child", "task_type": "attack_update_data", "target_payload": {},
            "trigger_mode": "after_task",
            "depends_on_schedule_id": parent.id, "depends_on_condition": "success",
            "workflow_uuid": workflow.uuid,
        }, admin)

        updated, err = TaskSchedulerModel.clear_task_dependency(child.uuid)
        assert err is None
        assert updated.trigger_mode == 'daily'
        assert updated.depends_on_schedule_id is None
        assert updated.is_active is False


def test_clear_task_dependency_rejects_task_without_a_dependency(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        task, _ = TaskSchedulerModel.create_schedule({
            "title": "Solo", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)

        _, err = TaskSchedulerModel.clear_task_dependency(task.uuid)
        assert err is not None


def test_bulk_delete_workflow_runs_removes_only_the_bookkeeping_row(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        task, _ = TaskSchedulerModel.create_schedule({
            "title": "Task", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)

        TaskSchedulerModel.run_workflow_now(workflow.uuid, triggered_by=admin)
        TaskSchedulerModel.run_workflow_now(workflow.uuid, triggered_by=admin)
        page = TaskSchedulerModel.get_workflow_runs_page(workflow.uuid)
        assert page.total == 2
        run_uuids = [r.uuid for r in page.items]

        count, err = TaskSchedulerModel.bulk_delete_workflow_runs(workflow.uuid, run_uuids)
        assert err is None
        assert count == 2

        page_after = TaskSchedulerModel.get_workflow_runs_page(workflow.uuid)
        assert page_after.total == 0
        # The task's own run history is untouched by deleting the launch bookkeeping.
        assert AdminTaskRun.query.filter_by(schedule_id=task.id).count() == 2


def test_bulk_delete_workflow_runs_404s_for_unknown_workflow(app):
    with app.app_context():
        count, err = TaskSchedulerModel.bulk_delete_workflow_runs("00000000-0000-0000-0000-000000000000", [])
        assert count is None
        assert err == "Workflow not found."


# ─────────────────────────────────────────────────────────────────────────────
#  Stop Workflow — cancel every currently pending/running job
# ─────────────────────────────────────────────────────────────────────────────

def test_stop_workflow_jobs_cancels_pending_jobs(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        task, _ = TaskSchedulerModel.create_schedule({
            "title": "Task", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        TaskSchedulerModel.run_schedule_now(task.uuid)
        run = AdminTaskRun.query.filter_by(schedule_id=task.id).first()
        job = BackgroundJob.query.filter_by(uuid=run.job_uuid).first()
        assert job.status == 'pending'

        stopped, err = TaskSchedulerModel.stop_workflow_jobs(workflow.uuid)
        assert err is None
        assert stopped == 1

        db.session.refresh(job)
        assert job.status == 'cancelled'


def test_stop_workflow_jobs_404s_for_unknown_workflow(app):
    with app.app_context():
        stopped, err = TaskSchedulerModel.stop_workflow_jobs("00000000-0000-0000-0000-000000000000")
        assert stopped is None
        assert err == "Workflow not found."


def test_run_workflow_now_returns_the_created_run(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        TaskSchedulerModel.create_schedule({
            "title": "Task", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)

        workflow_run, err = TaskSchedulerModel.run_workflow_now(workflow.uuid, triggered_by=admin)
        assert err is None
        assert workflow_run.uuid is not None
        assert workflow_run.workflow_id == workflow.id


# ─────────────────────────────────────────────────────────────────────────────
#  In-app notifications — workflow launched / finished (bell, pref_workflow_runs)
# ─────────────────────────────────────────────────────────────────────────────

def test_run_workflow_now_notifies_admins_it_started(app):
    from app.core.db_class.db import Notification
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        TaskSchedulerModel.create_schedule({
            "title": "Task", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)

        workflow_run, err = TaskSchedulerModel.run_workflow_now(workflow.uuid, triggered_by=admin)
        assert err is None

        notif = Notification.query.filter_by(
            user_id=admin.id, job_uuid=workflow_run.uuid, notif_type='workflow_run_started').first()
        assert notif is not None
        assert workflow.title in notif.title


def test_workflow_run_finished_notification_fires_once_the_only_task_settles(app):
    from app.core.db_class.db import Notification
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        TaskSchedulerModel.create_schedule({
            "title": "Task", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)

        workflow_run, err = TaskSchedulerModel.run_workflow_now(workflow.uuid, triggered_by=admin)
        assert err is None
        run = AdminTaskRun.query.filter_by(workflow_run_id=workflow_run.id).first()
        job = BackgroundJob.query.filter_by(uuid=run.job_uuid).first()
        job.status = 'done'
        db.session.commit()
        scheduler_engine.on_job_finished(job)

        # Same row, updated in place — not a second notification.
        notifs = Notification.query.filter_by(user_id=admin.id, job_uuid=workflow_run.uuid).all()
        assert len(notifs) == 1
        assert notifs[0].notif_type == 'workflow_run_finished'
        assert notifs[0].job_status == 'done'


def test_workflow_run_finished_notification_waits_for_the_full_chain(app):
    from app.core.db_class.db import Notification
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        root, _ = TaskSchedulerModel.create_schedule({
            "title": "Root", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        child, _ = TaskSchedulerModel.create_schedule({
            "title": "Child", "task_type": "attack_update_data", "target_payload": {},
            "trigger_mode": "after_task",
            "depends_on_schedule_id": root.id, "depends_on_condition": "success",
            "workflow_uuid": workflow.uuid,
        }, admin)

        workflow_run, err = TaskSchedulerModel.run_workflow_now(workflow.uuid, triggered_by=admin)
        assert err is None

        root_run = AdminTaskRun.query.filter_by(schedule_id=root.id).first()
        root_job = BackgroundJob.query.filter_by(uuid=root_run.job_uuid).first()
        root_job.status = 'done'
        db.session.commit()
        scheduler_engine.on_job_finished(root_job)

        # Child just fired and is still 'pending' — not finished yet.
        notif = Notification.query.filter_by(job_uuid=workflow_run.uuid, notif_type='workflow_run_finished').first()
        assert notif is None

        child_run = AdminTaskRun.query.filter_by(schedule_id=child.id).first()
        child_job = BackgroundJob.query.filter_by(uuid=child_run.job_uuid).first()
        child_job.status = 'done'
        db.session.commit()
        scheduler_engine.on_job_finished(child_job)

        notif = Notification.query.filter_by(job_uuid=workflow_run.uuid, notif_type='workflow_run_finished').first()
        assert notif is not None
        assert notif.job_status == 'done'


def test_stop_workflow_triggers_a_finished_notification(app):
    from app.core.db_class.db import Notification
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        TaskSchedulerModel.create_schedule({
            "title": "Task", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)

        workflow_run, err = TaskSchedulerModel.run_workflow_now(workflow.uuid, triggered_by=admin)
        assert err is None

        stopped, err = TaskSchedulerModel.stop_workflow_jobs(workflow.uuid)
        assert err is None and stopped == 1

        notif = Notification.query.filter_by(job_uuid=workflow_run.uuid, notif_type='workflow_run_finished').first()
        assert notif is not None
        assert notif.job_status == 'cancelled'


def test_workflow_run_notifications_respect_the_preference_toggle(app):
    from app.core.db_class.db import Notification
    from app.features.notification.notification_core import update_preference
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        update_preference(admin.id, {'workflow_runs': False})
        workflow = _make_workflow(admin)
        TaskSchedulerModel.create_schedule({
            "title": "Task", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)

        workflow_run, err = TaskSchedulerModel.run_workflow_now(workflow.uuid, triggered_by=admin)
        assert err is None

        assert Notification.query.filter_by(job_uuid=workflow_run.uuid).first() is None


# ─────────────────────────────────────────────────────────────────────────────
#  Paused mid-chain tasks still run inside a manual "Run Workflow" launch
# ─────────────────────────────────────────────────────────────────────────────

def test_paused_child_still_fires_inside_a_workflow_launch(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        root, _ = TaskSchedulerModel.create_schedule({
            "title": "Root", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "daily", "hour": 3, "minute": 0,
            "workflow_uuid": workflow.uuid,
        }, admin)
        child, _ = TaskSchedulerModel.create_schedule({
            "title": "PausedChild", "task_type": "attack_update_data", "target_payload": {},
            "trigger_mode": "after_task", "is_active": False,
            "depends_on_schedule_id": root.id, "depends_on_condition": "success",
            "workflow_uuid": workflow.uuid,
        }, admin)
        assert child.is_active is False

        workflow_run, err = TaskSchedulerModel.run_workflow_now(workflow.uuid, triggered_by=admin)
        assert err is None

        root_run = AdminTaskRun.query.filter_by(schedule_id=root.id).first()
        root_job = BackgroundJob.query.filter_by(uuid=root_run.job_uuid).first()
        root_job.status = 'done'
        db.session.commit()
        scheduler_engine.on_job_finished(root_job)

        child_run = AdminTaskRun.query.filter_by(schedule_id=child.id).first()
        assert child_run is not None, "a paused task should still fire as part of an explicit workflow launch"
        assert child_run.workflow_run_id == workflow_run.id
        # Pausing it wasn't silently cleared — still paused for its own
        # schedule/automatic firing afterwards.
        db.session.refresh(child)
        assert child.is_active is False


def test_paused_child_does_not_fire_for_a_standalone_task_run(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        workflow = _make_workflow(admin)
        parent, _ = TaskSchedulerModel.create_schedule({
            "title": "Parent", "task_type": "db_backup", "target_payload": {},
            "trigger_mode": "once",
            "run_once_at": (datetime.datetime.utcnow() + datetime.timedelta(days=1)).isoformat(),
            "workflow_uuid": workflow.uuid,
        }, admin)
        child, _ = TaskSchedulerModel.create_schedule({
            "title": "PausedChild", "task_type": "attack_update_data", "target_payload": {},
            "trigger_mode": "after_task", "is_active": False,
            "depends_on_schedule_id": parent.id, "depends_on_condition": "success",
            "workflow_uuid": workflow.uuid,
        }, admin)

        ok, err = TaskSchedulerModel.run_schedule_now(parent.uuid)
        assert ok, err
        parent_run = AdminTaskRun.query.filter_by(schedule_id=parent.id).first()
        parent_job = BackgroundJob.query.filter_by(uuid=parent_run.job_uuid).first()
        parent_job.status = 'done'
        db.session.commit()
        scheduler_engine.on_job_finished(parent_job)

        assert AdminTaskRun.query.filter_by(schedule_id=child.id).first() is None, (
            "a paused task should NOT fire outside of an explicit workflow launch"
        )
