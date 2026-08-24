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
