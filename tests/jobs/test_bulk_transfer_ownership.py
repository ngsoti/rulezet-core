"""
Tests for the admin "Manual Ownership" bulk transfer job
(job_type: bulk_transfer_ownership).
"""

import uuid

from app import db
from app.core.db_class.db import BackgroundJob, Notification, Rule, RequestOwnerRule, User
from app.features.jobs.job_handlers import handle_bulk_transfer_ownership


def _make_job(payload, created_by):
    job = BackgroundJob(
        uuid=str(uuid.uuid4()),
        created_by=created_by,
        job_type='bulk_transfer_ownership',
        status='running',
        payload=payload,
    )
    db.session.add(job)
    db.session.commit()
    return job


def _make_rule(title, user_id):
    rule = Rule(
        format="yara",
        title=title,
        license="test",
        description="test",
        uuid=str(uuid.uuid4()),
        source="test",
        author="test",
        version=1,
        user_id=user_id,
        to_string=" rule test { condition: 1}",
    )
    db.session.add(rule)
    db.session.commit()
    return rule


def test_bulk_transfer_ownership_reassigns_rules(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        old_owner = User.query.filter_by(email="neo@admin.admin").first()
        new_owner = User.query.filter_by(email="t@t.t").first()

        r1 = _make_rule("Rule A", old_owner.id)
        r2 = _make_rule("Rule B", old_owner.id)

        job = _make_job(
            {"new_owner_id": new_owner.id, "filters": {"rule_ids": [r1.id, r2.id]}},
            admin.id,
        )

        handle_bulk_transfer_ownership(job, app)

        db.session.refresh(job)
        assert job.total == 2
        assert job.done == 2

        r1_after = Rule.query.get(r1.id)
        r2_after = Rule.query.get(r2.id)
        assert r1_after.user_id == new_owner.id
        assert r2_after.user_id == new_owner.id

        # New owner was notified
        notif = Notification.query.filter_by(
            user_id=new_owner.id, notif_type="ownership_approved"
        ).first()
        assert notif is not None


def test_bulk_transfer_ownership_rejects_pending_requests_for_transferred_rules(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        old_owner = User.query.filter_by(email="neo@admin.admin").first()
        requester = User.query.filter_by(email="t@t.t").first()
        new_owner = admin

        rule = _make_rule("Rule C", old_owner.id)

        pending_request = RequestOwnerRule(
            uuid=str(uuid.uuid4()),
            rule_id=rule.id,
            user_id=requester.id,
            title="I want this rule",
            content="please",
            status="pending",
        )
        db.session.add(pending_request)
        db.session.commit()

        job = _make_job(
            {"new_owner_id": new_owner.id, "filters": {"rule_ids": [rule.id]}},
            admin.id,
        )
        handle_bulk_transfer_ownership(job, app)

        db.session.refresh(pending_request)
        assert pending_request.status == "rejected"
        assert pending_request.user_id_to_send == new_owner.id


def test_bulk_transfer_ownership_requires_new_owner_id(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        job = _make_job({"filters": {"rule_ids": []}}, admin.id)
        try:
            handle_bulk_transfer_ownership(job, app)
            assert False, "expected ValueError"
        except ValueError as e:
            assert "new_owner_id" in str(e)


def test_bulk_transfer_ownership_no_matching_rules_is_a_noop(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        new_owner = User.query.filter_by(email="t@t.t").first()
        job = _make_job(
            {"new_owner_id": new_owner.id, "filters": {"rule_ids": [999999]}},
            admin.id,
        )
        handle_bulk_transfer_ownership(job, app)
        db.session.refresh(job)
        assert job.total == 0
