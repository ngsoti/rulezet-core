"""
Tests for POST /api/tags/private/bulk_add — lets an API key holder with the
rule.tag_any permission (or an admin) enqueue a bulk_add_tag_to_rules job,
mirroring the web UI's quick_meta tag-only carve-out but for API-key callers.

The route is two-step: the first call (no "confirm") only returns a preview
of what would happen, so a caller always sees the blast radius before
anything is queued; "confirm": true is required to actually create the job.

Rules and tags can each be identified by Rulezet's own id, its own uuid, or
both mixed together — never by the separate GitHub-import original_uuid
field some rules also carry.
"""

import uuid

from app import db
from app.core.db_class.db import BackgroundJob, Rule, RuleTagAssociation, RuleUpdateHistory, Tag, User
from app.features.jobs.job_handlers import handle_bulk_add_tag_to_rules
from app.features.roles import roles_core


def _make_tag():
    admin = User.query.filter_by(email="admin@admin.admin").first()
    tag = Tag(uuid=str(uuid.uuid4()), name="api-bulk-tag", created_by=admin.id, source="Manual")
    db.session.add(tag)
    db.session.commit()
    return tag


def test_invalid_api_key_is_rejected(app, client):
    with app.app_context():
        # The blanket @api_required check (verif_api_key) rejects an unknown
        # key before this route's own body ever runs — same 403 every other
        # API route gets for a bad key, not a route-specific 401.
        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "not-a-real-key"},
                           json={"rule_ids": [1], "tag_ids": [1]})
        assert res.status_code == 403


def test_api_key_without_permission_is_forbidden(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()
        # neo@admin.admin has api_key="user_api_key" and no role/admin
        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "user_api_key"},
                           json={"rule_ids": [rule.id], "tag_ids": [tag.id], "confirm": True})
        assert res.status_code == 403


def test_first_call_without_confirm_returns_preview_and_creates_no_job(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()
        jobs_before = BackgroundJob.query.count()

        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_ids": [rule.id], "tag_ids": [tag.id]})
        assert res.status_code == 200
        data = res.get_json()
        assert data["confirmed"] is False
        assert "job_uuid" not in data
        assert tag.name in data["message"]
        assert data["preview"]["matched_rule_count"] == 1
        assert data["preview"]["requested_rule_count"] == 1
        assert data["preview"]["tags"] == [{"id": tag.id, "name": tag.name}]

        assert BackgroundJob.query.count() == jobs_before


def test_confirmed_call_creates_job_and_returns_job_url(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()
        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_ids": [rule.id], "tag_ids": [tag.id], "confirm": True})
        assert res.status_code == 202
        data = res.get_json()
        assert data["confirmed"] is True
        assert data["job_url"] == f"/jobs/detail/{data['job_uuid']}"
        job = BackgroundJob.query.filter_by(uuid=data["job_uuid"]).first()
        assert job is not None
        assert job.job_type == "bulk_add_tag_to_rules"


def test_tagger_api_key_can_bulk_tag_and_job_applies_it(app, client):
    with app.app_context():
        roles_core.seed_default_permissions_and_roles()
        tagger = User.query.filter_by(email="neo@admin.admin").first()
        role = next(r for r in roles_core.get_all_roles() if r.name == "Tag manager")
        roles_core.add_user_to_role(role.id, tagger.id, granted_by_id=None)

        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()

        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "user_api_key"},
                           json={"rule_ids": [rule.id], "tag_ids": [tag.id], "confirm": True})
        assert res.status_code == 202
        job_uuid = res.get_json()["job_uuid"]
        job = BackgroundJob.query.filter_by(uuid=job_uuid).first()

        handle_bulk_add_tag_to_rules(job, app)

        assert RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag.id).first() is not None


def test_missing_fields_are_rejected(app, client):
    with app.app_context():
        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_ids": [], "confirm": True})
        assert res.status_code == 400


def test_missing_tag_ids_is_rejected(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_ids": [rule.id], "tag_ids": [], "confirm": True})
        assert res.status_code == 400


def test_nonexistent_tag_ids_are_rejected(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_ids": [rule.id], "tag_ids": [999999], "confirm": True})
        assert res.status_code == 400


def test_all_rule_ids_nonexistent_is_rejected(app, client):
    """Symmetric with the tag_ids-side check: if literally none of the given
    rule_ids/rule_uuids resolve to a real rule, that's a 400, not a job
    silently created to tag nothing."""
    with app.app_context():
        tag = _make_tag()
        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_ids": [999999], "tag_ids": [tag.id], "confirm": True})
        assert res.status_code == 400


def test_mix_of_valid_and_nonexistent_rule_ids_only_tags_existing(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()
        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_ids": [rule.id, 999999], "tag_ids": [tag.id], "confirm": True})
        assert res.status_code == 202
        job_uuid = res.get_json()["job_uuid"]
        job = BackgroundJob.query.filter_by(uuid=job_uuid).first()

        handle_bulk_add_tag_to_rules(job, app)

        assert RuleTagAssociation.query.filter_by(tag_id=tag.id).count() == 1
        assert RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag.id).first() is not None


def test_job_records_rule_history_entry(app, client):
    """The bulk job must leave an audit trail on each newly-tagged rule's own
    history — otherwise a bulk tag change via this route (or the equivalent
    admin bulk-tag UI, which shares this same job handler) is invisible when
    reviewing that rule's history later."""
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        admin = User.query.filter_by(email="admin@admin.admin").first()
        tag = _make_tag()
        history_before = RuleUpdateHistory.query.filter_by(rule_id=rule.id).count()

        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_ids": [rule.id], "tag_ids": [tag.id], "confirm": True})
        job = BackgroundJob.query.filter_by(uuid=res.get_json()["job_uuid"]).first()
        handle_bulk_add_tag_to_rules(job, app)

        entries = RuleUpdateHistory.query.filter_by(rule_id=rule.id).order_by(RuleUpdateHistory.id.desc()).all()
        assert len(entries) == history_before + 1
        entry = entries[0]
        assert entry.change_type == "metadata"
        assert tag.name in entry.message
        assert entry.analyzed_by_user_id == admin.id
        assert entry.old_snapshot == {"tags": []}
        assert entry.new_snapshot == {"tags": [tag.name]}


def test_bulk_tag_shows_up_correctly_on_the_rule_history_page(app, client):
    """Same page/endpoint the "Content & metadata updated" / "Metadata
    updated" entries for a manual edit render from
    (/rule/history_data/<id>, feeding /rule/detail_rule/<id>/history) — a
    bulk-tag entry must land there too, and must not fall through to the
    generic "Checked — no change" bucket just because old_content ==
    new_content (which is the case for a tags-only change, manual or not)."""
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()

        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_ids": [rule.id], "tag_ids": [tag.id], "confirm": True})
        job = BackgroundJob.query.filter_by(uuid=res.get_json()["job_uuid"]).first()
        handle_bulk_add_tag_to_rules(job, app)

        with client.session_transaction() as sess:
            admin = User.query.filter_by(email="admin@admin.admin").first()
            sess["_user_id"] = str(admin.id)
            sess["_fresh"] = True

        res = client.get(f"/rule/history_data/{rule.id}")
        assert res.status_code == 200
        items = res.get_json()["items"]
        update_events = [e for e in items if e["type"] == "update"]
        assert update_events, "expected at least one RuleUpdateHistory-backed event"

        bulk_event = update_events[0]
        assert bulk_event["title"] != "Checked — no change"
        assert bulk_event["title"] == "Metadata updated"
        assert bulk_event["metadata_changes"] == [
            {"field": "tags", "label": "Tags", "type": "list", "added": [tag.name], "removed": []}
        ]


def test_job_does_not_record_history_for_already_tagged_rule(app, client):
    """Re-running a bulk tag over a rule that already has the tag must not
    spam a new history entry for a no-op association."""
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()

        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_ids": [rule.id], "tag_ids": [tag.id], "confirm": True})
        job = BackgroundJob.query.filter_by(uuid=res.get_json()["job_uuid"]).first()
        handle_bulk_add_tag_to_rules(job, app)
        history_after_first_run = RuleUpdateHistory.query.filter_by(rule_id=rule.id).count()

        res2 = client.post("/api/tags/private/bulk_add",
                            headers={"X-API-KEY": "admin_api_key"},
                            json={"rule_ids": [rule.id], "tag_ids": [tag.id], "confirm": True})
        job2 = BackgroundJob.query.filter_by(uuid=res2.get_json()["job_uuid"]).first()
        handle_bulk_add_tag_to_rules(job2, app)

        assert RuleUpdateHistory.query.filter_by(rule_id=rule.id).count() == history_after_first_run


def test_rule_uuids_and_tag_uuids_are_accepted(app, client):
    """Rulezet's own id and uuid must both work as identifiers, mixed or not
    — not the GitHub-import original_uuid, only Rule.uuid/Tag.uuid."""
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()

        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_uuids": [rule.uuid], "tag_uuids": [tag.uuid], "confirm": True})
        assert res.status_code == 202
        job = BackgroundJob.query.filter_by(uuid=res.get_json()["job_uuid"]).first()

        handle_bulk_add_tag_to_rules(job, app)

        assert RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag.id).first() is not None


def test_mixing_rule_id_and_rule_uuid_in_same_call(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        tag = _make_tag()

        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_ids": [rule.id], "tag_uuids": [tag.uuid], "confirm": True})
        assert res.status_code == 202
        data = res.get_json()
        assert "id=" + str(tag.id) in data["message"]


def test_nonexistent_rule_uuid_is_rejected_like_nonexistent_id(app, client):
    with app.app_context():
        tag = _make_tag()
        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_uuids": ["00000000-0000-0000-0000-000000000000"],
                                 "tag_ids": [tag.id], "confirm": True})
        assert res.status_code == 400


def test_nonexistent_tag_uuid_is_rejected(app, client):
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_ids": [rule.id],
                                 "tag_uuids": ["00000000-0000-0000-0000-000000000000"], "confirm": True})
        assert res.status_code == 400


def test_original_uuid_is_not_a_valid_identifier(app, client):
    """The GitHub-import original_uuid field must never be accepted here —
    only Rulezet's own Rule.uuid. Setting a rule's original_uuid and trying
    to bulk-tag by it (as if it were rule_uuids) must not resolve."""
    with app.app_context():
        rule = Rule.query.filter_by(title="test").first()
        rule.original_uuid = "11111111-1111-1111-1111-111111111111"
        db.session.commit()
        tag = _make_tag()

        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "admin_api_key"},
                           json={"rule_uuids": [rule.original_uuid], "tag_ids": [tag.id], "confirm": True})
        assert res.status_code == 400


def test_nonexistent_rule_ids_alone_is_still_gated_by_permission(app, client):
    """A caller without rule.tag_any can't probe for rule existence via this
    route either — the permission check runs before any rule lookup."""
    with app.app_context():
        res = client.post("/api/tags/private/bulk_add",
                           headers={"X-API-KEY": "user_api_key"},
                           json={"rule_ids": [999999], "tag_ids": [1], "confirm": True})
        assert res.status_code == 403
