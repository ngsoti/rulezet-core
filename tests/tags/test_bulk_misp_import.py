"""
Tests for the admin "Add all taxonomies" / "Add all galaxies" bulk import jobs
(job_types: import_all_taxonomies, import_all_galaxies), and for the galaxy
icon regression (Tag.icon must store the raw MISP icon name, not a
pre-resolved FontAwesome class, or every display path double-maps it into
a nonexistent class and the icon disappears).
"""

import uuid

from app import db
from app.core.db_class.db import BackgroundJob, Tag, User
from app.features.jobs.job_handlers import handle_import_all_taxonomies, handle_import_all_galaxies
from app.features.tags import tags_core


def _make_job(job_type, created_by):
    job = BackgroundJob(
        uuid=str(uuid.uuid4()),
        created_by=created_by,
        job_type=job_type,
        status='running',
    )
    db.session.add(job)
    db.session.commit()
    return job


def _login(client, email):
    """Force a session cookie for this user, bypassing the password form —
    same pattern as tests/rules/test_github_proposal.py (test users other
    than admin@admin.admin get a random generate_api_key() password, so a
    real login POST isn't an option here)."""
    user = User.query.filter_by(email=email).first()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True
    return user


def test_add_tags_from_misp_galaxy_stores_raw_icon_name(app):
    """Regression test: importing a galaxy must not store an already-resolved
    FontAwesome class in Tag.icon — every display path re-resolves it via
    mapIcon()/similar, which only understands raw MISP icon names."""
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()

        uuids = tags_core.get_all_galaxy_uuids_from_disk()
        assert uuids, "expected at least one galaxy JSON on disk under app/modules/misp-galaxy"
        gal_uuid, gal_type = uuids[0]

        ok, msg = tags_core.add_tags_from_misp_galaxy(gal_uuid, admin)
        assert ok is True, msg

        tag = Tag.query.filter_by(source="Galaxy").first()
        assert tag is not None
        assert tag.icon, "icon must not be empty"
        assert not tag.icon.startswith("fas "), (
            f"Tag.icon stores a pre-resolved FA class ({tag.icon!r}) instead of "
            f"the raw MISP icon name — mapIcon() will double-map it and the icon "
            f"will not render"
        )
        assert " " not in tag.icon, f"raw icon names never contain spaces, got {tag.icon!r}"


def test_import_all_taxonomies_job_imports_from_disk(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        assert Tag.query.filter_by(source="Taxonomy").count() == 0

        job = _make_job('import_all_taxonomies', admin.id)
        handle_import_all_taxonomies(job, app)

        db.session.refresh(job)
        assert job.total > 0
        assert job.done == job.total
        assert Tag.query.filter_by(source="Taxonomy").count() > 0
        assert job.logs.count() > 0


def test_import_all_galaxies_job_imports_from_disk(app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()
        assert Tag.query.filter_by(source="Galaxy").count() == 0

        job = _make_job('import_all_galaxies', admin.id)
        handle_import_all_galaxies(job, app)

        db.session.refresh(job)
        assert job.total > 0
        assert job.done == job.total
        assert Tag.query.filter_by(source="Galaxy").count() > 0
        assert job.logs.count() > 0


def test_import_all_taxonomies_is_idempotent(app):
    """Re-running the job must skip already-imported namespaces, not duplicate them."""
    with app.app_context():
        admin = User.query.filter_by(email="admin@admin.admin").first()

        job1 = _make_job('import_all_taxonomies', admin.id)
        handle_import_all_taxonomies(job1, app)
        count_after_first = Tag.query.filter_by(source="Taxonomy").count()
        assert count_after_first > 0

        job2 = _make_job('import_all_taxonomies', admin.id)
        handle_import_all_taxonomies(job2, app)
        count_after_second = Tag.query.filter_by(source="Taxonomy").count()

        assert count_after_second == count_after_first


def test_import_all_routes_require_admin(client, app):
    with app.app_context():
        _login(client, "neo@admin.admin")

    res = client.post('/tags/admin/import_all_taxonomies')
    assert res.status_code == 403

    res = client.post('/tags/admin/import_all_galaxies')
    assert res.status_code == 403


def test_import_all_routes_queue_job_for_admin(client, app):
    with app.app_context():
        _login(client, "admin@admin.admin")

    res = client.post('/tags/admin/import_all_taxonomies')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["job"]["job_type"] == "import_all_taxonomies"

    res = client.post('/tags/admin/import_all_galaxies')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["job"]["job_type"] == "import_all_galaxies"
