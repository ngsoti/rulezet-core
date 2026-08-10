import sys
import os


sys.path.append(os.getcwd())

from app import create_app, db
from app.core.utils.init_db import create_admin_test, create_default_user, create_rule_test, create_user_test
import pytest

@pytest.fixture
def app():
    os.environ.setdefault("FLASKENV", "testing")
    # No test relies on the live background worker, telemetry, update-checker,
    # or sync-schedule threads actually ticking — they call handlers/functions
    # directly and assert DB state synchronously. Leaving them running just
    # means every test process has a worker thread polling the same SQLite
    # file every 2s for the whole suite, which occasionally collides with a
    # test's own write and raises "database is locked" (seen in full-suite
    # runs, never in isolated single-file runs).
    app = create_app(start_worker=False)
    app.config.update({
        "TESTING": True,
        "SERVER_NAME": f"{app.config.get('FLASK_URL')}:{app.config.get('FLASK_PORT')}"
    })
    

    with app.app_context():
        db.drop_all()
        db.create_all()
        create_user_test()
        create_admin_test()
        create_rule_test()
        create_default_user() # for the rule with no author


    yield app

@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()
    

