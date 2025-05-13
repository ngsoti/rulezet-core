import sys
import os
sys.path.append(os.getcwd())

from app.db_class.db import User
from app import create_app, db
from app.utils.init_db import create_user_test
import pytest

@pytest.fixture
def app():
    os.environ.setdefault("FLASKENV", "testing")
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SERVER_NAME": f"{app.config.get('FLASK_URL')}:{app.config.get('FLASK_PORT')}"
    })

    with app.app_context():
        db.drop_all()
        db.create_all()
        create_user_test()

    yield app

@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()
    

@pytest.fixture
def new_user(app):  
    with app.app_context():
        other_user = User(
            email="existing@example.com",
            first_name="Existing",
            last_name="User"
        )
        other_user.password = "password"  
        db.session.add(other_user)
        db.session.commit()

        yield other_user

@pytest.fixture
def logged_in_client(client, new_user):  
    client.post("/api/account/register", json={
        "email": "test@example.com",
        "password": "password",
        "first_name": "Test",
        "last_name": "User"
    })
    
    # Connecter l'utilisateur
    response = client.post("/api/account/login", json={
        "email": "test@example.com",
        "password": "password"
    })

    yield client  