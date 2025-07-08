import datetime
import uuid
from flask_login import current_user
from ..db_class.db import Rule, User, db
from .utils import generate_api_key


############
############

def create_admin():
    # Admin user
    user = User(
        first_name="admin",
        last_name="admin",
        email="admin@admin.admin",
        password="admin",
        admin=True,
        api_key = "admin_api_key"
    )
    db.session.add(user)
    db.session.commit()

def create_default_user():
    user = User(
        first_name="no editor",
        last_name="no editor",
        email="default@default.default",
        password=generate_api_key(),
        admin=False,
        api_key = "aa"
    )
    db.session.add(user)
    db.session.commit()

def create_user_test():
    user = User(
        first_name="Matrix",
        last_name="Bot",
        email="neo@admin.admin",
        password=generate_api_key(),
        api_key = "user_api_key",
    )
    db.session.add(user)
    db.session.commit()

    user2 = User(
        first_name="theo",
        last_name="theo",
        email="t@t.t",
        password="t",
        admin=False,
        api_key = "api_key_user_rule"
    )
    db.session.add(user2)
    db.session.commit()

def create_rule_test():
    editor = User.query.filter_by(email="t@t.t").first()
    if editor :
        rule = Rule(
            format="yara",
            title="test",
            license="test",
            description="test",
            uuid=str(uuid.uuid4()),
            source="test",
            author="test",
            version=1,
            user_id=editor.id,
            creation_date = datetime.datetime.now(tz=datetime.timezone.utc),
            last_modif = datetime.datetime.now(tz=datetime.timezone.utc),
            vote_up=0,
            vote_down=0,
            to_string = " rule test { condition: 1}"
        )
        db.session.add(rule)
        db.session.commit()

