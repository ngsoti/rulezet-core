import datetime
import uuid
from flask_login import current_user

from app.account.account_core import get_admin_user
from ..db_class.db import FormatRule, Rule, User, db
from .utils import generate_api_key


############
############

def create_admin():
    # Admin user
    raw_password = generate_api_key()
    user = User(
        first_name="admin",
        last_name="admin",
        email="admin@admin.admin",
        password= raw_password,  #"admin",
        admin=True,
        api_key = generate_api_key() #for test  "admin_api_key"
    )
    db.session.add(user)
    db.session.commit()
    return user , raw_password

def create_default_user():
    user = User(
        first_name="no editor",
        last_name="no editor",
        email="default@default.default",
        password= generate_api_key(),
        admin=False,
        api_key = generate_api_key() # "aa"
    )
    db.session.add(user)
    db.session.commit()
    return user

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


def insert_default_formats():
    formats = [
        {"name": "yara", "can_be_execute": True},
        {"name": "sigma", "can_be_execute": True},
        {"name": "zeek", "can_be_execute": False},
        {"name": "suricata", "can_be_execute": False},
        {"name": "test", "can_be_execute": False},
    ]

    user_admin = get_admin_user()
    for fmt in formats:
        existing = FormatRule.query.filter_by(name=fmt["name"]).first()
        if not existing:
            new_format = FormatRule(
                user_id = user_admin.id,
                name=fmt["name"],
                can_be_execute=fmt["can_be_execute"],
                creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
            )
            db.session.add(new_format)

    db.session.commit()


# def create_rule_test():
#     editor = User.query.filter_by(email="t@t.t").first()
#     if editor :
#         rule = Rule(
#             format="yara",
#             title="test",
#             license="test",
#             description="test",
#             uuid=str(uuid.uuid4()),
#             source="test",
#             author="test",
#             version=1,
#             user_id=editor.id,
#             creation_date = datetime.datetime.now(tz=datetime.timezone.utc),
#             last_modif = datetime.datetime.now(tz=datetime.timezone.utc),
#             vote_up=0,
#             vote_down=0,
#             to_string = " rule test { condition: 1}"
#         )
#         db.session.add(rule)
#         db.session.commit()

