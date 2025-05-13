from ..db_class.db import User, db
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
        api_key = generate_api_key()
    )
    db.session.add(user)
    db.session.commit()


def create_user_test():
    # Admin user
    user1 = User(
        first_name="theo",
        last_name="theo",
        email="t@t.t",
        password="t",
        admin=True,
        api_key = generate_api_key()
    )
    db.session.add(user1)
    db.session.commit()

    user = User(
        first_name="editor",
        last_name="editor",
        email="editor@editor.editor",
        password="editor",
        admin=False,
        api_key = "editor_api_key"
    )
    db.session.add(user)
    db.session.commit()

    user = User(
        first_name="read",
        last_name="read",
        email="read@read.read",
        password="read",
        admin=False,
        api_key = "read_api_key"
    )
    db.session.add(user)
    db.session.commit()

