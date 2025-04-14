from ..db_class.db import User, Role, db
from .utils import generate_api_key

def create_admin_role():
    role = Role(
        name = "Admin",
        description = "All rights",
        admin = True,
        read_only = False
    )
    db.session.add(role)
    db.session.commit()
    return role

def create_editor_role():
    role = Role(
        name = "Editor",
        description = "Can edit a lot",
        admin = False,
        read_only = False
    )
    db.session.add(role)
    db.session.commit()

def create_read_only_role():
    role = Role(
        name = "Read Only",
        description = "Can only read",
        admin = False,
        read_only = True
    )
    db.session.add(role)
    db.session.commit()


############
############

def create_admin():
    # Role
    role = create_admin_role()
    create_editor_role()
    create_read_only_role()

    # Admin user
    user = User(
        first_name="admin",
        last_name="admin",
        email="admin@admin.admin",
        password="admin",
        role_id=role.id,
        api_key = generate_api_key()
    )
    db.session.add(user)
    db.session.commit()


def create_user_test():
    # Role
    role = create_admin_role()
    create_editor_role()
    create_read_only_role()

    # Admin user
    user = User(
        first_name="admin",
        last_name="admin",
        email="admin@admin.admin",
        password="admin",
        role_id=role.id,
        api_key = "admin_api_key"
    )
    db.session.add(user)
    db.session.commit()

    user = User(
        first_name="editor",
        last_name="editor",
        email="editor@editor.editor",
        password="editor",
        role_id=2,
        api_key = "editor_api_key"
    )
    db.session.add(user)
    db.session.commit()

    user = User(
        first_name="read",
        last_name="read",
        email="read@read.read",
        password="read",
        role_id=3,
        api_key = "read_api_key"
    )
    db.session.add(user)
    db.session.commit()

