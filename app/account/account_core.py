from .. import db
from typing import List
from ..db_class.db import User, Role ,User, Role
from ..utils.utils import generate_api_key
# CRUD

# Create

def add_user_core(form_dict) -> User :
    """Add a user to the DB"""
    user = User(
        first_name=form_dict["first_name"],
        last_name=form_dict["last_name"],
        email=form_dict["email"],
        password=form_dict["password"],
        api_key = generate_api_key()
    )
    db.session.add(user)
    db.session.commit()

    return user

# Update

def edit_user_core(form_dict, id) -> None:
    """Edit the user to the DB"""
    user = get_user(id)

    user.first_name=form_dict["first_name"]
    user.last_name=form_dict["last_name"]
    user.email=form_dict["email"]

    db.session.commit()

# Delete
def delete_user_core(id) -> bool:
    """Delete the user to the DB"""
    user = get_user(id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return True
    else:
        return False

# Read



def get_user(id):
    """Return the user"""
    return User.query.get(id)

def get_all_users():
    """Return all users"""
    return User.query.all()

def get_users_page(page):
    """Return all users by page"""
    return User.query.paginate(page=page, per_page=20, max_per_page=50)


def get_user_by_lastname(lastname):
    return User.query.filter_by(last_name=lastname).all()

def get_username_by_id(user_id):
    user = get_user(user_id)
    return user.first_name 
