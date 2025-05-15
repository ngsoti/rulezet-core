import os
import uuid
import random
import string
from ..db_class.db import User

def isUUID(uid):
    try:
        uuid.UUID(str(uid))
        return True
    except ValueError:
        return False

def generate_api_key(length=60):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def get_user_api(api_key):
    """Get a user by its api key"""
    return User.query.filter_by(api_key=api_key).first()

def get_user_from_api(headers):
    """Try to get bot user by matrix id. If not, get basic user"""
    if "MATRIX-ID" in headers:
        bot = User.query.filter_by(last_name="Bot", first_name="Matrix").first()
        if bot:
            if bot.api_key == headers["X-API-KEY"]:
                user = User.query.filter_by(matrix_id=headers["MATRIX-ID"]).first()
                if user:
                    return user
    return get_user_api(headers["X-API-KEY"])


def verif_api_key(headers):
    key = headers.get("X-API-KEY")
    if not key:
        return False
    user = get_user_api(key)
    return user is not None


def create_specific_dir(specific_dir):
    if not os.path.isdir(specific_dir):
        os.mkdir(specific_dir)

def form_to_dict(form):
    """Parse a form into a dict"""
    loc_dict = dict()
    for field in form._fields:
        if field == "files_upload":
            loc_dict[field] = dict()
            loc_dict[field]["data"] = form._fields[field].data
            loc_dict[field]["name"] = form._fields[field].name
        elif not field == "submit" and not field == "csrf_token":
            loc_dict[field] = form._fields[field].data
    return loc_dict