import uuid
import datetime

from flask_login import current_user

from .. import db
from ..db_class.db import *


def add_rule_core(form_dict):
    title = form_dict["title"].strip()

    existing_rule = get_rule_by_title(title)
    if existing_rule:
        return False

    new_rule = Rule(
        format=form_dict["format"],
        title=title,
        license=form_dict["license"],
        description=form_dict["description"],
        uuid=str(uuid.uuid4()),
        source=form_dict["source"],
        # author=form_dict["author"],
        version=form_dict["version"],
        userId=current_user.id,
        creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
        last_modif=datetime.datetime.now(tz=datetime.timezone.utc),
        vote_up=0,
        vote_down=0
    )

    db.session.add(new_rule)
    db.session.commit()
    return True




def delete_rule_core(id):
    rule = get_rule(id)
    if rule:
        db.session.delete(rule)
        db.session.commit()
        return True
    else:
        return False


def edit_rule_core(form_dict, id) -> None:
    """Edit the rule in the DB"""
    rule = get_rule(id)

    rule.format = form_dict["format"]
    rule.title = form_dict["title"]
    rule.license = form_dict["license"]
    rule.description = form_dict["description"]
    rule.source = form_dict["source"]
    rule.version = form_dict["version"]

    db.session.commit()

def increment_up(id):
    rule = get_rule(id)
    rule.vote_up = int(rule.vote_up) + 1
    db.session.commit()


def decrement_up(id):
    rule = get_rule(id)
    rule.vote_down = int(rule.vote_down) + 1
    db.session.commit()



def get_rules_page(page):
    """Return all rules by page"""
    return Rule.query.paginate(page=page, per_page=3, max_per_page=3)

def get_rule(id):
    """Return the rule"""
    return Rule.query.get(id)

def get_rule_by_title(title):
    return Rule.query.filter_by(title=title).all()