import json
import uuid
import datetime

from flask import abort
from flask_login import current_user
from jsonschema import ValidationError, validate
from sqlalchemy import asc, case, desc, func, or_
import yaml

from app.import_github_project.test_Sigma import load_json_schema
from app.import_github_project.test_yara import extract_first_match, extract_metadata_value
from app.import_github_project.untils_import import clean_rule_filename_Yara

from .. import db
from ..db_class.db import *
from . import rule_core as RuleModel



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
        author=form_dict["author"],
        version=form_dict["version"],
        user_id=current_user.id,
        creation_date = datetime.datetime.now(tz=datetime.timezone.utc),
        last_modif = datetime.datetime.now(tz=datetime.timezone.utc),
        vote_up=0,
        vote_down=0,
        to_string = form_dict["to_string"]
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
    rule.to_string = form_dict["to_string"]
    rule.last_modif = datetime.datetime.now(tz=datetime.timezone.utc)

    db.session.commit()

def increment_up(id):
    rule = get_rule(id)
    rule.vote_up = rule.vote_up + 1
    db.session.commit()


def decrement_up(id):
    rule = get_rule(id)
    rule.vote_down = rule.vote_down + 1
    db.session.commit()



def remove_one_to_increment_up(id):
    rule = get_rule(id)
    rule.vote_up = rule.vote_up - 1
    db.session.commit()

def remove_one_to_decrement_up(id):
    rule = get_rule(id)
    rule.vote_down = rule.vote_down - 1
    db.session.commit()



def get_rules_page(page):
    """Return all rules by page"""
    return Rule.query.paginate(page=page, per_page=1000, max_per_page=1700)


def get_bad_rules_page(page=1, per_page=20):
    """
    Returns paginated invalid rules. If current user is admin, returns all.
    Otherwise, returns only the current user's invalid rules.
    """
    query = InvalidRuleModel.query.order_by(InvalidRuleModel.created_at.desc())

    if not current_user.is_admin():
        query = query.filter_by(user_id=current_user.id)

    return query.paginate(page=page, per_page=per_page, error_out=False)



def get_rules_page_owner(page):
    """Return all owner rules by page where the user_id matches the current logged-in user"""
    return Rule.query.filter_by(user_id=current_user.id).paginate(page=page, per_page=1000, max_per_page=1700)

def get_total_rules_count_owner():
    """Return the total count of rules created by the current logged-in user"""
    return Rule.query.filter_by(user_id=current_user.id).count()

def get_rule(id):
    """Return the rule"""
    return Rule.query.get(id)

def get_rule_by_title(title):
    return Rule.query.filter_by(title=title).all()

def get_total_rules_count():
    return Rule.query.count()



def get_rule_user_id(rule_id: int):
    rule = get_rule(rule_id)
    if rule:
        return rule.user_id  
    return None  

def get_rules_page_favorite(page, id_user, per_page=10):
    favorites_query = Rule.query\
        .join(RuleFavoriteUser, Rule.id == RuleFavoriteUser.rule_id)\
        .filter(RuleFavoriteUser.user_id == id_user)\
        .order_by(RuleFavoriteUser.created_at.desc())
    
    return favorites_query.paginate(page=page, per_page=per_page, error_out=False)


def set_user_id(rule_id, user_id):
    rule = get_rule(rule_id)
    if rule:
        rule.user_id = user_id
        db.session.commit()  
        return True
    return False



def propose_edit_core(rule_id, proposed_content, message=None):
    if not proposed_content:
        return False
    rule = get_rule(rule_id)

    new_proposal = RuleEditProposal(
        rule_id=rule_id,
        user_id=current_user.id,
        proposed_content=proposed_content,
        message=message,
        old_content =rule.to_string
    )
    db.session.add(new_proposal)
    db.session.commit()
    return True



# def get_rules_edit_propose_page(page):
#     """Return all rules by page"""
#     return RuleEditProposal.query.paginate(page=page, per_page=60, max_per_page=70)

# def get_rules_edit_propose_page_pending(page):
#     return RuleEditProposal.query.filter_by(status='pending').paginate(
#         page=page,
#         per_page=60,
#         max_per_page=70
#     )

from sqlalchemy.orm import joinedload
def get_rules_edit_propose_page(page):
    """Return all rule proposals where the original rule belongs to current user"""
    return RuleEditProposal.query.join(Rule).filter(
        Rule.user_id == current_user.id
    ).options(joinedload(RuleEditProposal.rule)).paginate(
        page=page,
        per_page=60,
        max_per_page=70
    )

def get_rules_edit_propose_page_pending(page):
    """Return all pending rule proposals where the original rule belongs to current user"""
    return RuleEditProposal.query.join(Rule).filter(
        Rule.user_id == current_user.id,
        RuleEditProposal.status == 'pending'
    ).options(joinedload(RuleEditProposal.rule)).paginate(
        page=page,
        per_page=60,
        max_per_page=70
    )





def get_rules_edit_propose_page_admin(page):
    """Return all rule edit proposals (admin view, no user filter)"""
    return RuleEditProposal.query.options(
        joinedload(RuleEditProposal.rule)
    ).paginate(
        page=page,
        per_page=60,
        max_per_page=70
    )


def get_rules_edit_propose_page_pending_admin(page):
    """Return all pending rule edit proposals (admin view, no user filter)"""
    return RuleEditProposal.query.filter(
        RuleEditProposal.status == 'pending'
    ).options(
        joinedload(RuleEditProposal.rule)
    ).paginate(
        page=page,
        per_page=60,
        max_per_page=70
    )

















def get_rule_proposal(id):
    """Return the rule"""
    return RuleEditProposal.query.get(id)

def set_to_string_rule(rule_id, proposed_content):
    try:
        rule = Rule.query.get(rule_id)
        if not rule:
            return {"message": "Rule not found"}, 404

        rule.to_string = proposed_content  
        db.session.commit()
        return {"message": "Rule updated successfully"}, 200

    except Exception as e:
        db.session.rollback()
        return {"message": "Error updating rule", "error": str(e)}, 500
    
def set_status(proposal_id, status):
    if status not in ['accepted', 'rejected']:
        return {'error': 'Statut invalide'}, 400

    proposal = RuleEditProposal.query.get(proposal_id)

    if not proposal:
        return {'error': 'Proposition non trouvée'}, 404

    proposal.status = status
    db.session.commit()

    return {'success': True, 'new_status': status}, 200



def get_last_rules_from_db(limit=10):
    return Rule.query.order_by(
        case(
            (Rule.creation_date > Rule.last_modif, Rule.creation_date),
            else_=Rule.last_modif
        ).desc()
    ).limit(limit).all()




# vote 

def has_already_vote(rule_id, user_id):
    vote =  RuleVote.query.filter_by(rule_id=rule_id, user_id=user_id).first()
    if vote:
        return True , vote.vote_type
    return False , None

def has_voted(vote,rule_id):
    user_id = current_user.id
    vote = RuleVote(rule_id=rule_id, user_id=user_id, vote_type=vote)
    db.session.add(vote)    
    db.session.commit()
    return True


def remove_has_voted(vote, rule_id):
    user_id = current_user.id
    existing_vote = RuleVote.query.filter_by(rule_id=rule_id, user_id=user_id, vote_type=vote).first()

    if existing_vote:
        db.session.delete(existing_vote)
        db.session.commit()
        return True 

    return False 



def search_rules(user_id, query):
    return Rule.query.filter(
        Rule.user_id == user_id,
        (Rule.title.ilike(f"%{query}%") | 
         Rule.description.ilike(f"%{query}%") |
         Rule.author.ilike(f"%{query}%"))
    ).all()






def filter_rules(user_id, search=None, author=None, sort_by=None, rule_type=None):
    query = Rule.query

    if search:
        search_lower = f"%{search.lower()}%"
        query = query.filter(
            or_(
                Rule.title.ilike(search_lower),
                Rule.description.ilike(search_lower),
                Rule.format.ilike(search_lower),
                Rule.author.ilike(search_lower),
                Rule.to_string.ilike(search_lower)
            )
        )

    if author:
        query = query.filter(Rule.author.ilike(f"%{author.lower()}%"))

    if rule_type:
        query = query.filter(Rule.format.ilike(f"%{rule_type.lower()}%"))  


    if sort_by == "newest":
        query = query.order_by(Rule.creation_date.desc())
    elif sort_by == "oldest":
        query = query.order_by(Rule.creation_date.asc())
    elif sort_by == "most_likes":
        query = query.order_by(Rule.vote_up.desc())
    elif sort_by == "least_likes":
        query = query.order_by(Rule.vote_down.desc())
    else:
        query = query.order_by(Rule.creation_date.desc())

    return query



def get_total_change_to_check():
    """Return the count of pending RuleEdit proposals for rules owned by current user."""
    return RuleEditProposal.query.join(Rule, RuleEditProposal.rule_id == Rule.id) \
        .filter(
            Rule.user_id == current_user.id,
            RuleEditProposal.status == "pending"
        ).count()


def get_total_change_to_check_admin():
    """Return the total count of all pending rule edit proposals (for admins)."""
    return RuleEditProposal.query.filter_by(status="pending").count()


def save_invalid_rules(bad_rules, rule_type ,repo_url, license):
    """
    Save a list of invalid rules to the database if not already existing.
    
    :param bad_rules: List of dicts with 'file', 'error', and optional 'content'
    :param rule_type: Type of the rule, default is 'Sigma'
    """
    for bad_rule in bad_rules:
        file_name = bad_rule.get("file")
        error_message = str(bad_rule.get("error"))
        raw_content = bad_rule.get("content", "")

        existing = InvalidRuleModel.query.filter_by(
            file_name=file_name,
            error_message=error_message,
            raw_content=raw_content,
            rule_type=rule_type,
            user_id=current_user.id
        ).first()

        if existing:
            continue

        new_invalid_rule = InvalidRuleModel(
            file_name=file_name,
            error_message=error_message,
            raw_content=raw_content,
            rule_type=rule_type,
            user_id=current_user.id,
            url=repo_url,
            license=license
        )
        db.session.add(new_invalid_rule)

    db.session.commit()


import yara


def process_and_import_fixed_rule(bad_rule_obj, raw_content):
    
    try:
        print(f"Traitement de la règle invalide : {bad_rule_obj.file_name}")
        rule_type = bad_rule_obj.rule_type 

        if rule_type.upper() == "YARA":
            try:
                yara.compile(source=raw_content)
            except yara.SyntaxError as e:
                return False, str(e)

            title = extract_first_match(raw_content, ["title", "Title"]) or clean_rule_filename_Yara(bad_rule_obj.file_name)
            description = extract_first_match(raw_content, ["description", "Description"])
            license = extract_first_match(raw_content, ["license", "License"]) or bad_rule_obj.license
            author = extract_first_match(raw_content, ["author", "Author"])
            version = extract_first_match(raw_content, ["version", "Version"])
            source_url = bad_rule_obj.url

            rule_dict = {
                "format": "YARA",
                "title": title,
                "license": license,
                "description": description,
                "source": source_url,
                "version": version or "1.0",
                "author": author or "Unknown",
                "to_string": raw_content
            }
        # elif rule_type.upper() == "Sigma":
        else: 
            rule = yaml.safe_load(raw_content)
            rule_json = json.loads(json.dumps(rule, indent=2, default=str))
            schema = load_json_schema("app/import_github_project/sigma_format.json")
            validate(instance=rule_json, schema=schema)

            rule_dict = {
                "format": "Sigma",
                "title": rule.get("title", "Untitled"),
                "license": rule.get("license", bad_rule_obj.license),
                "description": rule.get("description", "No description provided"),
                "source": bad_rule_obj.url,
                "version": rule.get("version", "1.0"),
                "author": rule.get("author", "Unknown"),
                "to_string": raw_content
            }


        success = RuleModel.add_rule_core(rule_dict)
        if success:
            db.session.delete(bad_rule_obj)
            db.session.commit()
            print("Règle corrigée et importée avec succès.")
            return True, False

        return False, "Rule already exists or failed to insert."

    except Exception as e:
        print(f"Erreur pendant le traitement : {e}")
        db.session.rollback()
        return False, str(e)

def get_invalid_rule_by_id(rule_id):
    """Retrieve an invalid rule by its ID or abort with 404."""
    rule = InvalidRuleModel.query.get(rule_id)
    if not rule:
        return None
    return rule

def get_user_id_of_bad_rule(rule_id):
    rule = InvalidRuleModel.query.get(rule_id)
    return rule.user_id


def delete_bad_rule(rule_id):
    rule = get_invalid_rule_by_id(rule_id)
    if rule:
        db.session.delete(rule)
        db.session.commit()
        return True
    else:
        return False



    