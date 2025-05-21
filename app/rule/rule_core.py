from collections import Counter
import json
import re

import uuid
import datetime
from flask import jsonify
from flask_login import current_user
from jsonschema import  ValidationError, validate
from sqlalchemy import case, or_
import yaml
import yara
from app.account.account_core import get_user
from app.import_github_project.import_github_yara import extract_first_match
from app.import_github_project.untils_import import build_externals_dict, clean_rule_filename_Yara
from .. import db
from ..db_class.db import *
from . import rule_core as RuleModel
from sqlalchemy.orm import joinedload
from ..account import account_core as AccountModel

###################
#   Rule action   #
###################

# CRUD

# Create

def add_rule_core(form_dict , user) -> bool:
    """Add a rule"""
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
    return new_rule

# Delete

def delete_rule_core(id) -> bool:
    """Delete a rule"""
    rule = get_rule(id)
    if rule:
        db.session.delete(rule)
        db.session.commit()
        return True
    else:
        return False

# Update

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

def set_user_id(rule_id, user_id) -> bool:
    """"Set a user id"""
    rule = get_rule(rule_id)
    if rule:
        rule.user_id = user_id
        db.session.commit()  
        return True
    return False

def compile_yara(external_vars, form_dict) -> tuple[bool, dict]:
    """Try to compile a YARA rule with external variables. Return updated form_dict if success."""
    external_vars_temp = external_vars.copy()
    externals = build_externals_dict(external_vars_temp)
    rule_str = form_dict["to_string"]
    while True:
        try:
            yara.compile(source=rule_str, externals=externals)
            form_dict["to_string"] = rule_str
            return True, form_dict , 'no error'
        except yara.SyntaxError as e:

            error_msg = str(e)
            match = re.search(r'undefined identifier "(.*?)"', error_msg)
            if match:
                # try to parse it with the new content
                missing_var = match.group(1)
                external_vars_temp.append({"type": "string", "name": missing_var})
                externals = build_externals_dict(external_vars_temp)
            else:
                return False , form_dict["to_string"] , error_msg

# sync methode 
def load_json_schema_sync(schema_file):
    """
    Load a JSON schema synchronously from a file.
    """
    try:
        with open(schema_file, 'r', encoding='utf-8') as f:
            content = f.read()
            schema = json.loads(content)
        return schema
    except Exception:
        return None


def compile_sigma(form_dict) -> tuple[bool, dict]:
    """
    Try to compile and validate a Sigma rule using JSON Schema.
    
    :param external_vars: Not used here but kept for symmetry with compile_yara
    :param form_dict: Dict containing the Sigma rule in form_dict["to_string"]
    :return: (success: bool, possibly modified form_dict)
    """
    sigma_schema = load_json_schema_sync("app/import_github_project/sigma_format.json")
    rule_string = form_dict['to_string']
    try:
        rule = yaml.safe_load(rule_string)
        if not rule:
            raise ValueError("Empty or invalid YAML structure.")

        rule_json_string = json.dumps(rule, indent=2, default=str)
        rule_json_object = json.loads(rule_json_string)

        validate(instance=rule_json_object, schema=sigma_schema)
        return True, form_dict["to_string"] , 'no error'

    except ValidationError as e:
        error_msg = str(e)
        return False, form_dict["to_string"] , error_msg

    except Exception as e:
        error_msg = str(e)
        return False, form_dict["to_string"] , error_msg

# Read

def get_rules_page(page) -> Rule:
    """Return all rules by page"""
    return Rule.query.paginate(page=page, per_page=20, max_per_page=20)

def get_rules_of_user_with_id(user__id) -> Rule:
    """Get all the rule made by the user (with id)"""
    return Rule.query.filter(Rule.user_id == user__id).all()

def get_rules_of_user_with_id_page(user__id , page) -> Rule:
    """Get all the page rule made by the user (with id)"""
    return Rule.query.filter(Rule.user_id == user__id).paginate(page=page, per_page=20, max_per_page=20)

def get_rules_of_user_with_id_count(user__id) -> int:
    """Return the count of rules"""
    return Rule.query.filter(Rule.user_id == user__id).count()

def get_rule(id) -> int:
    """Return the rule from id"""
    return Rule.query.get(id)

def get_rule_type_count(user_id):
    """Return JSON of the different rule types and total"""
    rules = Rule.query.filter_by(user_id=user_id).all()
    if not rules:
        return jsonify({
            "total": 0,
            "types": {}
        })

    format_counts = {}
    total = 0

    for rule in rules:
        if rule.format:
            fmt = rule.format.strip().upper()
            total += 1
            if fmt in format_counts:
                format_counts[fmt] += 1
            else:
                format_counts[fmt] = 1

    return jsonify({
        "total": total,
        "types": format_counts
    })

    

def get_rule_by_title(title) -> str:
    """Return the rule from the title"""
    return Rule.query.filter_by(title=title).all()

def get_rule_id_by_title(title) -> int:
    """Return the rule ID from the title"""
    rule = Rule.query.filter_by(title=title).first()
    return rule.id if rule else None


def get_total_rules_count() -> int:
    """Return the count of rules"""
    return Rule.query.count()

def get_rule_user_id(rule_id: int) -> int:
    """Return the user id (the user who import or create this rule) of the rule """
    rule = get_rule(rule_id)
    if rule:
        return rule.user_id  
    return None  

def get_last_rules_from_db(limit=10) -> Rule:
    """Get last 10 rules"""
    return Rule.query.order_by(
        case(
            (Rule.creation_date > Rule.last_modif, Rule.creation_date),
            else_=Rule.last_modif
        ).desc()
    ).limit(limit).all()

#################
#   Bad Rule    #
#################

# CRUD

# Update

def save_invalid_rules(bad_rules, rule_type ,repo_url, license) -> None:
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
            file_name=file_name or "invalide rule" ,
            error_message=error_message,
            raw_content=raw_content,
            rule_type=rule_type,
            user_id=current_user.id,
            url=repo_url,
            license=license
        )
        db.session.add(new_invalid_rule)
    db.session.commit()

def save_invalid_rule(form_dict, to_string ,rule_type, error) -> None:
    """
    Save an invalid rule to the database if not already existing.
    
    :param form_dict: Dict containing at least 'title', 'to_string' (content), 'error' and optionally 'url' and 'license'
    :param rule_type: Type of the rule (e.g., 'YARA', 'SIGMA')
    """
    file_name = str(form_dict["title"]) 
    error_message = str(error)
    raw_content = str(to_string)
    repo_url = str(form_dict["source"])
    license = str(form_dict["license"])
    existing = InvalidRuleModel.query.filter_by(
        file_name=file_name,
        error_message=error_message,
        raw_content=raw_content,
        rule_type=rule_type,
        user_id=current_user.id
    ).first()
    if existing:
        return

    new_invalid_rule = InvalidRuleModel(
        file_name=file_name or "invalide rule"+current_user.id ,
        error_message=error_message,
        raw_content=raw_content,
        rule_type=rule_type,
        user_id=current_user.id,
        url=repo_url,
        license=license
    )

    db.session.add(new_invalid_rule)
    db.session.commit()

# Create

def process_and_import_fixed_rule(bad_rule_obj, raw_content) :
    """Process the bad rule and the new content to attempt to create the rule"""
    try:
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

        else:  # Sigma or other types
            rule = yaml.safe_load(raw_content)
            rule_json = json.loads(json.dumps(rule, indent=2, default=str))
            schema = None
            try:
                # Load schema synchronously here
                with open("app/import_github_project/sigma_format.json", 'r', encoding='utf-8') as f:
                    schema = json.load(f)
                validate(instance=rule_json, schema=schema)
            except (ValidationError, FileNotFoundError) as e:
                return False, str(e)

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

        success = RuleModel.add_rule_core(rule_dict, current_user)
        if success:
            db.session.delete(bad_rule_obj)
            db.session.commit()
            return True, ""

        return False, "Rule already exists or failed to insert."

    except Exception as e:
        db.session.rollback()
        return False, str(e)



# def process_and_import_fixed_rule(bad_rule_obj, raw_content) -> bool:
#     """Porcess the bad rule and the new content to attempt to create the rule"""
#     try:
#         rule_type = bad_rule_obj.rule_type 

#         if rule_type.upper() == "YARA":
#             try:
#                 yara.compile(source=raw_content)
#             except yara.SyntaxError as e:
#                 return False, str(e)

#             title = extract_first_match(raw_content, ["title", "Title"]) or clean_rule_filename_Yara(bad_rule_obj.file_name)
#             description = extract_first_match(raw_content, ["description", "Description"])
#             license = extract_first_match(raw_content, ["license", "License"]) or bad_rule_obj.license
#             author = extract_first_match(raw_content, ["author", "Author"])
#             version = extract_first_match(raw_content, ["version", "Version"])
#             source_url = bad_rule_obj.url

#             rule_dict = {
#                 "format": "YARA",
#                 "title": title,
#                 "license": license,
#                 "description": description,
#                 "source": source_url,
#                 "version": version or "1.0",
#                 "author": author or "Unknown",
#                 "to_string": raw_content
#             }
#         # elif rule_type.upper() == "Sigma":
#         else: 
#             rule = yaml.safe_load(raw_content)
#             rule_json = json.loads(json.dumps(rule, indent=2, default=str))
#             schema = load_json_schema("app/import_github_project/sigma_format.json")
#             validate(instance=rule_json, schema=schema)

#             rule_dict = {
#                 "format": "Sigma",
#                 "title": rule.get("title", "Untitled"),
#                 "license": rule.get("license", bad_rule_obj.license),
#                 "description": rule.get("description", "No description provided"),
#                 "source": bad_rule_obj.url,
#                 "version": rule.get("version", "1.0"),
#                 "author": rule.get("author", "Unknown"),
#                 "to_string": raw_content
#             }
#         success = RuleModel.add_rule_core(rule_dict , current_user)
#         if success:
#             db.session.delete(bad_rule_obj)
#             db.session.commit()
#             return True, False

#         return False, "Rule already exists or failed to insert."
#     except Exception as e:
#         db.session.rollback()
#         return False, str(e)


# Read

def get_bad_rules_page(page, per_page=20) -> InvalidRuleModel:
    """
    Returns paginated invalid rules. If current user is admin, returns all.
    Otherwise, returns only the current user's invalid rules.
    """
    query = InvalidRuleModel.query.order_by(InvalidRuleModel.created_at.desc())
    if not current_user.is_admin():
        query = query.filter_by(user_id=current_user.id)
    return query.paginate(page=page, per_page=per_page, error_out=False)

def get_invalid_rule_by_id(rule_id) -> Rule:
    """Retrieve an invalid rule by its ID or abort with 404."""
    rule = InvalidRuleModel.query.get(rule_id)
    if not rule:
        return None
    return rule

def get_user_id_of_bad_rule(rule_id) -> id:
    """Get the user id of a bad rule with his id"""
    rule = InvalidRuleModel.query.get(rule_id)
    return rule.user_id

def get_count_bad_rules_page() -> int:
    """Return the count of bad rules"""
    return InvalidRuleModel.query.count()

def get_bad_rule_with_url(url) -> InvalidRuleModel:
    """Return all the bad rule with this url"""
    return(InvalidRuleModel.query.filter_by(url=url).all())

# Delete

def delete_bad_rule(rule_id) -> bool:
    """Delete a bad rule"""
    rule = get_invalid_rule_by_id(rule_id)
    if rule:
        db.session.delete(rule)
        db.session.commit()
        return True
    else:
        return False
    


def delete_bad_rule_from_url(url: str, current_user_id: int) -> bool:
    """
    Delete all InvalidRuleModel entries with the given URL
    only if they belong to the current user.
    """
    try:
        rules_to_delete = get_bad_rule_with_url(url)
        deleted = False

        for rule in rules_to_delete:
            if rule.user_id == current_user_id:
                db.session.delete(rule)
                deleted = True 

        if deleted:
            db.session.commit()
            return True
        else:
            db.session.rollback()
            return False
    except Exception as e:
        db.session.rollback()
        return False


#################
#   Owner Rule  #
#################

def get_rules_page_owner(page) -> Rule:
    """Return all owner rules by page where the user_id matches the current logged-in user"""
    return Rule.query.filter_by(user_id=current_user.id).paginate(page=page, per_page=20, max_per_page=20)

def get_total_rules_count_owner() -> int:
    """Return the total count of rules created by the current logged-in user"""
    return Rule.query.filter_by(user_id=current_user.id).count()

def give_all_right_to_admin(rules) -> None:
    """give all right for admin for each rule"""
    id_default =  AccountModel.get_default_user()
    for rule in rules:
        rule.user_id = id_default.id   
    db.session.commit()

#####################
#   Favorite rule   #
#####################

def get_rules_page_favorite(page, id_user, per_page=20) -> Rule:
    """Get all the favorite rule of a user"""
    favorites_query = Rule.query\
        .join(RuleFavoriteUser, Rule.id == RuleFavoriteUser.rule_id)\
        .filter(RuleFavoriteUser.user_id == id_user)\
        .order_by(RuleFavoriteUser.created_at.desc())
    return favorites_query.paginate(page=page, per_page=per_page, error_out=False)




#########################
#   Propose edit rule   #
#########################

# CRUD

# Create

def propose_edit_core(rule_id, proposed_content, message=None) -> bool:
    """create an issue for a rule"""
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

# Read
##################################__User__##################################################

def get_rules_edit_propose_page(page) -> RuleEditProposal:
    """Return all rule proposals where the original rule belongs to current user (simple join version)"""
    return RuleEditProposal.query.join(RuleEditProposal.rule).filter(
        Rule.user_id == current_user.id,
        RuleEditProposal.status != 'pending'
    ).paginate(
        page=page,
        per_page=2,
        max_per_page=2
    )

def get_rules_edit_propose_page_pending(page) -> RuleEditProposal:
    """Return all pending rule proposals where the original rule belongs to current user"""
    return RuleEditProposal.query.join(Rule).filter(
        Rule.user_id == current_user.id,
        RuleEditProposal.status == 'pending'
    ).options(joinedload(RuleEditProposal.rule)).paginate(
        page=page,
        per_page=2,
        max_per_page=2
    )

##################################__Admin__##################################################

def get_rules_edit_propose_page_admin(page) -> RuleEditProposal:
    """Return all rule proposals where the original rule belongs to current user (simple join version)"""
    return RuleEditProposal.query.filter(
        RuleEditProposal.status != 'pending'
    ).paginate(
        page=page,
        per_page=20,
        max_per_page=20
    )



def get_rules_edit_propose_page_pending_admin(page) -> RuleEditProposal:
    """Return all pending rule edit proposals (admin view, no user filter)"""
    return RuleEditProposal.query.filter(
        RuleEditProposal.status == 'pending'
    ).paginate(
        page=page,
        per_page=20,
        max_per_page=20
    )


def get_all_rules_edit_propose_page(page , rule_id) -> RuleEditProposal:
    """Return all rule edit proposals"""
    return RuleEditProposal.query.join(RuleEditProposal.rule).filter(
        RuleEditProposal.rule_id == rule_id
    ).paginate(
        page=page,
        per_page=20,
        max_per_page=20
    )

def get_rules_edits_propose_page_old_total_admin() -> int:
    """Get the count of rules not in 'pending' status (e.g., validated or rejected proposals)"""
    return RuleEditProposal.query.filter(RuleEditProposal.status != "pending").count()


def get_rule_proposal(id) -> RuleEditProposal:
    """Return the rule"""
    return RuleEditProposal.query.get(id)

def get_rule_proposal_user_id(proposal_id) -> id:
    """Get the user id of a proposal"""
    rule_proposal = get_rule_proposal(proposal_id)
    return rule_proposal.user_id

def get_all_rules_edit_propose_user_part_from_page(page, user_id, per_page=10)-> RuleEditProposal:
        """Get all the rule edit porposal where the current user has part of """

        commented_ids = db.session.query(RuleEditComment.proposal_id)\
            .filter(RuleEditComment.user_id == user_id)\
            .distinct()

        pagination = RuleEditProposal.query\
            .filter(
                or_(
                    RuleEditProposal.user_id == user_id,
                    RuleEditProposal.id.in_(commented_ids)
                )
            )\
            .order_by(RuleEditProposal.timestamp.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)

        return pagination

# Update

def set_to_string_rule(rule_id, proposed_content) -> json:
    """Set a new content to the rule"""
    rule = Rule.query.get(rule_id)
    if not rule:
        return {"message": "Rule not found"}, 404

    rule.to_string = proposed_content  
    db.session.commit()
    return {"message": "Rule updated successfully"}, 200
    
def set_status(proposal_id, status) -> json:
    """Set the statue of an edit request"""
    if status not in ['accepted', 'rejected']:
        return {'error': 'Statut invalide'}, 400
    proposal = RuleEditProposal.query.get(proposal_id)
    if not proposal:
        return {'error': 'Proposition non trouvée'}, 404
    proposal.status = status
    db.session.commit()
    return {'success': True, 'new_status': status}, 200

##############
#   discuss  #
##############


def get_comments_by_proposal_id(proposal_id) -> RuleEditComment:
    """Get all the discuss"""
    return RuleEditComment.query \
        .filter_by(proposal_id=proposal_id) \
        .order_by(RuleEditComment.created_at.asc()) \
        .all()

def create_comment_discuss(proposal_id, user_id, content) -> RuleEditComment:
        """Create a new comment in the discuss"""
        new_comment = RuleEditComment(
            proposal_id=proposal_id,
            user_id=user_id,
            content=content
        )
        db.session.add(new_comment)
        db.session.commit()
        return new_comment

def delete_comment_discuss(comment_id, user_id) -> bool:
        """Delete a comment in the discuss"""
        comment = RuleEditComment.query.get(comment_id)
        if comment and comment.user_id == user_id:
            db.session.delete(comment)
            db.session.commit()
            return True
        return False

####################
#   Vote section   #
####################

# CRUD

# Read

def has_already_vote(rule_id, user_id) -> bool:
    """Test if an user has ever vote"""
    vote =  RuleVote.query.filter_by(rule_id=rule_id, user_id=user_id).first()
    if vote:
        return True , vote.vote_type
    return False , None

def has_voted(vote,rule_id , id) -> bool:
    """Set a vote"""
    user_id = id or current_user.id
    vote = RuleVote(rule_id=rule_id, user_id=user_id, vote_type=vote)
    db.session.add(vote)    
    db.session.commit()
    return True

# Update

def increment_up(id) -> None:
    """Increment the like section"""
    rule = get_rule(id)
    rule.vote_up = rule.vote_up + 1
    db.session.commit()

def decrement_up(id) -> None:
    """Increment the dislike section"""
    rule = get_rule(id)
    rule.vote_down = rule.vote_down + 1
    db.session.commit()

def remove_one_to_increment_up(id) -> None:
    """Decrement the dislike section"""
    rule = get_rule(id)
    rule.vote_up = rule.vote_up - 1
    db.session.commit()

def remove_one_to_decrement_up(id) -> None:
    """Decrement the dislike section"""
    rule = get_rule(id)
    rule.vote_down = rule.vote_down - 1
    db.session.commit()

# Remove

def remove_has_voted(vote, rule_id , id) -> bool:
    """Remove a vote"""
    user_id = id or current_user.id
    existing_vote = RuleVote.query.filter_by(rule_id=rule_id, user_id=user_id, vote_type=vote).first()
    if existing_vote:
        db.session.delete(existing_vote)
        db.session.commit()
        return True 
    return False 

#############
#   Filter  #
#############

def filter_rules(search=None, author=None, sort_by=None, rule_type=None) -> Rule:
    """Filter the rules"""
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

def filter_rules_owner(search=None, author=None, sort_by=None, rule_type=None) -> Rule:
    """Filter the rules"""
    query = Rule.query.filter_by(user_id=current_user.id)
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

def get_filtered_bad_rules_query(search=None) -> InvalidRuleModel:
    """Return a SQLAlchemy query for filtered bad rules belonging to the current user."""
    query = InvalidRuleModel.query.filter_by(user_id=current_user.id)

    if search:
        search_pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                InvalidRuleModel.file_name.ilike(search_pattern),
                InvalidRuleModel.error_message.ilike(search_pattern),
                InvalidRuleModel.raw_content.ilike(search_pattern),
                InvalidRuleModel.url.ilike(search_pattern)
            )
        )

    return query.order_by(InvalidRuleModel.created_at.desc())

############################
#   Owner Request section  #
############################

def get_total_change_to_check() -> int:
    """Return the count of pending RuleEdit proposals for rules owned by current user."""
    return RuleEditProposal.query.join(Rule, RuleEditProposal.rule_id == Rule.id) \
        .filter(
            Rule.user_id == current_user.id,
            RuleEditProposal.status == "pending"
        ).count()

def get_total_change_to_check_admin() -> int:
    """Return the total count of all pending rule edit proposals (for admins)."""
    return RuleEditProposal.query.filter_by(status="pending").count()

########################
#    Comment section   #
########################

# CRUD

# Create

def add_comment_core(rule_id, content , user) -> tuple[bool, str, User]:
    """Add a new comment to a rule"""
    if not content.strip():
        return False, "Comment cannot be empty."

    comment = Comment(
        rule_id=rule_id,
        user_id=user.id or current_user.id,
        user_name=current_user.first_name,
        content=content.strip(),
        created_at=datetime.datetime.now(tz=datetime.timezone.utc),
        updated_at=datetime.datetime.now(tz=datetime.timezone.utc)
    )
    db.session.add(comment)
    db.session.commit()
    return True, "Comment posted successfully."

# Read

def get_comment_by_id(comment_id) -> Comment | None:
    """Get a comment by its ID"""
    return Comment.query.get(comment_id)

def get_comments_for_rule(rule_id) -> list[Comment]:
    """Get all comments for a rule"""
    return Comment.query.filter_by(rule_id=rule_id).order_by(Comment.created_at.desc()).all()

def get_username_comment(comment_id) -> str:
    """Get the full name of the comment's author"""
    user = get_user(comment_id)
    return f"{user.first_name} {user.last_name}"

def get_comment_page(page, rule_id) -> object:
    """Get paginated comments for a rule"""
    return Comment.query.filter_by(rule_id=rule_id).paginate(page=page, per_page=20, max_per_page=20)

def get_total_comments_count() -> int:
    """Get total number of comments"""
    return Comment.query.count()

def get_latest_comment_for_user_and_rule(user_id: int, rule_id: int) -> Comment | None:
    """Get the most recent comment by a user for a rule"""
    return Comment.query\
        .filter_by(user_id=user_id, rule_id=rule_id)\
        .order_by(Comment.id.desc())\
        .first()

# Update

def update_comment(comment_id, new_content) -> Comment | None:
    """Update content of a comment"""
    comment = get_comment_by_id(comment_id)
    if comment:
        comment.content = new_content
        db.session.commit()
    return comment

# Delete

def delete_comment(comment_id) -> bool:
    """Delete a comment by its ID"""
    comment = get_comment_by_id(comment_id)
    if comment:
        db.session.delete(comment)
        db.session.commit()
        return True
    return False

###################
#   contributor   #
###################

# CRUD

# Create

def create_contribution(user_id, proposal_id) -> bool:
    """Add a user to the contributor"""
    if not user_id or not proposal_id:
        return False 

    rule_id = get_rule_id_with_edit_disccuss(proposal_id)
    contribution = RuleEditContribution(user_id=user_id, proposal_id=proposal_id , rule_id=rule_id)
    db.session.add(contribution)
    db.session.commit()
    return True , contribution

# Read

def get_rule_id_with_edit_disccuss(proposal_id)-> id:
    """Get the id of the reel rule"""
    rule = get_rule_proposal(proposal_id)
    return rule.rule_id

def get_all_contributions() -> RuleEditContribution:
    """Get all the contributor"""
    return RuleEditContribution.query.all()


def get_contribution_by_id(contribution_id) -> RuleEditContribution:
    """Get a contributor with id"""
    return RuleEditContribution.query.get(contribution_id)

def get_all_contributions_with_rule_id(rule_id) -> list:
    """
    Get all unique contributors for a given rule_id.
    """
    contributions = (
        RuleEditContribution.query
        .filter(RuleEditContribution.rule_id == rule_id)
        .all()
    )
    users_id = []
    seen_user_ids = set()
    for contribution in contributions:
        if contribution.user_id not in seen_user_ids:
            seen_user_ids.add(contribution.user_id)
            users_id.append(contribution)
    return users_id

# Update

def update_contribution(contribution_id, user_id=None, proposal_id=None , rule_id=None) -> RuleEditContribution:
    """Update a contributor"""
    contribution = RuleEditContribution.query.get(contribution_id)
    if not contribution:
        return None

    if user_id:
        contribution.user_id = user_id
    if proposal_id:
        contribution.proposal_id = proposal_id
    if rule_id:
        contribution.rule_id = rule_id

    db.session.commit()
    return contribution

# Delete

def delete_contribution(contribution_id)-> bool:
    """Delete a contributor"""
    contribution = RuleEditContribution.query.get(contribution_id)
    if not contribution:
        return False

    db.session.delete(contribution)
    db.session.commit()
    return True
