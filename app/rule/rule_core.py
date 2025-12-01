
import json
from typing import Any, Dict, List, Optional, Tuple
import uuid
import datetime
from typing import List
from sqlalchemy.exc import SQLAlchemyError
from flask import jsonify
from flask_login import current_user
from sqlalchemy import case, or_
from sqlalchemy.orm import joinedload

from .. import db
from ..db_class.db import *

from ..account import account_core as AccountModel

###################
#   Rule action   #
###################

# CRUD

# Create
def add_rule_core(form_dict, user) -> bool:
    """
    Add a rule safely with error handling.

    Rules handling logic:
    - If a rule with the same title AND same to_string AND same original_uuid already exists → do not add (it's an update of the same rule).
    - If title + to_string match but original_uuid is different → it's considered a different rule, allow insertion.
    - Otherwise → insert as a new rule.
    """
    try:
        title = form_dict["title"].strip()
        new_to_string = form_dict.get("to_string", "").strip()
        new_original_uuid = str(form_dict.get("original_uuid") or "").strip()  # Normalize to string

        existing_rules = get_rule_by_title(title)

        if existing_rules:
            for r in existing_rules:
                # Normalize stored UUID for comparison
                
                existing_original_uuid = str(r.original_uuid or "").strip()

                # Case 1: Same content and same original UUID → update case, skip
                if r.to_string == new_to_string and existing_original_uuid == new_original_uuid:
                    return False

                # Case 2: Same content but different original UUID → allow as new rule
                if r.to_string == new_to_string and existing_original_uuid != new_original_uuid:
                    break  # continue to insertion

        # Identify user
        if current_user and current_user.is_authenticated:
            user_id = current_user.id
        else:
            user_id = user.id if user else None

        if form_dict.get("cve_id") == "None":
            form_dict["cve_id"] = None
        # Create the new rule
        new_rule = Rule(
            format=form_dict["format"],
            title=title,
            license=form_dict.get("license", "unknown"),
            description=form_dict.get("description", ""),
            uuid=str(uuid.uuid4()),
            original_uuid=new_original_uuid,
            source=form_dict.get("source"),
            author=form_dict.get("author"),
            version=form_dict.get("version", "1.0"),
            user_id=user_id,
            creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
            last_modif=datetime.datetime.now(tz=datetime.timezone.utc),
            vote_up=0,
            vote_down=0,
            to_string=new_to_string,
            cve_id=form_dict.get("cve_id") or None,
        )

        db.session.add(new_rule)
        db.session.commit()
        return new_rule

    except Exception as e:
        return False

def rule_exists(Metadata: dict) -> tuple[bool, int]:
    """
    Check if a rule already exists.
    - If no original_uuid is provided: check by title.
    - If original_uuid is provided: check by original_uuid.
    """
    original_uuid = str(Metadata.get("original_uuid") or "").strip()
    if original_uuid.lower() == "none":
        original_uuid = ""

    title = Metadata.get("title", "").strip()
    to_string = Metadata.get("to_string", "").strip()

    existing_rules = get_rule_by_title(title)

    if not existing_rules:
        return False, None

    for r in existing_rules:
        # Case 1 : without original_uuid → compare title only
        if not original_uuid:
            if r.title.strip() == title:
                return True, r.id

        # Case 2 : with original_uuid → compare both original_uuid and title
        else:
            if str(r.original_uuid or "").strip() == original_uuid:
                return True, r.id

    return False, None

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

def edit_rule_core(form_dict, id) -> tuple[bool,Rule]:
    """Edit the rule in the DB"""
    rule = get_rule(id)

    rule.format = form_dict["format"]
    rule.title = form_dict["title"]
    rule.license = form_dict["license"]
    rule.description = form_dict["description"]
    rule.source = form_dict["source"]
    rule.version = form_dict["version"]
    rule.to_string = form_dict["to_string"]
    rule.cve_id = form_dict["cve_id"]
    rule.last_modif = datetime.datetime.now(tz=datetime.timezone.utc)

    db.session.commit()
    return True , rule


# Read

def get_rule_history_count(rule_id) -> int:
    """Get the count of reports for a specific rule"""
    return  RuleUpdateHistory.query.filter(
        RuleUpdateHistory.rule_id == rule_id,
        RuleUpdateHistory.message == "accepted"
    ).count()

from urllib.parse import urlparse

def is_valid_github_url(url: str) -> bool:
    """
    Check if a URL is a valid GitHub URL.
    """
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and 'github.com' in parsed.netloc
    except Exception:
        return False

def get_sources_from_ids(rule_ids: List[int]) -> List[str]:
    """
    Given a list of rule IDs, retrieve the 'source' for each rule from the DB,
    but only if the source is a valid GitHub URL and not already added.
    Returns a deduplicated list of sources.
    """
    if not rule_ids:
        return []

    # Récupère toutes les règles d'un seul coup
    rules = Rule.query.filter(Rule.id.in_(rule_ids)).all()

    sources = []
    seen_sources = set()

    for rule in rules:
        src = rule.source
        if src and src not in seen_sources and is_valid_github_url(src):
            sources.append(src)
            seen_sources.add(src)

    return sources

def get_sources_from_ids(rules_list: List[dict]) -> List[str]:
    """
    Given a list of dicts containing 'id', retrieve the 'source' from the DB for each rule,
    but only if the id is unique in the DB and the source has not already been added.
    Returns a deduplicated list of sources.
    """
    sources = []

    for rule_id in rules_list:
        
            
        count = Rule.query.filter_by(id=rule_id).count()

        if count == 1:
            rule = Rule.query.filter_by(id=rule_id).first()
            if rule.source not in sources:
                sources.append(rule.source)

    return sources

def get_rules() -> Rule:
    """Get all the rules"""
    return Rule.query.all()
def get_rules_page(page) -> Rule:
    """Return all rules by page"""
    return Rule.query.paginate(page=page, per_page=20, max_per_page=20)

def get_rules_of_user_with_id(user_id) -> Rule:
    """Get all the rule made by the user (with id)"""
    return Rule.query.filter(Rule.user_id == user_id).all()

def get_rules_of_user_with_id_page(user_id, page, search, sort_by, rule_type) -> Rule:
    """Get all the page rule made by the user (with id)"""
    query = Rule.query.filter(Rule.user_id == user_id)

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

    if rule_type:
        query = query.filter(Rule.format.ilike(rule_type))  # use ilike for case-insensitive match

    # Sorting
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

    # Pagination
    return query.paginate(page=page, per_page=20, max_per_page=20)

def get_rule(id) -> int:
    """Return the rule from id"""
    return Rule.query.get(id)


def get_similar_rule(rule_id) -> list:
    """Return up to 3 similar rules based on cve_id, title, format, and author."""
    rule = Rule.query.get(rule_id)
    if not rule:
        return []

    filters = [Rule.id != rule.id]  # Exclude the current rule

    similarity_criteria = []

    if rule.cve_id:
        similarity_criteria.append(Rule.cve_id.ilike(f'%{rule.cve_id}%'))
    if rule.title:
        similarity_criteria.append(Rule.title.ilike(f'%{rule.title}%'))
    # if rule.format:
    #     similarity_criteria.append(Rule.format == rule.format)
    if rule.author:
        similarity_criteria.append(Rule.author.ilike(f'%{rule.author}%'))

    # if no similarity criteria are provided, fallback to the last 3 rules
    if not similarity_criteria:
        fallback_rules = Rule.query.filter(Rule.id != rule.id).order_by(Rule.creation_date.desc()).limit(3).all()
        return [r.to_json() for r in fallback_rules]

    # else, filter based on the provided criteria
    similar_rules = Rule.query.filter(
        *filters,
        or_(*similarity_criteria)
    ).order_by(Rule.creation_date.desc()).limit(3).all()

    # complete the list with the last 3 rules if less than 3 similar rules found
    if len(similar_rules) < 3:
        additional_rules = Rule.query.filter(
            Rule.id != rule.id,
            ~Rule.id.in_([r.id for r in similar_rules])
        ).order_by(Rule.creation_date.desc()).limit(3 - len(similar_rules)).all()
        similar_rules += additional_rules

    return [r.to_json() for r in similar_rules]

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

def get_all_editor_from_rules_list(rules):
    """
    Get a list of unique editors (user_id) from a list of rules.
    
    :param rules: A list of Rule objects.
    :return: A list of unique authors.
    """
    return list({rule.user_id for rule in rules if rule.user_id})

def get_rules_by_title(title) -> str:
    """Return the rule from the title"""
    return Rule.query.filter_by(title=title).all()
def get_rule_by_title(title) -> str:
    """Return the rule from the title"""
    return Rule.query.filter_by(title=title).first()

def get_rule_by_source(source_) -> str:
    """Return all the rule from the source"""
    return Rule.query.filter_by(source=source_).all()

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

def get_history_rule(page, rule_id) -> list:
    """Get all the accepted edit history of a rule by its ID, paginated."""
    return RuleEditProposal.query.filter_by(rule_id=rule_id, status="accepted") \
        .filter(RuleEditProposal.old_content.isnot(None)) \
        .order_by(RuleEditProposal.timestamp.desc()) \
        .paginate(page=page, per_page=20, max_per_page=20)

def get_concerned_rules_page(source, page):
    """Return paginated concerned rules for the given page (20 per page)."""
    return Rule.query.filter_by(source=source, user_id=current_user.id).paginate(
        page=page,
        per_page=30,
        max_per_page=30
    )

def get_concerned_rule_count(source):
    """Return paginated concerned rules for the given page (20 per page)."""
    return Rule.query.filter_by(source=source, user_id=current_user.id).count()

def get_concerned_rules_admin_page(source, page, user_id_concerned):
    """Return paginated concerned rules for the given page (20 per page)."""
    return Rule.query.filter_by(source=source, user_id=user_id_concerned).paginate(
        page=page,
        per_page=30,
        max_per_page=30
    )

def get_all_rules_by_user(user_id) -> Rule:
    """Return all rules by user id"""
    return Rule.query.filter_by(user_id=user_id).all()

def get_concerned_rule_admin_count(source, page, user_id_concerned):
    """Return paginated concerned rules for the given page (20 per page)."""
    return Rule.query.filter_by(source=source, user_id=user_id_concerned).count()

def get_concerned_rules(source):
    """Return all the concerned rules"""
    return Rule.query.filter_by(source=source, user_id=current_user.id).all()

def get_concerned_rules_admin(source , user_id_to_send):
    """Return all the concerned rules"""
    return Rule.query.filter_by(source=source, user_id=user_id_to_send).all()

def get_rules_by_ids(rule_ids) -> list:
    """Get all the rules with id"""
    return Rule.query.filter(Rule.id.in_(rule_ids)).all()

def is_valid_github_url(url: str) -> bool:
    """Check if a URL is a valid GitHub URL."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and 'github.com' in parsed.netloc
    except Exception:
        return False

def get_all_rule_update(search=None, rule_type=None, sourceFilter=None) -> List[Rule]:
    """Select all current user's rules with optional filters: search, rule_type, and sourceFilter.
       If no sourceFilter is provided, return only rules with a valid GitHub source.
    """
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

    if rule_type:
        query = query.filter(Rule.format == rule_type)

    if sourceFilter:
        if not sourceFilter.startswith("http"):
            sourceFilter = f"https://github.com/{sourceFilter}"

        query = query.filter(
            or_(
                Rule.source.ilike(f"%{sourceFilter}%"),
                Rule.source.ilike(f"%{sourceFilter}.git%")
            )
        )
    else:
        query = query.filter(Rule.source.isnot(None))
        all_rules = query.all()
        return [rule for rule in all_rules if is_valid_github_url(rule.source)]

    return query.all()

def get_all_rule_sources_by_user():
    """
    Return a list of distinct non-null rule sources for a given user.
    """
    sources = db.session.query(Rule.source)\
        .filter(Rule.user_id == current_user.id)\
        .filter(Rule.source.isnot(None))\
        .distinct().all()

    return [s[0] for s in sources]

#################
#   Bad Rule    #
#################

# CRUD

# Update

def save_invalid_rule(form_dict, to_string ,rule_type, error , user) -> None:
    """
    Save an invalid rule to the database if not already existing.
    
    :param form_dict: Dict containing at least 'title', 'to_string' (content), 'error' and optionally 'url' and 'license'
    :param rule_type: Type of the rule (e.g., 'YARA', 'SIGMA')
    """

    if current_user and current_user.is_authenticated:
        user_id = current_user.id
    else:
        user_id = user.id if user else None

    if form_dict.get("source") is None:
        form_dict["source"] = "Unknown"

    if form_dict.get("license") is None:
        form_dict["license"] = "Unknown"


    file_name = str(form_dict["title"]) 
    error_message = str(error)
    raw_content = str(to_string)
    repo_url = str(form_dict["source"]) or "Unknown"
    license = str(form_dict["license"]) or "Unknown"
    existing = InvalidRuleModel.query.filter_by(
        file_name=file_name,
        error_message=error_message,
        raw_content=raw_content,
        rule_type=rule_type,
        user_id= user_id
    ).first()
    if existing:
        return

    new_invalid_rule = InvalidRuleModel(
        file_name=file_name or "invalide rule"+user_id ,
        error_message=error_message,
        raw_content=raw_content,
        rule_type=rule_type,
        user_id= user_id,
        url=repo_url,
        license=license
    )

    db.session.add(new_invalid_rule)
    db.session.commit()

def save_invalid_rule_from_new_rule(new_rule_obj: 'NewRule', user: 'User') -> Tuple[Optional['InvalidRuleModel'], Optional[str]]:
    """
    Creates or retrieves an InvalidRuleModel object from NewRule data, using global db session.

    This function handles data persistence, checking for existing invalid rules,
    and database exception management.

    :param new_rule_obj: The instance of the temporary rule (NewRule) to process.
    :param user: The user triggering the action (User object).
    :return: A tuple (InvalidRuleModel object, None) on success, 
             or (None, error_message) on DB or unexpected failure.
    """
    
    # --- 1. Data Preparation ---
    
    user_id = user.id
    
    # Use data from the NewRule object
    file_name = new_rule_obj.name_rule
    error_message = new_rule_obj.message or "Syntax error during update process."
    raw_content = new_rule_obj.rule_content
    # Use 'format' attribute from NewRule (assuming it was added in the migration)
    rule_type = getattr(new_rule_obj, 'format', 'Unknown') or "Unknown"
    
    # Context fields (using getattr for safe access if NewRule lacks these)
    repo_url = getattr(new_rule_obj, 'source', 'Update Process')
    license_name = getattr(new_rule_obj, 'license', 'Unknown')
    
    try:
        # --- 2. Check for Existing Invalid Rule (Prevent Duplicates) ---
        
        existing = InvalidRuleModel.query.filter_by(
            file_name=file_name,
            error_message=error_message,
            raw_content=raw_content,
            rule_type=rule_type,
            user_id=user_id
        ).first()
        
        if existing:
            # The invalid rule already exists in the correction table
            return existing, None

        # --- 3. Create and Save New Invalid Rule ---
        
        new_invalid_rule = InvalidRuleModel(
            user_id=user_id,
            file_name=file_name,
            error_message=error_message,
            raw_content=raw_content,
            rule_type=rule_type,
            url=repo_url,
            license=license_name,
            created_at=datetime.datetime.now(tz=datetime.timezone.utc)
        )
        
        db.session.add(new_invalid_rule)
        
        # Optional: Delete the temporary NewRule entry
        # db.session.delete(new_rule_obj) 
        
        db.session.commit()
        
        return new_invalid_rule, None
    
    except SQLAlchemyError as e:
        db.session.rollback()
        # Return the original database error message
        return None, f"Database error during correction save: {e.orig}"
        
    except Exception as e:
        # Handle any other non-DB exceptions
        db.session.rollback()
        return None, f"Unexpected error during save: {e}"

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
    return rule

def get_all_bad_rule_user(user_id: int) -> list:
    """Get all the invalid (bad) rules of a specific user"""
    bad_rules = InvalidRuleModel.query.filter_by(user_id=user_id).order_by(InvalidRuleModel.created_at.desc()).all()
    return  bad_rules

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

#################
#   Owner Rule  #
#################

def get_rules_page_owner(page) -> Rule:
    """Return all owner rules by page where the user_id matches the current logged-in user"""
    return Rule.query.filter_by(user_id=current_user.id).paginate(page=page, per_page=30, max_per_page=30)

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

def get_rules_page_favorite(page, id_user, search=None, author=None, sort_by=None, rule_type=None):
    """Get paginated favorite rules of a user with optional filters"""
    per_page = 30

    # Base query: select favorite rules for the user
    query = Rule.query\
        .join(RuleFavoriteUser, Rule.id == RuleFavoriteUser.rule_id)\
        .filter(RuleFavoriteUser.user_id == id_user)

    # Apply search filter
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

    # Apply author filter
    if author:
        query = query.filter(Rule.author.ilike(f"%{author.lower()}%"))

    # Apply rule type filter
    if rule_type:
        query = query.filter(Rule.format.ilike(f"%{rule_type.lower()}%"))

    # Apply sorting
    if sort_by == "newest":
        query = query.order_by(Rule.creation_date.desc())
    elif sort_by == "oldest":
        query = query.order_by(Rule.creation_date.asc())
    elif sort_by == "most_likes":
        query = query.order_by(Rule.vote_up.desc())
    elif sort_by == "least_likes":
        query = query.order_by(Rule.vote_down.desc())
    else:
        # Default sort: order by favorite added time (most recent first)
        query = query.order_by(RuleFavoriteUser.created_at.desc())

    return query.paginate(page=page, per_page=per_page, error_out=False)


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

def get_rules_edit_propose_page(page) -> RuleEditProposal:
    """Return all rule proposals where the original rule belongs to current user (simple join version)"""
    return RuleEditProposal.query.join(RuleEditProposal.rule).filter(
        Rule.user_id == current_user.id,
        RuleEditProposal.status != 'pending'
    ).paginate(
        page=page,
        per_page=20,
        max_per_page=20
    )

def get_rules_edit_propose_page_pending(page) -> RuleEditProposal:
    """Return all pending rule proposals where the original rule belongs to current user"""
    return RuleEditProposal.query.join(Rule).filter(
        Rule.user_id == current_user.id,
        RuleEditProposal.status == 'pending'
    ).options(joinedload(RuleEditProposal.rule)).paginate(
        page=page,
        per_page=20,
        max_per_page=20
    )

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
def get_rule_proposal(id) -> RuleEditProposal:
    """Return the rule"""
    return RuleEditProposal.query.get(id)

def get_rule_proposal_user_id(proposal_id) -> id:
    """Get the user id of a proposal"""
    rule_proposal = get_rule_proposal(proposal_id)
    return rule_proposal.user_id

def get_all_rules_edit_propose_user_part_from_page(page, user_id, per_page=30)-> RuleEditProposal:
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
    rule.last_modif = datetime.datetime.now(tz=datetime.timezone.utc)
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
                Rule.to_string.ilike(search_lower),
                Rule.uuid.ilike(search_lower)
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

def filter_rules_owner(search=None, author=None, sort_by=None, rule_type=None , source=None) -> Rule:
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
    if source:    
        query = query.filter(Rule.source.ilike(f"%{source.lower()}%"))
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



def filter_rules_owner_github(search=None, author=None, sort_by=None, rule_type=None, source=None) -> Rule:
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
    
    if source:    
        query = query.filter(Rule.source.ilike(f"%{source.lower()}%"))

    github_patterns = ['%https://github.com/%', '%http://github.com/%', '%github.com/%']
    query = query.filter(
        or_(
            Rule.source.ilike(pattern) for pattern in github_patterns
        )
    )

    # Tri
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
    contribution = RuleEditContribution(user_id=user_id, proposal_id=proposal_id , rule_id=rule_id , created_at=datetime.datetime.now(tz=datetime.timezone.utc))
    db.session.add(contribution)
    db.session.commit()
    return True , contribution

# Read

def get_rule_id_with_edit_disccuss(proposal_id)-> id:
    """Get the id of the reel rule"""
    rule = get_rule_proposal(proposal_id)
    return rule.rule_id
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

#######################
#   Repport section   #
#######################

# CRUD

# Create

def create_repport(user_id, rule_id, message, reason) -> RepportRule:
    """Create a new report, unless an identical one already exists"""

    existing = RepportRule.query.filter_by(
        user_id=user_id,
        rule_id=rule_id,
        message=message,
        reason=reason
    ).first()

    if existing:
        return existing  

    repport = RepportRule(
        user_id=user_id,
        rule_id=rule_id,
        message=message,
        reason=reason,
        created_at=datetime.datetime.now(datetime.timezone.utc)
    )
    db.session.add(repport)
    db.session.commit()
    return repport



# Read 

def get_repported_rule(page) -> RepportRule:
    """Get all the page for reported"""
    return RepportRule.query.paginate(
        page=page,
        per_page=20,
        max_per_page=20
    )

def get_total_repport_to_check_admin() -> int:
    """Get the total count of reports to check (admin view)"""
    return RepportRule.query.count()

def get_repport_by_id(repport_id) -> RepportRule:
    """Read a report by ID"""
    return RepportRule.query.get(repport_id)

# Delete

def delete_report(repport_id) -> bool:
    """Delete a repport"""
    repport = get_repport_by_id(repport_id)
    if not repport:
        return False
    db.session.delete(repport)
    db.session.commit()
    return True

#######################
#   history section   #
#######################

def create_rule_history(data: dict) -> bool:
    """Create a history entry for a rule update, unless it already exists. Returns the created RuleUpdateHistory.id or None if duplicate or error."""
    try:
        rule_id = data.get("id")
        rule_title = data.get("title", "Unknown Title")
        success = data.get("success", False)
        message = data.get("message", "")
        new_content = data.get("new_content", "")
        old_content = data.get("old_content", "")

        rule = get_rule(rule_id)
        if rule:
            if current_user:
                user_id = current_user.id
            else:
                user_id = rule.user_id

        existing_entry = RuleUpdateHistory.query.filter_by(
            rule_id=rule_id,
            rule_title=rule_title,
            success=success,
            message=message,
            new_content=new_content,
            old_content=old_content,
            analyzed_by_user_id=user_id
        ).first()

        if existing_entry:
            return existing_entry.id


        history_entry = RuleUpdateHistory(
            rule_id=rule_id,
            rule_title=rule_title,
            success=success,
            message=message,
            new_content=new_content,
            old_content=old_content,
            analyzed_by_user_id=user_id,
            analyzed_at=datetime.datetime.now(tz=datetime.timezone.utc)
        )

        db.session.add(history_entry)
        db.session.commit()

        return history_entry.id

    except Exception as e:
        db.session.rollback()
        return None


def get_history_rule_by_id(history_id):
    """Return an history for a rule by id"""
    return RuleUpdateHistory.query.get(history_id)


def get_history_rule_(page, rule_id) -> list:
    """Get all the accepted edit history of a rule by its ID, paginated."""
    return RuleUpdateHistory.query.filter(
        RuleUpdateHistory.rule_id == rule_id,
        RuleUpdateHistory.success == True ,
        RuleUpdateHistory.message == "accepted" 
    ).paginate(page=page, per_page=30, max_per_page=30)

def get_old_rule_choice(page) -> list:
    """Get all the old choice to make"""    
    return RuleUpdateHistory.query.filter(
        RuleUpdateHistory.message != "accepted",
        RuleUpdateHistory.message != "rejected",
        RuleUpdateHistory.analyzed_by_user_id == current_user.id
    ).paginate(page=page, per_page=30, max_per_page=30)

def get_update_pending():
    """Get all the schedules with pending updates for the current user"""
    return RuleUpdateHistory.query.filter(
        RuleUpdateHistory.analyzed_by_user_id == current_user.id,
        RuleUpdateHistory.message != 'accepted',
        RuleUpdateHistory.message != 'rejected'
    ).count()

#####################
#   Format rules    #
#####################

def get_all_rule_format():
    """Return all rule formats sorted alphabetically, excluding 'no format'."""
    return (
        FormatRule.query
        .filter(FormatRule.name.ilike('%'))  
        .filter(FormatRule.name != 'no format')
        .order_by(FormatRule.name.asc())
        .all()
    )


def get_all_rule_format_page(page):
    """Get all rule format in page (20 per pages)"""
    return FormatRule.query.paginate(page=page, per_page=20, error_out=False)


def get_rule_format_with_id(id):
    """Get the rule format with id"""
    return FormatRule.query.get(id)

def add_format_rule(format_name: str, user_id: int, can_be_execute: bool) -> tuple[bool, str]:
        """Ajoute un format de règle si non existant.

        Returns:
            (success: bool, message: str)
        """
        existing_format = FormatRule.query.filter_by(name=format_name).first()
        if existing_format:
            return False, "This format name already exists."

        new_format = FormatRule(
            name=format_name.strip(),
            user_id=user_id,
            creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
            can_be_execute=can_be_execute
        )

        db.session.add(new_format)
        db.session.commit()

        return True, "Format created successfully!"

def delete_format(id):
    """Check admin user somewhere before calling this function"""

    format_rule = FormatRule.query.get(id)
    if not format_rule:
        return False

    try:
        db.session.delete(format_rule)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        return False

def get_all_rule_with_this_format(format_name):
    """Get all rules using the given format name (case-insensitive)"""
    return Rule.query.filter(Rule.format.ilike(format_name)).all()

def get_all_format() -> list[dict]:
    """
    Get all rule formats from the database.

    Returns:
        list[dict]: list of formats with their attributes and rule count.
    """
    formats = FormatRule.query.all()
    return [fmt.to_json() for fmt in formats]


def get_all_url_github_page(page: int = 1, search: str = None):
    """Get paginated unique GitHub project URLs from Rule.source and return pagination + total count."""
    github_pattern = r'^https?://(www\.)?github\.com/[\w\-_]+/[\w\-_]+'

    query = Rule.query.filter(Rule.source.isnot(None))

    if search:
        query = query.filter(Rule.source.ilike(f"%{search}%"))

    query = query.filter(Rule.source.op('~')(github_pattern))

    query = query.distinct(Rule.source)

    total_count = query.count()

    pagination = query.paginate(page=page, per_page=20, max_per_page=20)

    return pagination, total_count

def get_rule_count_by_github_page(page: int = 1, search: str = None):
        """Return paginated list of GitHub URLs with how many rules are linked to each."""
        github_pattern = r'^https?://(www\.)?github\.com/[\w\-_]+/[\w\-_]+'

        query = (
            db.session.query(
                Rule.source.label("url"),
                func.count(Rule.id).label("rule_count")
            )
            .filter(Rule.source.isnot(None))
            .filter(Rule.source.op('~')(github_pattern))
        )

        if search:
            query = query.filter(Rule.source.ilike(f"%{search}%"))

        query = query.group_by(Rule.source).order_by(func.count(Rule.id).desc())

        total_count = query.count()
        pagination = query.paginate(page=page, per_page=20, max_per_page=20)

        return pagination, total_count

def get_all_rule_by_url_github_page(page: int = 1, search: str = None, url: str = None):
    """Get paginated list of Rules whose source matches a specific GitHub project URL."""
    
    query = Rule.query.filter(Rule.source.isnot(None))
    
    if url:
        query = query.filter(Rule.source.ilike(f"{url}%"))
    
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (Rule.title.ilike(search_pattern)) |
            (Rule.description.ilike(search_pattern)) |
            (Rule.author.ilike(search_pattern)) |
            (Rule.cve_id.ilike(search_pattern))
        )
    
    query = query.order_by(Rule.last_modif.desc())
    total_count = query.count()
    
    pagination = query.paginate(page=page, per_page=20, max_per_page=20)
    
    return pagination, total_count

def get_all_rule_by_url_github(url: str = None):
    """Get list of Rules whose source contains a specific GitHub project URL."""
    
    query = Rule.query.filter(Rule.source != None)
    
    if url:
        query = query.filter(Rule.source.ilike(f"%{url}%"))
    
    return query.all()


def get_all_rule_by_github_url_page(search: str = None, page: int = 1):
    """Get paginated list of Rules whose source matches a specific GitHub project URL and belong to the current user."""
    per_page = 10

    # Base query: only rules that have a GitHub source and belong to the current user
    query = Rule.query.filter(
        Rule.source.isnot(None),
        Rule.source.ilike("%github.com%"),
        Rule.user_id == current_user.id
    )

    # Optional search filter
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            or_(
                Rule.title.ilike(search_pattern),
                Rule.description.ilike(search_pattern),
                Rule.author.ilike(search_pattern),
                Rule.cve_id.ilike(search_pattern)
            )
        )
    total_count = query.count()
    # Return paginated results
    pagination = query.paginate(page=page, per_page=per_page)
    return pagination, total_count



def exists_format_in_rules(format_name: str) -> bool:
    """
    Check if a format exists in any rule (case-insensitive).
    Returns True if at least one rule has this format, False otherwise.
    """
    return Rule.query.filter(Rule.format == format_name).first() is not None



def replace_rule_format(old_format_name: str, new_format_name: str) -> int:
    """Replace all occurrences of old_format_name with new_format_name in Rule.format.

    Returns:
        int: Number of rules updated.
    """
    rules_to_update = Rule.query.filter(func.lower(Rule.format) == old_format_name.lower()).all()
    count = 0
    for rule in rules_to_update:
        rule.format = new_format_name
        count += 1
    db.session.commit()
    return count


def get_importer_result(sid: str):
    return ImporterResult.query.filter_by(uuid=sid).first()

def get_updater_result(sid: str):
    return UpdateResult.query.filter_by(uuid=sid).first()

def get_updater_result_new_rule_page(sid: str, page: int, per_page: int = 30):
    """
    Retrieve paginated NewRule entries linked to the UpdateResult with UUID = sid
    """
    update_result = UpdateResult.query.filter_by(uuid=sid).first()
    if not update_result:
        return None

    return NewRule.query.filter_by(update_result_id=update_result.id).paginate(
        page=page, per_page=per_page, error_out=False
    )

def get_updater_result_rule_page(sid: str, page: int, per_page: int = 30):
    """
    Retrieve paginated RuleStatus entries linked to the UpdateResult with UUID = sid,
    prioritizing rules that have an update available.
    """
    update_result = UpdateResult.query.filter_by(uuid=sid).first()
    if not update_result:
        return None

    # Prioritize rules with update_available=True, then by date ascending
    return RuleStatus.query.filter_by(update_result_id=update_result.id)\
        .order_by(RuleStatus.update_available.desc(), RuleStatus.date.asc())\
        .paginate(page=page, per_page=per_page, error_out=False)


def get_importer_list_page(page: int = 1):
    return ImporterResult.query.paginate(page=page, per_page=20, max_per_page=20)

def get_updater_list_page(page: int = 1):
    return UpdateResult.query.paginate(page=page, per_page=20, max_per_page=20)
#####################
#   Dump all rules  #
#####################
def parse_datetime(value: Optional[str]) -> Optional[datetime.datetime]:
    if not value:
        return None
    try:
        if "T" in value:
            dt = datetime.datetime.fromisoformat(value)
        elif " " in value:
            dt = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M")
        else:
            dt = datetime.datetime.strptime(value, "%Y-%m-%d")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        return None



def get_arg_filter_dump_rule(data: Dict[str, Any]) -> Dict[str, Any]:
    filters = {}

    def parse_if_needed(val):
        if val is None:
            return None
        if isinstance(val, datetime.datetime):
            return val.isoformat()
        if isinstance(val, str) and "T" in val:
            # Already ISO string, return as-is
            return val
        return parse_datetime(val)

    # --- Dates
    filters["created_after"] = parse_if_needed(data.get("created_after"))
    filters["created_before"] = parse_if_needed(data.get("created_before"))
    filters["updated_after"] = parse_if_needed(data.get("updated_after"))
    filters["updated_before"] = parse_if_needed(data.get("updated_before"))

    # --- Formats
    format_name = data.get("format_name")
    if isinstance(format_name, str):
        filters["format_name"] = None if format_name.lower() == "all" else [format_name]
    elif isinstance(format_name, list):
        lowered = [str(f).lower() for f in format_name]
        filters["format_name"] = None if "all" in lowered else format_name
    else:
        filters["format_name"] = None

    # --- Top liked/disliked
    def safe_int(val):
        try:
            return int(val) if val is not None else None
        except (ValueError, TypeError):
            return None

    filters["top_liked"] = safe_int(data.get("top_liked"))
    filters["top_disliked"] = safe_int(data.get("top_disliked"))

    return filters


def make_json_safe(obj: Any) -> Any:
    """
    Recursively convert datetimes (and dates) to ISO strings so the object
    can be JSON-serialized by Flask/Flask-RESTX.
    Leaves other types intact (primitives, dicts, lists, etc).
    """
    # Datetime / date -> ISO string
    if isinstance(obj, (datetime.datetime, datetime.date)):
        # Prefer full ISO datetime if available
        try:
            # if timezone-aware, isoformat will include it
            return obj.isoformat()
        except Exception:
            return str(obj)

    # dict -> map values
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}

    # list/tuple/set -> list (JSON will want arrays)
    if isinstance(obj, (list, tuple, set)):
        return [make_json_safe(v) for v in obj]

    # Fallback — leave as-is (primitives are fine)
    return obj

def get_all_rules_in_json_dump(data: Dict[str, Any]) -> dict:
    """
    Retrieve all rules applying the provided filters,
    and organize them in a JSON structure suitable for open data analysis.

    Returns:
        dict: JSON dump containing all rules grouped by format, a summary,
              and export metadata.
    """
    filters = get_arg_filter_dump_rule(data)
    query = Rule.query

    # --- Apply format filter
    if filters["format_name"] is not None:
        query = query.filter(Rule.format.in_(filters["format_name"]))
    # --- Apply date filters
    if filters["created_after"]:
        query = query.filter(Rule.creation_date >= filters["created_after"])
    if filters["created_before"]:
        query = query.filter(Rule.creation_date <= filters["created_before"])

    if filters["updated_after"]:
        query = query.filter(Rule.last_modif >= filters["updated_after"])
    if filters["updated_before"]:
        query = query.filter(Rule.last_modif <= filters["updated_before"])

    # --- Apply top liked/disliked filters
    if filters["top_liked"]:
        query = query.order_by(Rule.vote_up.desc()).limit(filters["top_liked"])
    elif filters["top_disliked"]:
        query = query.order_by(Rule.vote_down.desc()).limit(filters["top_disliked"])

    rules = query.all()

    # --- Build JSON dump
    dump = {
        "rules_by_format": {},
        "summary_by_format": {}
    }

    for rule in rules:
        rule_json = rule.to_json()
        fmt = getattr(rule, "format", "unknown")

        dump["rules_by_format"].setdefault(fmt, []).append(rule_json)
        dump["summary_by_format"][fmt] = dump["summary_by_format"].get(fmt, 0) + 1

    dump["summary_by_format"]["total_rules"] = len(rules)

    # --- Export metadata
    dump["export_info"] = {
        "rulezet_version": "1.1",
        "exported_at": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
        "source": "rulezet.org"
    }

    return dump

def get_new_rule(new_rule_id):
    return NewRule.query.get(new_rule_id)