
#################
#   Bad Rule    #
#################

# CRUD

# Update

from typing import Optional, Tuple

from flask_login import current_user
from sqlalchemy.exc import SQLAlchemyError
from app.features.rule.rule_core import get_updater_result_by_id
from app import db
from app.core.db_class.db import *

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

    if form_dict.get("github_path") is None:
        form_dict["github_path"] = "None"

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
        license=license,
        github_path=form_dict["github_path"]
    )

    db.session.add(new_invalid_rule)
    db.session.commit()

    return new_invalid_rule.id

def save_invalid_rule_from_new_rule(new_rule_obj: 'NewRule', user: 'User', github_path: str) -> Tuple[Optional['InvalidRuleModel'], Optional[str]]:
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
    
    # Found the updater associated to this rule

    updater = get_updater_result_by_id(new_rule_obj.update_result_id) 
  

    try:
        updater_info = json.loads(updater.info)
        repo_url = updater_info.get('repo_url')
        
        source_info = repo_url
        
    except (json.JSONDecodeError, AttributeError):
        source_info = "Unknown Source from Updater" 


    repo_url = source_info or 'Update Process'
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

def delete_all_bad_rules(filters):
    try:
        query = InvalidRuleModel.query


        if not current_user.is_admin():
            query = query.filter(InvalidRuleModel.user_id == current_user.id)
        elif filters.get('user_id'):
            query = query.filter(InvalidRuleModel.user_id == filters.get('user_id'))

        search = filters.get('search')
        if search:
            search_val = f"%{search}%"
            field = filters.get('search_field')
            if field == 'file_name':
                query = query.filter(InvalidRuleModel.file_name.ilike(search_val))
            elif field == 'error_message':
                query = query.filter(InvalidRuleModel.error_message.ilike(search_val))
            else:
                query = query.filter(db.or_(
                    InvalidRuleModel.file_name.ilike(search_val),
                    InvalidRuleModel.error_message.ilike(search_val)
                ))

        if filters.get('error_messages'):
            query = query.filter(InvalidRuleModel.error_message.in_(filters.get('error_messages').split(',')))
        
        if filters.get('sources'):
            query = query.filter(InvalidRuleModel.url.in_(filters.get('sources').split(',')))

        if filters.get('rule_types'):
            query = query.filter(InvalidRuleModel.rule_type.in_(filters.get('rule_types').split(',')))


        deleted_count = query.delete(synchronize_session=False)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return False

def get_sources_usage(user_id=None):
    query = db.session.query(
        InvalidRuleModel.url,
        db.func.count(InvalidRuleModel.id).label('count')
    ).group_by(InvalidRuleModel.url)
    # flter by user_id
    if user_id:
        query = query.filter(InvalidRuleModel.user_id == user_id)
    
    results = query.all()
    sources = [{'name': url, 'count': count} for url, count in results]
    return sources

def get_error_messages_usage(user_id=None):
    query = db.session.query(
        InvalidRuleModel.error_message,
        db.func.count(InvalidRuleModel.id).label('count')
    ).group_by(InvalidRuleModel.error_message)
    # flter by user_id
    if user_id:
        query = query.filter(InvalidRuleModel.user_id == user_id)
    
    results = query.all()
    error_messages = [{'name': error_message, 'count': count} for error_message, count in results]
    return error_messages

def get_types_usage(user_id=None):
    query = db.session.query(
        InvalidRuleModel.rule_type,
        db.func.count(InvalidRuleModel.id).label('count')
    ).group_by(InvalidRuleModel.rule_type)
    # flter by user_id
    if user_id:
        query = query.filter(InvalidRuleModel.user_id == user_id)
    
    results = query.all()
    types = [{'name': rule_type, 'count': count} for rule_type, count in results]
    return types

def get_licenses_usage(user_id=None):
    query = db.session.query(
        InvalidRuleModel.license,
        db.func.count(InvalidRuleModel.id).label('count')
    ).group_by(InvalidRuleModel.license)
    # flter by user_id
    if user_id:
        query = query.filter(InvalidRuleModel.user_id == user_id)
    
    results = query.all()
    licenses = [{'name': license, 'count': count} for license, count in results]
    return licenses

def get_filtered_bad_rules_query(params) -> tuple:
    """Return a SQLAlchemy paginated query for filtered bad rules belonging to the current user."""
    page = params.get('page', 1, type=int)
    search = params.get('search', '', type=str)
    search_field = params.get('search_field', 'all', type=str)
    error_messages = params.get('error_messages', '', type=str)
    sources = params.get('sources', '', type=str)
    user_id = params.get('user_id', type=int)
    rule_types = params.get('rule_types', '', type=str)
    licenses = params.get('licenses', '', type=str)
    
    query = InvalidRuleModel.query
    
    if user_id:
        query = query.filter(InvalidRuleModel.user_id == user_id)
    else:
        query = query.filter(InvalidRuleModel.user_id == current_user.id)
    
    if search and search.strip():
        search_term = f"%{search}%"
        if search_field == 'file_name':
            query = query.filter(InvalidRuleModel.file_name.ilike(search_term))
        elif search_field == 'error_message':
            query = query.filter(InvalidRuleModel.error_message.ilike(search_term))
        else:
            query = query.filter(
                db.or_(
                    InvalidRuleModel.file_name.ilike(search_term),
                    InvalidRuleModel.error_message.ilike(search_term)
                )
            )
    
    if error_messages and error_messages.strip():
        error_list = [msg.strip() for msg in error_messages.split(',') if msg.strip()]
        if error_list:
            query = query.filter(InvalidRuleModel.error_message.in_(error_list))
    
    if sources and sources.strip():
        source_list = [src.strip() for src in sources.split(',') if src.strip()]
        if source_list:
            query = query.filter(InvalidRuleModel.url.in_(source_list))
    
    if rule_types and rule_types.strip():
        rule_type_list = [rule_type.strip() for rule_type in rule_types.split(',') if rule_type.strip()]
        if rule_type_list:
            query = query.filter(InvalidRuleModel.rule_type.in_(rule_type_list))
    
    if licenses and licenses.strip():
        license_list = [license.strip() for license in licenses.split(',') if license.strip()]
        if license_list:
            query = query.filter(InvalidRuleModel.license.in_(license_list))
    
    total_rules = query.count()
    per_page = 12
    paginated = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return paginated, total_rules
