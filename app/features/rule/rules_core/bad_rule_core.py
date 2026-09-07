
#################
#   Bad Rule    #
#################

# CRUD

# Update

import uuid as uuid_mod
from typing import Optional, Tuple

from flask_login import current_user
from sqlalchemy.exc import SQLAlchemyError
from app.features.rule.rule_core import get_updater_result_by_id
from app import db
from app.core.db_class.db import *


def _can_manage_all_bad_rules() -> bool:
    """A GitHub Manager sees/acts on every bad rule, not just their own — bad
    rules from a GitHub import are usually owned by whichever admin/user ran
    that particular import, not by the person managing GitHub overall."""
    return current_user.is_admin() or current_user.has_permission('github.manage')


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
    if not _can_manage_all_bad_rules():
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


        if not _can_manage_all_bad_rules():
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
        return deleted_count
    except Exception as e:
        db.session.rollback()
        return None

def delete_bad_rules_by_ids(rule_ids: list) -> int:
    """Delete a specific set of invalid rules by id (selection-based bulk
    delete, complements delete_all_bad_rules's filter-based one). Same
    admin-vs-owner scoping as delete_all_bad_rules — a non-admin can only
    ever delete their own rows, regardless of what ids were requested."""
    if not rule_ids:
        return 0
    try:
        query = InvalidRuleModel.query.filter(InvalidRuleModel.id.in_(rule_ids))
        if not _can_manage_all_bad_rules():
            query = query.filter(InvalidRuleModel.user_id == current_user.id)
        deleted_count = query.delete(synchronize_session=False)
        db.session.commit()
        return deleted_count
    except Exception:
        db.session.rollback()
        return 0

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

def get_users_usage(source=None, rule_type=None):
    """Distinct users with an invalid rule matching the given source/format
    scope — feeds BadRuleList's "Editor" filter with the same {id, name, count}
    shape UserChip-adjacent pickers elsewhere in the app already expect."""
    query = db.session.query(
        InvalidRuleModel.user_id,
        User.first_name,
        User.last_name,
        db.func.count(InvalidRuleModel.id).label('count'),
    ).join(User, User.id == InvalidRuleModel.user_id).group_by(
        InvalidRuleModel.user_id, User.first_name, User.last_name
    )
    if source:
        query = query.filter(InvalidRuleModel.url == source)
    if rule_type:
        query = query.filter(InvalidRuleModel.rule_type == rule_type)

    results = query.order_by(db.func.count(InvalidRuleModel.id).desc()).all()
    return [
        {'id': uid, 'name': f"{first} {last}".strip(), 'count': count}
        for uid, first, last, count in results
    ]

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

    # A non-admin/non-GitHub-Manager can never pass an arbitrary `user_id` to
    # view someone else's invalid rules (which include full raw rule content
    # and error detail) — only admins/GitHub Managers may pick a specific
    # user via the Editor filter; everyone else is always scoped to their
    # own rows regardless of what `user_id` was sent.
    if _can_manage_all_bad_rules() and user_id:
        query = query.filter(InvalidRuleModel.user_id == user_id)
    elif not _can_manage_all_bad_rules():
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

    # Server-side sort — same sort/dir query params RuleList's own /rule/data_table uses.
    sort_col = {
        'file_name':    InvalidRuleModel.file_name,
        'rule_type':    InvalidRuleModel.rule_type,
        'error_message': InvalidRuleModel.error_message,
        'github_path':  InvalidRuleModel.github_path,
        'created_at':   InvalidRuleModel.created_at,
    }.get(params.get('sort', '', type=str), InvalidRuleModel.created_at)
    sort_dir = params.get('dir', 'desc', type=str)
    query = query.order_by(sort_col.asc() if sort_dir == 'asc' else sort_col.desc())

    per_page = params.get('per_page', 12, type=int) or 12
    per_page = max(1, min(per_page, 100))  # same bound RuleList's own rows-per-page picker offers (10/25/50/100)
    paginated = query.paginate(page=page, per_page=per_page, error_out=False)

    return paginated, total_rules

# AI fix (Rule Fixer agent)
#
# One-shot by design (see ~/Documents/Rulezet/IA-Integration-plan/AI_04_RULE_FIXER.md,
# "one-shot redesign" note): no retry loop, no automatic re-validation against
# verify_syntax_rule_by_format — a compile/validate round-trip per attempt was slow
# for little payoff, and a 3-attempt terminal log was a worse UX than a single
# fast answer the human reviews themselves via the diff. A human always makes the
# actual accept/reject call before anything is saved, same as before.
#
# Emits the shared "thinking steps" protocol (AI_00_FOUNDATION.md §10) so any
# frontend can render this as a mascot-style step list instead of a raw log:
# {"type": "step", "stage": <see AI_STEP_STAGES>, "text": "..."} while working,
# then exactly one {"type": "result", "ok": bool, "fixed_content", "explanation",
# "error"} to close the stream.

AI_STEP_STAGES = ('reading', 'thinking', 'writing', 'done', 'failed')

# A "fix" shorter than this fraction of the original rule is almost certainly
# the model returning just the changed line/section instead of the full rule
# (a real failure mode of smaller local models despite explicit instructions
# not to) — never save or forward a candidate like that; it would corrupt the
# rule if accepted as-is. Cheap to check, no extra model call, so kept even
# though full syntax re-validation was dropped.
MIN_FIX_LENGTH_RATIO = 0.5


def run_ai_fix_streaming(bad_rule: 'InvalidRuleModel', user):
    """Generator version of the fix flow — yields one {"type": "step", ...}
    event per stage so the route can stream them to the browser as they
    happen, then a single closing {"type": "result", ...} event with the same
    shape run_ai_fix() returns.

    Exactly one call to the model — see the module docstring above for why.

    Never mutates `bad_rule` — the InvalidRuleModel row and its error_message
    are left exactly as they are, so a human always sees the real validator
    error, never an AI attempt's guess. A human still has to explicitly click
    "Save" on the existing edit form to commit any proposed content — this
    only proposes.
    """
    from app.features.ai.ai_core import get_agent

    agent = get_agent('rule_fixer')
    if agent is None:
        yield {"type": "step", "stage": "failed", "text": "Rule Fixer agent is unavailable."}
        yield {"type": "result", "ok": False, "error": "Rule Fixer agent is unavailable."}
        return

    yield {"type": "step", "stage": "reading", "text": "Reading the rule and its validator error…"}
    yield {"type": "step", "stage": "thinking", "text": "Thinking through a fix…"}

    result = agent.run(
        user=user,
        input_summary=f"Fix invalid {bad_rule.rule_type} rule (id={bad_rule.id})",
        content=bad_rule.raw_content or '', format_name=bad_rule.rule_type,
        error_message=bad_rule.error_message or '',
    )
    if not result.ok:
        yield {"type": "step", "stage": "failed", "text": result.error}
        yield {"type": "result", "ok": False, "error": result.error}
        return

    candidate = result.content
    explanation = result.meta.get("explanation") or ""

    original_len = len(bad_rule.raw_content or '')
    if original_len > 80 and len(candidate) < original_len * MIN_FIX_LENGTH_RATIO:
        # The model returned a fragment/snippet, not the full rule — never
        # accept this as a candidate, it would corrupt the rule if saved.
        # No retry: the human can just click "Try AI fix" again if they want.
        message = "The model returned a partial fragment instead of the full rule content."
        yield {"type": "step", "stage": "failed", "text": message}
        yield {"type": "result", "ok": False, "error": message}
        return

    yield {"type": "step", "stage": "writing", "text": "Preparing the diff…"}
    db.session.add(AIGeneration(
        uuid=str(uuid_mod.uuid4()), agent_key='rule_fixer', rule_id=None,
        user_id=getattr(user, 'id', None), content=candidate,
        model=result.model_used, is_public=True,
    ))
    db.session.commit()
    yield {"type": "step", "stage": "done", "text": "Fix ready — review the diff below."}
    yield {"type": "result", "ok": True, "fixed_content": candidate, "explanation": explanation}


def run_ai_fix(bad_rule: 'InvalidRuleModel', user) -> dict:
    """Non-streaming convenience wrapper around run_ai_fix_streaming() — runs
    it to completion and returns just the final result dict. Used by tests
    and any non-HTTP caller; the live HTTP route streams the generator's
    events directly instead.

    Returns {"ok": bool, "fixed_content": str, "explanation": str, "error": str}.
    `fixed_content`/`explanation` are only present when `ok` is true — this is
    a single attempt, not validated against the rule format's compiler, so the
    human must review the diff before accepting it (§ AI_04 "one-shot redesign").
    """
    for event in run_ai_fix_streaming(bad_rule, user):
        if event.get("type") == "result":
            return {k: v for k, v in event.items() if k != "type"}
    return {"ok": False, "error": "The fix stream ended without a result."}
