
import json
from collections import Counter
import math
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid
import datetime
from typing import List
from sqlalchemy.exc import SQLAlchemyError
from flask import jsonify
from flask_login import current_user
from sqlalchemy import case, or_
from sqlalchemy.orm import joinedload
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
            
from app.rule_format.abstract_rule_type import rule_type_abstract
from app.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult, load_all_rule_formats

from .. import db
from ..db_class.db import *

from ..account import account_core as AccountModel

###################
#   Rule action   #
###################

# CRUD

# Create
def add_rule_core(form_dict, user) -> tuple[bool, str] | tuple[Rule, str]:
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

        existing_rule = get_rule_by_content(new_to_string)
        # Check if the rule already exists with the original_uuid (if a rule is different but with the same uuid we don't want to import it)
        
        if existing_rule != None:
            return False, "Rule already exists (content matches)"

            
        # Identify user
        if current_user and current_user.is_authenticated:
            user_id = current_user.id
        else:
            user_id = user.id if user else None

        if form_dict.get("cve_id") == "None":
            form_dict["cve_id"] = None
        if form_dict.get("vulnerabilities") == "None":
            form_dict["vulnerabilities"] = []
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
            cve_id= form_dict.get("vulnerabilities") or form_dict.get("cve_id") or [],
            github_path=form_dict.get("github_path") or None
        )

        db.session.add(new_rule)
        db.session.commit()
        return new_rule , "rule created" 

    except Exception as e:
        return False, e

def get_rule_by_content(content):
    if not content:
        return None
        
    # 1. Normalisation en Python : supprime TOUT (espaces, \n, \r, \t)
    # et met tout en minuscule pour éviter les doublons de casse
    clean_content = "".join(content.split()).lower()

    # 2. Comparaison SQL avec gestion des Tabulations (\t)
    query = Rule.query.filter(
        func.lower(
            func.replace(
                func.replace(
                    func.replace(
                        func.replace(Rule.to_string, ' ', ''), 
                    '\n', ''), 
                '\r', ''),
            '\t', '') # Ajout du remplacement des tabulations
        ) == clean_content
    )
    
    return query.first()

def rule_exists(Metadata: dict) -> tuple[bool, int]:
    """
    Check if a rule already exists.
    - If no original_uuid is provided: check by title.
    - If original_uuid is provided: check by original_uuid.
    """

    original_uuid = str(Metadata.get("original_uuid") or "").strip()
    if original_uuid.lower() == "none" or original_uuid.lower() == "null" or original_uuid.lower() == "unknown":
        original_uuid = ""
    else:
        # get the rule by original_uuid
        existing_rule = Rule.query.filter_by(original_uuid=original_uuid).first()
        if existing_rule != None:
            return True, existing_rule.id
    

    to_string = Metadata.get("to_string", "").strip()

    existing_rule_by_content = get_rule_by_content(to_string)
        
    if existing_rule_by_content != None:
        return True, existing_rule_by_content.id

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
    if not rule:
        return False, None

    rule.format = form_dict["format"]
    rule.title = form_dict["title"]
    rule.license = form_dict["license"]
    rule.description = form_dict["description"]
    rule.source = form_dict["source"]
    rule.version = form_dict["version"]
    rule.to_string = form_dict["to_string"]
    rule.cve_id = form_dict["vulnerabilities"]
    rule.last_modif = datetime.datetime.now(tz=datetime.timezone.utc)

    db.session.commit()
    return True , rule


# Read

def get_count_rules_by_user_id(user_id) -> int:
    """Get the count of rules for a specific user"""
    return Rule.query.filter(Rule.user_id == user_id).count(
)



    

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

    return query.paginate(page=page, per_page=20, max_per_page=20)

def get_rule(id) -> Rule:
    """Return the rule from id"""
    return Rule.query.get(id)





import numpy as np
import faiss
from sklearn.feature_extraction.text import TfidfVectorizer

_INDEX = None
_ID_MAP = []
_VECTORIZER = None

def get_index():
    global _INDEX, _ID_MAP, _VECTORIZER
    
    if _INDEX is None:
        from .rule_core import Rule 
        rules = Rule.query.filter(Rule.to_string.isnot(None)).all()
        
        if not rules:
            return None, None, None

        texts = [r.to_string for r in rules]
        
        
        _VECTORIZER = TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            max_features=10000, 
            stop_words='english' 
        )
        
        tfidf_matrix = _VECTORIZER.fit_transform(texts).toarray().astype('float32')

        
        faiss.normalize_L2(tfidf_matrix)
        
      
        d = tfidf_matrix.shape[1]
        _INDEX = faiss.IndexFlatIP(d)
        _INDEX.add(tfidf_matrix)
        
        
        _ID_MAP = [r.id for r in rules]
        
    return _INDEX, _ID_MAP, _VECTORIZER

def refresh_similarity_index():
    global _INDEX
    _INDEX = None
    return get_index()

def get_similar_rule(rule_id, limit=3, min_score=0.15) -> list:
   
    index, id_map, vectorizer = get_index()
    
    if index is None:
        return []

    rule = Rule.query.get(rule_id)
    if not rule or not rule.to_string:
        return []

    target_vec = vectorizer.transform([rule.to_string]).toarray().astype('float32')
    faiss.normalize_L2(target_vec)

    k = min(len(id_map), limit * 5 + 1 if limit > 0 else len(id_map))
    scores, indices = index.search(target_vec, k)

    results = []
    for score, idx in zip(scores[0], indices[0]):
        if idx == -1:
            continue
            
        candidate_id = id_map[idx]
        
        if candidate_id != rule_id and score >= min_score:
            candidate = Rule.query.get(candidate_id)
            
            if candidate and candidate.format == rule.format:
                results.append({
                    **candidate.to_json(),
                    "similarity": round(float(score), 3)
                })
                
                if limit > 0 and len(results) >= limit:
                    break

    return results



def get_similar_rules_paginated(rule_id, page=1, per_page=10, min_score=0.15, search=None, sort_by="highest_match", pourcent=111):
    index, id_map, vectorizer = get_index()
    
    base_rule = Rule.query.get(rule_id)
    if not base_rule or not base_rule.to_string or index is None:
        return [], 0, 1

    target_vec = vectorizer.transform([base_rule.to_string]).toarray().astype('float32')
    faiss.normalize_L2(target_vec)
    all_scores, all_indices = index.search(target_vec, len(id_map))
    
    score_dict = {id_map[idx]: float(score) for score, idx in zip(all_scores[0], all_indices[0]) if idx != -1}

    query = Rule.query.filter(
        Rule.id != base_rule.id,
        Rule.format == base_rule.format,
        Rule.to_string.isnot(None)
    )

    if search:
        search_query = f"%{search}%"
        query = query.filter(or_(
            Rule.title.ilike(search_query),
            Rule.description.ilike(search_query),
            Rule.to_string.ilike(search_query)
        ))

    candidates = query.all()

    try:
        pourcent_val = int(pourcent)
        threshold = pourcent_val / 100 if 0 <= pourcent_val <= 100 else min_score
    except:
        threshold = min_score

    scored_results = []
    for candidate in candidates:
        score = score_dict.get(candidate.id, 0)
        
        if score >= threshold:
            data = candidate.to_json()
            data["similarity"] = round(score, 4)
            scored_results.append(data)

    reverse_sort = (sort_by == "highest_match")
    scored_results.sort(key=lambda x: x["similarity"], reverse=reverse_sort)


    total_count = len(scored_results)
    total_pages = max(1, math.ceil(total_count / per_page))
    page = max(1, min(page, total_pages))
    
    start = (page - 1) * per_page
    end = start + per_page
    
    return scored_results[start:end], total_count, total_pages



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

def get_rule_by_title(title) -> Rule | None:
    """Return the rule from the title"""
    return Rule.query.filter_by(title=title).first()

def get_rule_from_a_github(title, filepath_in_the_repo, repo_source, original_uuid) -> tuple[Rule | None, str]:
    """
    Retrieve a rule by title, repository source, and filepath in the repo.
    """

    clean_uuid = str(original_uuid).strip().lower()


    forbidden = ["none", "null", "unknown", "n/a", "undefined", ""]
    if original_uuid and clean_uuid not in forbidden:
        rule = Rule.query.filter_by(original_uuid=original_uuid).first()
        if rule:
            return rule, "Rule found in Rulezet with this original_uuid"

    query = Rule.query.filter(
        Rule.title == title,
        Rule.source == repo_source
    )

    count_title = query.count()
   

    if count_title == 0:
        
        return None, "[new rule]"

    if count_title == 1:
        rule = query.first()
       
        if rule.github_path != filepath_in_the_repo:
            return None, "[new rule]"
        return rule, "Rule found in Rulezet with this title"

    query_path = query.filter(Rule.github_path == filepath_in_the_repo)
    count_path = query_path.count()

   

    if count_path == 1:
        rule = query_path.first()
       
        return rule, "Rule found in Rulezet with this title and this github_path"

    if count_path > 1:
       
        return None, "Impossible to find the real rule multiple rules found with this title and this github_path)"
        

    # add like new rule 
    return None, "[new rule]"


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

def get_last_rules_from_db(limit=12) -> Rule:
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
    rule_list = []
    for rule_id in rule_ids:
        rule = get_rule(rule_id)
        if rule:
            rule_list.append(rule)
        
    return rule_list
            

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

def filter_rules(search=None, author=None, sort_by=None, rule_type=None, vulnerabilities: list[str] | None = None, source=None, user_id=None) -> Rule:
    """Filter the rules"""
    query = Rule.query
    if search:
        search = search.strip()
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
    if vulnerabilities:
        vuln_filters = []
        for v in vulnerabilities:
            search_pattern = '%"' + v + '"%'
            vuln_filters.append(Rule.cve_id.ilike(search_pattern))
        
        query = query.filter(or_(*vuln_filters))
    if source:
        query = query.filter(Rule.source.ilike(f"%{source}%"))

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

    if user_id:
        query = query.filter(Rule.user_id == user_id)
    return query

def get_rules_page_filter_bundle_page(search=None, author=None, sort_by=None, rule_type=None,page=1, bundle_id=None, per_page=10) -> Rule:
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


   # if bundle id, we want to return all the rules which are not part of the bundle
    if bundle_id:
       # get all the rule ids of the bundle
       # from BundleRuleAssociation
        bundle_rule_ids = BundleRuleAssociation.query.filter(BundleRuleAssociation.bundle_id == bundle_id).all()
        bundle_rule_ids = [b.rule_id for b in bundle_rule_ids]
        query = query.filter(Rule.id.notin_(bundle_rule_ids))
    query = query.paginate(page=page, per_page=per_page)
    return query , query.total

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

       
        if not data.get("manual_submit"):
            _submit_content = False
        else:
            _submit_content = data.get("manual_submit")

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
            analyzed_by_user_id=user_id,
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
            analyzed_at=datetime.datetime.now(tz=datetime.timezone.utc),
            manuel_submit=_submit_content
        )

        db.session.add(history_entry)
        db.session.commit()

        return history_entry.id

    except Exception as e:
        db.session.rollback()
        print(e)
        return None

def was_last_history_manuel(rule_id):
    """
    Retourne True si le dernier history a manuel_submit == True,
    False sinon ou s'il n'y a aucun history.
    """
    history_rule = RuleUpdateHistory.query.filter_by(rule_id=rule_id)\
                                          .order_by(RuleUpdateHistory.id.desc())\
                                          .first()
    if history_rule and history_rule.manuel_submit:
        return True
    return False


def get_history_rule_by_id(history_id):
    """Return an history for a rule by id"""
    return RuleUpdateHistory.query.get(history_id)


def get_history_rule_(page, rule_id, per_page) -> list:
    """Get all the accepted edit history of a rule by its ID, paginated."""
    return RuleUpdateHistory.query.filter(
        RuleUpdateHistory.rule_id == rule_id,
        RuleUpdateHistory.success == True ,
        RuleUpdateHistory.message == "accepted" 
    ).paginate(page=page, per_page=per_page, max_per_page=per_page)

def get_old_rule_choice(page , search=None) -> list:
    """Get all the old choice to make"""    
    if current_user.is_admin():
        query = RuleUpdateHistory.query.filter(
            RuleUpdateHistory.message != "accepted",
            RuleUpdateHistory.message != "rejected"
        )
    else:
        query = RuleUpdateHistory.query.filter(
            RuleUpdateHistory.message != "accepted",
            RuleUpdateHistory.message != "rejected",
            RuleUpdateHistory.analyzed_by_user_id == current_user.id
        )
    if search:
        query = query.filter(RuleUpdateHistory.rule_title.ilike(f"%{search}%"))
    return query.paginate(page=page, per_page=20, max_per_page=20)


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

def get_rule_count_for_urls(urls: list[str]):
        """Return a dict {url: count} for a list of URLs"""
        if not urls:
            return {}
        counts = db.session.query(
            Rule.source,
            func.count(Rule.id).label("rule_count")
        ).filter(Rule.source.in_(urls)).group_by(Rule.source).all()
        return {c.source: c.rule_count for c in counts}

def get_all_url_github_page(page: int = 1, search: str = None):
    """Get paginated unique GitHub project URLs from Rule.source and return pagination + total count."""
    
    github_pattern = r'^https?://(www\.)?github\.com/[\w\-_]+/[\w\-_]+'

    query = Rule.query.filter(Rule.source.isnot(None))

    # if current_user.is_admin():
    #     if search:
    #         query = query.filter(Rule.source.ilike(f"%{search}%"))

    # else:
    #     query = query.filter(Rule.user_id == current_user.id)

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

def get_all_rule_by_url_github(url: str = None , current_user_: User = None):
    """Get list of Rules whose source contains a specific GitHub project URL."""
    query = Rule.query.filter(Rule.source.isnot(None))

    if current_user_.is_admin():
        if url:
            query = query.filter(Rule.source.ilike(f"%{url}%"))

    else:
        query = query.filter(Rule.user_id == current_user_.id)

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

    return (
        NewRule.query
        .filter_by(update_result_id=update_result.id)
        .filter(NewRule.message != "imported")    
        .paginate(page=page, per_page=per_page, error_out=False)
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
    if current_user.is_admin():
        return UpdateResult.query.paginate(page=page, per_page=20, max_per_page=20)
    else :
        return UpdateResult.query.filter_by(user_id=str(current_user.id)).paginate(page=page, per_page=20, max_per_page=20)
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


def search_rules_by_cve_patterns(vulnerabilities: list[str]) -> dict:
    """
    Search rules by matching CVE patterns inside the cve_id string column.
    Optimized to use a single SQL query.
    """

    
    base_url = "https://rulezet.org/rule/detail_rule/"
    query = Rule.query

    if vulnerabilities:
        vuln_filters = []
        for v in vulnerabilities:
            search_pattern = '%"' + v + '"%'
            vuln_filters.append(Rule.cve_id.ilike(search_pattern))
        
        query = query.filter(or_(*vuln_filters))
        

    all_rules = query.order_by(Rule.last_modif.desc()).all()
    
    final_rules = []
    for rule in all_rules:
        rule_data = rule.to_json()
        
        rule_data["detail_url"] = f"{base_url}{rule.id}"
        
        if rule.last_modif:
            rule_data["formatted_date"] = rule.last_modif.strftime('%Y-%m-%d %H:%M:%S')
        else:
            rule_data["formatted_date"] = None

        final_rules.append(rule_data)

    total_count = len(all_rules)

    return {
        "totals": total_count,
        "total_all_rules": total_count,
        "rules": final_rules
    }



def get_new_rule(new_rule_id):
    return NewRule.query.get(new_rule_id)




def get_rule_update_list(sid):
    update_result = UpdateResult.query.filter_by(uuid=sid).first()
    if not update_result:
        return None , 0
    # filter by update result update_available == true and the number of rules
    rule_udpate_list = RuleStatus.query.filter_by(update_result_id=update_result.id, update_available=True).all()
    return rule_udpate_list, len(rule_udpate_list)

def accept_all_update(rule_udpate_list):
    # for each rule take the history_id associated
    try:
        for rule in rule_udpate_list:
            rule.update_available = False
            if rule.rule_syntax_valid == True:
                rule.message = "Updated successfully"
            else:
                rule.message = "Rejected successfully because Invalide syntax"


            history_id = rule.history_id
            history = RuleUpdateHistory.query.filter_by(id=history_id).first()

            if not history:
                return False
            if rule.rule_syntax_valid == True:
                history.message = "accepted"
            else:
                history.message = "rejected"
            history.success = True
            db.session.commit()
        return True
    except Exception as e:
        return False
   

def get_rule_update_from_updater_by_rule_id_and_change_statue(rule_id, updater_id , decision, updater):
    rule = RuleStatus.query.filter_by(
        rule_id=str(rule_id),
        update_result_id=updater_id
    ).first()

    message = decision

    if rule and rule.rule_syntax_valid == True:
        rule.update_available = False
        rule.message = decision
        db.session.commit()   
    else:
        rule.update_available = False
        rule.message = 'Rejected successfully because Invalide syntax'
        message = 'Rejected'
        db.session.commit()
    
    if updater:
        updater.updated -= 1 if updater.updated > 0 else 0
        db.session.commit()
        return True , message
    else:
        return False , message

def get_format_name(id):
    rule = RuleStatus.query.filter_by(rule_id=id).first()
    reel_rule = get_rule(rule.rule_id)
    return reel_rule.format or "no format"

def get_updater_result_by_id(sid: int):
    """Retrieve UpdateResult by its integer ID."""
    return UpdateResult.query.get(sid)


def accept_rule_change(history_id):
    try:
        history = RuleUpdateHistory.query.filter_by(id=history_id).first()
        history.message = "accepted"
        history.success = True
        db.session.commit()

        # rule_id = history.rule_id
        # rule = RuleStatus.query.filter_by(rule_id=rule_id).first()
        # rule.update_available = False

        return True
    except Exception as e:
        return False
    
def get_all_pending_changes():
    if current_user.is_admin():
        return RuleUpdateHistory.query.filter(
            RuleUpdateHistory.message != "accepted",
            RuleUpdateHistory.message != "rejected"
        ).all()
    else:
        return RuleUpdateHistory.query.filter(
            RuleUpdateHistory.message != "accepted",
            RuleUpdateHistory.message != "rejected",
            RuleUpdateHistory.analyzed_by_user_id == current_user.id
        ).all()


def change_message_new_rule(id, new_message):
    if not new_message:
        return False    
    new_rule = get_new_rule(id)

    if not new_rule:
        return False

    new_rule.message = new_message
    db.session.commit()
    return True


def update_all_updater_status(history_id, message):
   # Found in all the UpdateResult all the Rulestatue with rule_id == history.rule_id
   # Reject all the change for the other sectio for this rule
   # Change the message of the history
   # change the number of update available from updater -1

    history = RuleUpdateHistory.query.filter_by(id=history_id).first()
    if not history:
        return False
    
    rules = RuleStatus.query.filter_by(rule_id=str(history.rule_id)).all()

    for rule in rules:
        rule.update_available = False
        if rule.rule_syntax_valid == True:
            rule.message = "Updated successfully"
        else:
            rule.message = "Rejected successfully because Invalide syntax"

        # Get the updater associated to this rule
        updater = UpdateResult.query.filter_by(id=rule.update_result_id).first()
        if not updater:
            return False
        if updater.updated == 0:
            updater.updated = 0
        else:
            updater.updated = updater.updated - 1

        if rule.rule_syntax_valid == True:
            history.message = "accepted"
        else:
            history.message = "rejected"
        history.success = True
        db.session.commit()

    # history.message = message
    # history.success = False
    # db.session.commit()
    return True


def verify_rule_syntaxe(rule: Any , new_content) -> Optional[ValidationResult]:
    """
    Found the good class to verify the rule syntax.

    Args:
        rule: The database rule object containing 'format' and 'to_string' (rule content).

    Returns:
        A ValidationResult object if the format class is found and validation is run, 
        or None if no matching rule format class is found.
    """
    if not hasattr(rule, 'format') or not hasattr(rule, 'to_string'):
        # Handle cases where the input object isn't a valid rule structure
        return None

    rule_format = rule.format.lower()
    load_all_rule_formats() # Ensure all available rule format classes are loaded

    # Get all subclasses of the RuleType abstract class
    # We iterate over classes that inherit from the abstract RuleType to find a match
    rule_classes = RuleType.__subclasses__()
    
    matching_class: Optional[RuleType] = None
    
    # --- 1. Find the correct concrete RuleType implementation ---
    for RuleClass in rule_classes:
        # Instantiate the class to check its 'format' property
        try:
            instance = RuleClass()
            if instance.format.lower() == rule_format:
                matching_class = instance
                break
        except Exception:
            # Skip classes that cannot be instantiated (e.g., if they are still abstract or incomplete)
            continue

    # --- 2. Validate the rule content ---
    if matching_class:
        # Call the validate method on the instance, passing the rule content
        return matching_class.validate(new_content)
    
    # If no matching class was found
    return None

    
def get_popular_rules():
    """ Get the ten most popular rules thankt to the like and dislike """
    return Rule.query.order_by(Rule.vote_up.desc(), Rule.vote_down.desc()).limit(10).all()

def get_total_rules():
    return Rule.query.count()

def get_total_formats():
    return Rule.query.distinct(Rule.format).count()


def delete_all_rule_by_url(url, batch_size=100):
    while True:
        rules = Rule.query.filter_by(source=url).limit(batch_size).all()
        if not rules:
            break
        for rule in rules:
            db.session.delete(rule)
        db.session.commit()
    return True


import requests
import time
import os

def get_filtered_history_ids():
    # Configuration du Token GitHub (à définir dans ton environnement ou en dur pour test)
    # os.environ['GITHUB_TOKEN'] = "ton_token_ici"
    github_token = os.getenv('GITHUB_TOKEN')
    
    uuid_updater = "335338e8-9a08-41e7-a1c5-e05096298911"
    updater = UpdateResult.query.filter_by(uuid=uuid_updater).first()
    
    if not updater:
        return []

    rule_statuses = RuleStatus.query.filter_by(
        update_result_id=updater.id, 
        update_available=True
    ).all()
    
    if not rule_statuses:
        print("Aucun status de règle trouvé avec update_available=True")
        return []

    history_ids = [rs.history_id for rs in rule_statuses if rs.history_id]
    history_entries = RuleUpdateHistory.query.filter(RuleUpdateHistory.id.in_(history_ids)).all()
    
    if not history_entries:
        print("history entries not found")
        return []

    unique_uuids = set()
    final_json_list = []


    search_url = "https://api.github.com/search/code"
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    for his in history_entries:
        rule = Rule.query.filter_by(id=his.rule_id).first()
        if not rule or rule.original_uuid in unique_uuids:
            continue
        
        unique_uuids.add(rule.original_uuid)
        
   
        rule_data = {
            "uuid": rule.original_uuid,
            "rule_name": rule.title,
            "db_source_path": rule.source, 
            "github_found_paths": rule.github_path,       
        }

       
        if rule.original_uuid:
            query = f"{rule.original_uuid} repo:Neo23x0/signature-base"
            try:
                response = requests.get(search_url, headers=headers, params={'q': query})
                
                if response.status_code == 200:
                    items = response.json().get('items', [])
                    # On récupère tous les chemins de fichiers où cet UUID apparaît
                    rule_data["github_found_paths"] = [item['path'] for item in items]
                elif response.status_code == 403:
                    print("Rate limit GitHub atteint, pause nécessaire...")
                
                # Petit délai pour ne pas brusquer l'API
                time.sleep(1) 
            except Exception as e:
                print(f"Erreur recherche GitHub pour {rule.original_uuid}: {e}")

        final_json_list.append(rule_data)

    return final_json_list

# Exemple d'exécution
# results = get_filtered_history_ids()
# import json
# print(json.dumps(results, indent=4))



    

def delete_importer_history(id):
    try:
        success = ImporterResult.query.filter_by(uuid=id).delete()
        db.session.commit()

        if success:
            return True, "Importer history deleted"
        else:
            return False, "Importer history not found"

    except Exception as e:
        db.session.rollback()
        return False, f"Importer history not deleted: {e}"
def delete_updater_history(id):
    try:
        success = UpdateResult.query.filter_by(uuid=id).delete()
        db.session.commit()

        if success:
            return True, "Updater history deleted"
        else:
            return False, "Updater history not found"

    except Exception as e:
        db.session.rollback()
        return False, f"Updater history not deleted: {e}"
    
def get_rules_vulnerabilities_usage(user_id=None, source_url=None):
    """
    Retrieves and counts vulnerability identifiers from Rules.
    If user_id is provided, only rules belonging to that user are counted.
    """

    query = db.session.query(Rule.cve_id).filter(
        Rule.cve_id.isnot(None),
        Rule.cve_id != '',
        Rule.cve_id != '[]'
    )

    if user_id:
        query = query.filter(Rule.user_id == user_id)
    if source_url:
        query = query.filter(Rule.source == source_url)

    elif current_user.is_authenticated:
        if not current_user.is_admin() and hasattr(Rule, 'access'):
            query = query.filter(
                or_(Rule.access.is_(True), Rule.user_id == current_user.id)
            )
    elif hasattr(Rule, 'access'):
        query = query.filter(Rule.access.is_(True))

    all_rules_vulns = query.all()
    

    vulnerability_counter = Counter()
    for (raw_json,) in all_rules_vulns:
        try:
            vuln_list = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            if isinstance(vuln_list, list):
                vulnerability_counter.update(vuln_list)
        except (json.JSONDecodeError, TypeError):
            continue

    return [
        {"name": vuln_id, "usage_count": count}
        for vuln_id, count in vulnerability_counter.most_common()
    ]


def migrate_rule_cve_to_json() -> Tuple[bool, str]:
    """Migrate Rule.cve_id to JSON format."""
    rules = Rule.query.all()
    updated_count = 0

    vuln_regex = re.compile(r'(?:CVE|GHSA|PYSEC|RHSA)[\s\-_]\d{4,}[\s\-_]\d{3,}', re.IGNORECASE)

    for rule in rules:
        if rule.cve_id is None:
            rule.cve_id = json.dumps([])
            updated_count += 1
            continue

        original_value = str(rule.cve_id).strip()
        
     
        if original_value.startswith('[') and original_value.endswith(']'):
            continue

      
        matches = vuln_regex.findall(original_value)
        
        if matches:
            cleaned_list = []
            for m in matches:
                normalized = re.sub(r'[\s\_]', '-', m).upper()
                cleaned_list.append(normalized)
            
            final_list = sorted(list(set(cleaned_list)))
            rule.cve_id = json.dumps(final_list)
            updated_count += 1
        else:
            rule.cve_id = json.dumps([])
            updated_count += 1
            
    try:
        db.session.commit()
        return True, f"Success! {updated_count} rules were updated to the standard JSON format."
    except Exception as e:
        db.session.rollback()
        return False, f"Error during migration: {e}"



def get_vulnerabilities_for_rule(rule_id: int):
    """
    Retrieve the list of vulnerability strings stored in the rule.
    """
    rule = get_rule(rule_id)
    if not rule or not rule.cve_id:
        return []
    
    # vulnerability_identifiers is a string like '["CVE-2024-1234", "GHSA-xxxx"]'
    try:
        return json.loads(rule.cve_id)
    except (json.JSONDecodeError, TypeError):
        return []
    


def get_sources_usage_with_filter(search_term, user_id=None):
    """
    Groups rules by source and counts them.
    Filters by search term (ILIKE) and optionally by creator's user_id.
    """

    query = db.session.query(
        Rule.source.label('source'), 
        func.count(Rule.id).label('count')
    ).filter(Rule.source != None, Rule.source != '')


    if search_term:
        query = query.filter(Rule.source.ilike(f'%{search_term}%'))

    if user_id:
        query = query.filter(Rule.user_id == user_id)

    return query.group_by(Rule.source).order_by(func.count(Rule.id).desc()).all()