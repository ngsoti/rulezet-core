
import json
from collections import Counter
import os
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid
import datetime
import zipfile
import requests
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app, jsonify, send_file
from flask_login import current_user
from sqlalchemy import and_, case, or_, text
from sqlalchemy.orm import joinedload
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sqlalchemy.orm import aliased
from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult, load_all_rule_formats

from ... import db
from ...core.db_class.db import *

from ..account import account_core as AccountModel

###################
#   Rule action   #
###################

def _active():
    """Base query that excludes soft-deleted rules — use for all user-facing lookups."""
    return Rule.query.filter(Rule.is_deleted == False)


# ── Soft delete / restore ──────────────────────────────────────────────────────

def soft_delete_rule(rule_id: int, user_id: int, batch_uuid: str = None) -> bool:
    """Mark a single rule as deleted without removing it from the DB."""
    rule = Rule.query.get(rule_id)
    if not rule or rule.is_deleted:
        return False
    rule.is_deleted        = True
    rule.deleted_at        = datetime.datetime.now(tz=datetime.timezone.utc)
    rule.deleted_by_id     = user_id
    rule.delete_batch_uuid = batch_uuid
    db.session.commit()
    return True


def soft_delete_rule_list(rule_ids: list, user_id: int, batch_uuid: str = None) -> int:
    """Soft-delete a list of rules. Returns the count actually deleted."""
    if not rule_ids:
        return 0
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    updated = Rule.query.filter(
        Rule.id.in_(rule_ids),
        Rule.is_deleted == False,
    ).update(
        {"is_deleted": True, "deleted_at": now, "deleted_by_id": user_id, "delete_batch_uuid": batch_uuid},
        synchronize_session=False,
    )
    db.session.commit()
    return updated


def soft_delete_all_by_url(urls: list, user_id: int) -> tuple[bool, str, int]:
    """Soft-delete all rules whose source matches the given GitHub URLs, as one batch."""
    try:
        if not urls:
            return False, "No URL provided", 0
        if isinstance(urls, str):
            urls = [urls.strip()]
        batch_uuid = str(uuid.uuid4())
        rule_ids = [r[0] for r in db.session.query(Rule.id).filter(
            Rule.source.in_(urls), Rule.is_deleted == False
        ).all()]
        count = soft_delete_rule_list(rule_ids, user_id, batch_uuid=batch_uuid)
        return True, f"{count} rules moved to trash", count
    except Exception as e:
        db.session.rollback()
        return False, str(e), 0


def restore_rule(rule_id: int):
    """Restore a single soft-deleted rule.

    Returns:
        True                          — restored OK
        False                         — not found / not deleted
        ("CONFLICT", active_rule)     — same content already exists in active rules
    """
    rule = Rule.query.get(rule_id)
    if not rule or not rule.is_deleted:
        return False
    # Check if an active rule with the same content already exists
    if rule.to_string:
        conflict = get_rule_by_content(rule.to_string)  # uses _active()
        if conflict and conflict.id != rule_id:
            return "CONFLICT", conflict
    rule.is_deleted        = False
    rule.deleted_at        = None
    rule.deleted_by_id     = None
    rule.delete_batch_uuid = None
    db.session.commit()
    return True


def restore_rules_bulk(rule_ids: list) -> int:
    """Restore multiple soft-deleted rules. Returns count restored."""
    if not rule_ids:
        return 0
    updated = Rule.query.filter(
        Rule.id.in_(rule_ids), Rule.is_deleted == True
    ).update(
        {"is_deleted": False, "deleted_at": None, "deleted_by_id": None, "delete_batch_uuid": None},
        synchronize_session=False,
    )
    db.session.commit()
    return updated


def restore_batch(batch_uuid: str) -> int:
    """Restore all rules sharing the same delete_batch_uuid."""
    if not batch_uuid:
        return 0
    updated = Rule.query.filter(
        Rule.delete_batch_uuid == batch_uuid, Rule.is_deleted == True
    ).update(
        {"is_deleted": False, "deleted_at": None, "deleted_by_id": None, "delete_batch_uuid": None},
        synchronize_session=False,
    )
    db.session.commit()
    return updated


def get_deleted_rules(page: int = 1, search: str = None, source: str = None,
                      batch_uuid: str = None, fmt: str = None, per_page: int = 30,
                      deleted_from: str = None, deleted_to: str = None):
    """Paginated list of soft-deleted rules for the admin trash page."""
    query = Rule.query.filter(Rule.is_deleted == True)
    if search:
        pattern = f"%{search}%"
        query = query.filter(Rule.title.ilike(pattern) | Rule.author.ilike(pattern))
    if source:
        query = query.filter(Rule.source.ilike(f"%{source}%"))
    if batch_uuid:
        query = query.filter(Rule.delete_batch_uuid == batch_uuid)
    if fmt:
        query = query.filter(Rule.format == fmt)
    if deleted_from:
        try:
            dt = datetime.datetime.strptime(deleted_from, '%Y-%m-%d')
            query = query.filter(Rule.deleted_at >= dt)
        except ValueError:
            pass
    if deleted_to:
        try:
            dt = datetime.datetime.strptime(deleted_to, '%Y-%m-%d') + datetime.timedelta(days=1)
            query = query.filter(Rule.deleted_at < dt)
        except ValueError:
            pass
    query = query.order_by(Rule.deleted_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, max_per_page=100)
    return pagination


def get_deleted_batches():
    """Return distinct batch UUIDs with counts and source info for the trash grouped view."""
    rows = (
        db.session.query(
            Rule.delete_batch_uuid,
            Rule.source,
            db.func.count(Rule.id).label('count'),
            db.func.min(Rule.deleted_at).label('deleted_at'),
        )
        .filter(Rule.is_deleted == True, Rule.delete_batch_uuid.isnot(None))
        .group_by(Rule.delete_batch_uuid, Rule.source)
        .order_by(db.func.min(Rule.deleted_at).desc())
        .all()
    )
    return [{"batch_uuid": r.delete_batch_uuid, "source": r.source,
             "count": r.count, "deleted_at": r.deleted_at.strftime('%Y-%m-%d %H:%M') if r.deleted_at else None}
            for r in rows]


def _wipe_rule_children(rule_ids: list) -> None:
    """Delete all FK-dependent rows for the given rule IDs before removing the rules.

    Uses the ORM query.delete(synchronize_session=False) pattern throughout so
    that SQLAlchemy correctly serializes the deletes within the open transaction
    without identity-map conflicts.

    No commit is issued here — the caller commits after deleting the rules.
    """
    if not rule_ids:
        return
    ids = list(rule_ids)

    # 1. Comment reactions reference both rule.id and comment.id — delete first
    RuleCommentReaction.query.filter(RuleCommentReaction.rule_id.in_(ids)).delete(synchronize_session=False)

    # 2. Comments have a self-referencing parent_comment_id FK.
    #    Null it out for the affected rows first to avoid FK cycles, then delete.
    Comment.query.filter(Comment.rule_id.in_(ids)).update({'parent_comment_id': None}, synchronize_session=False)
    Comment.query.filter(Comment.rule_id.in_(ids)).delete(synchronize_session=False)

    # 3. Tag associations — the table causing the FK violation
    RuleTagAssociation.query.filter(RuleTagAssociation.rule_id.in_(ids)).delete(synchronize_session=False)

    # 3b. ATT&CK technique associations — same shape as tag associations, same
    # missing ondelete=CASCADE on rule_id, same permanent-delete FK violation.
    RuleAttackAssociation.query.filter(RuleAttackAssociation.rule_id.in_(ids)).delete(synchronize_session=False)

    # 4. Bundle ↔ rule associations (no ondelete=CASCADE on this FK)
    BundleRuleAssociation.query.filter(BundleRuleAssociation.rule_id.in_(ids)).delete(synchronize_session=False)

    # 5. Favorites
    RuleFavoriteUser.query.filter(RuleFavoriteUser.rule_id.in_(ids)).delete(synchronize_session=False)

    # 6. Votes
    RuleVote.query.filter(RuleVote.rule_id.in_(ids)).delete(synchronize_session=False)

    # 7. Edit contributions reference both rule.id and proposal.id — delete before proposals
    RuleEditContribution.query.filter(RuleEditContribution.rule_id.in_(ids)).delete(synchronize_session=False)

    # 8. Edit comments only reference proposal.id — delete before proposals
    proposal_ids = [r for (r,) in
                    db.session.query(RuleEditProposal.id).filter(RuleEditProposal.rule_id.in_(ids)).all()]
    if proposal_ids:
        RuleEditComment.query.filter(RuleEditComment.proposal_id.in_(proposal_ids)).delete(synchronize_session=False)

    # 9. Edit proposals
    RuleEditProposal.query.filter(RuleEditProposal.rule_id.in_(ids)).delete(synchronize_session=False)

    # 9b. comment_v2 targets rules/proposals via object_type/object_id, not a
    #     real FK, so it can't cascade automatically — clean it up explicitly.
    purge_unified_comments('rule', ids)
    if proposal_ids:
        purge_unified_comments('proposal', proposal_ids)

    # 10. Reports
    RepportRule.query.filter(RepportRule.rule_id.in_(ids)).delete(synchronize_session=False)

    # 11. Ownership requests
    RequestOwnerRule.query.filter(RequestOwnerRule.rule_id.in_(ids)).delete(synchronize_session=False)

    # 12. Update history
    RuleUpdateHistory.query.filter(RuleUpdateHistory.rule_id.in_(ids)).delete(synchronize_session=False)

    # 13. Similarity pairs (has ondelete=CASCADE but be explicit)
    RuleSimilarity.query.filter(
        or_(RuleSimilarity.rule_id.in_(ids), RuleSimilarity.similar_rule_id.in_(ids))
    ).delete(synchronize_session=False)

    db.session.flush()


def permanent_delete_rule(rule_id: int) -> bool:
    """Physically delete a soft-deleted rule (admin only — irreversible)."""
    rule = Rule.query.filter(Rule.id == rule_id, Rule.is_deleted == True).first()
    if not rule:
        return False
    _wipe_rule_children([rule_id])
    db.session.delete(rule)
    db.session.commit()
    return True


def permanent_delete_bulk(rule_ids: list) -> int:
    """Physically delete multiple soft-deleted rules."""
    if not rule_ids:
        return 0
    valid_ids = [r.id for r in Rule.query.filter(Rule.id.in_(rule_ids), Rule.is_deleted == True)
                 .with_entities(Rule.id).all()]
    if not valid_ids:
        return 0
    _wipe_rule_children(valid_ids)
    Rule.query.filter(Rule.id.in_(valid_ids), Rule.is_deleted == True).delete(synchronize_session=False)
    db.session.commit()
    return len(valid_ids)


def count_deleted_rules() -> int:
    return Rule.query.filter(Rule.is_deleted == True).count()


# Default tags automatically attached to every new rule — loaded from config/default_tags.json
def _load_default_tag_names() -> list:
    try:
        from pathlib import Path
        config_path = Path(__file__).parents[3] / "config" / "default_tags.json"
        with open(config_path) as f:
            return json.load(f).get("auto_attach", [])
    except Exception:
        return ["tlp:clear", "pap:clear"]

_DEFAULT_TAG_NAMES = _load_default_tag_names()


def _attach_default_tags(rule, user_id):
    """Silently attach default tags to a newly created rule if they exist in the DB."""
    existing_ids = {
        row.tag_id
        for row in RuleTagAssociation.query.filter_by(rule_id=rule.id).all()
    }
    for name in _DEFAULT_TAG_NAMES:
        tag = Tag.query.filter(Tag.name.ilike(name)).first()
        if tag and tag.id not in existing_ids:
            db.session.add(RuleTagAssociation(
                uuid=str(uuid.uuid4()),
                rule_id=rule.id,
                tag_id=tag.id,
                user_id=user_id,
                added_at=datetime.datetime.now(tz=datetime.timezone.utc),
            ))
            existing_ids.add(tag.id)

# CRUD

def _find_in_trash_by_content(content: str):
    """Return a soft-deleted rule with identical content, or None."""
    if not content:
        return None
    content_hash = compute_rule_content_hash(content)
    return Rule.query.filter(
        Rule.is_deleted == True,
        Rule.content_hash == content_hash
    ).first()

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
        if existing_rule is not None:
            return False, "Rule already exists (content matches)"

        # Check if the same content exists in the trash — offer restore instead
        trashed_rule = _find_in_trash_by_content(new_to_string)
        if trashed_rule is not None:
            return False, f"TRASH_CONFLICT:{trashed_rule.uuid}:{trashed_rule.id}:{trashed_rule.title}"

            
        # Identify user
        if current_user and current_user.is_authenticated:
            user_id = current_user.id
        else:
            user_id = user.id if user else None

        # Resolve vulnerabilities to a clean Python list, handling all input forms:
        # - Python list (from format parsers)
        # - JSON string like '["CVE-2024-1234"]' (from Vue hidden input or detect_cve)
        # - "None" / None / "" (empty)
        def _resolve_vuln(v):
            if isinstance(v, list):
                return v
            if isinstance(v, str) and v.strip() not in ('', 'None', 'null', '[]'):
                try:
                    parsed = json.loads(v)
                    return parsed if isinstance(parsed, list) else []
                except (json.JSONDecodeError, TypeError):
                    pass
            return []

        vuln_list = (
            _resolve_vuln(form_dict.get("vulnerabilities"))
            or _resolve_vuln(form_dict.get("cve_id"))
        )
        # strip empty/whitespace-only entries
        vuln_list = [v for v in vuln_list if isinstance(v, str) and v.strip()]

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
            cve_id=json.dumps(vuln_list),
            github_path=form_dict.get("github_path") or None
        )

        db.session.add(new_rule)
        db.session.flush()
        

        tags_list = form_dict.get("tags")
        if tags_list and isinstance(tags_list, list):
            for tag_data in tags_list:
                if not isinstance(tag_data, dict):
                    continue
                tag_id = tag_data.get('id')
                if tag_id:
                    assoc = RuleTagAssociation(
                        uuid=str(uuid.uuid4()),
                        rule_id=new_rule.id,
                        tag_id=int(tag_id),
                        user_id=user.id if user else None,
                        added_at=datetime.datetime.now(tz=datetime.timezone.utc)
                    )
                    db.session.add(assoc)

        _attach_default_tags(new_rule, user_id)

        db.session.commit()

        # Notify followers of the rule author
        if user_id:
            try:
                from app.features.notification.notification_core import notify_followers_new_rule
                notify_followers_new_rule(new_rule, user_id)
            except Exception:
                pass

        # Auto-extract ATT&CK technique associations from rule content
        try:
            from app.features.attack.attack_core import auto_parse_rule
            auto_parse_rule(new_rule.id, user_id)
        except Exception:
            pass

        return new_rule, "rule created"

    except Exception as e:
        return False, e

def get_rule_by_uuid(uuid, include_deleted=False):
    q = Rule.query if include_deleted else _active()
    return q.filter(Rule.uuid == uuid).first()

def get_rule_by_content(content):
    if not content:
        return None

    content_hash = compute_rule_content_hash(content)
    return _active().filter(Rule.content_hash == content_hash).first()

def rule_exists(Metadata: dict) -> tuple[bool, int]:
    """
    Check if a rule already exists.
    - If a valid original_uuid is provided: check by original_uuid.
    - If not: check by content.
    """
    EMPTY_UUID_VALUES = {"none", "null", "unknown", "n/a", "na", ""}

    original_uuid = str(Metadata.get("original_uuid") or "").strip()

    if original_uuid.lower() not in EMPTY_UUID_VALUES:
        existing_rule = Rule.query.filter_by(original_uuid=original_uuid).first()
        if existing_rule:
            return True, existing_rule.id
        return False, None

    to_string = Metadata.get("to_string", "").strip()
    if not to_string:
        return False, None

    existing_rule = get_rule_by_content(to_string)
    if existing_rule:
        return True, existing_rule.id

    return False, None

# Delete

def delete_rule_core(id, user_id=None, batch_uuid=None) -> bool:
    """Soft-delete a rule (moves it to the trash)."""
    return soft_delete_rule(id, user_id or 0, batch_uuid=batch_uuid)

# Update

def edit_rule_core(form_dict, id) -> tuple[bool, Rule]:
    """Edit the rule in the DB with proper Tag synchronization"""
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
    rule.author = form_dict["author"]
    rule.original_uuid = form_dict["original_uuid"]
    def _resolve_vuln(v):
        if isinstance(v, list):
            return v
        if isinstance(v, str) and v.strip() not in ('', 'None', 'null', '[]'):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, list) else []
            except (json.JSONDecodeError, TypeError):
                pass
        return []

    vuln_edit = (
        _resolve_vuln(form_dict.get("vulnerabilities"))
        or _resolve_vuln(form_dict.get("cve_id"))
    )
    vuln_edit = [v for v in vuln_edit if isinstance(v, str) and v.strip()]
    rule.cve_id = json.dumps(vuln_edit)
    rule.last_modif = datetime.datetime.now(tz=datetime.timezone.utc)


    if "tags" in form_dict:
        try:
            tags_input = form_dict.get("tags")
            if isinstance(tags_input, str):
                tags_data_list = json.loads(tags_input)
            else:
                tags_data_list = tags_input

            new_tag_ids = set()
            for t in tags_data_list:
                if isinstance(t, dict) and t.get('id'):
                    new_tag_ids.add(int(t.get('id')))
                elif isinstance(t, (int, str)):
                    new_tag_ids.add(int(t))

            current_associations = RuleTagAssociation.query.filter_by(rule_id=rule.id).all()
            current_tag_ids = {assoc.tag_id for assoc in current_associations}

            for assoc in current_associations:
                if assoc.tag_id not in new_tag_ids:
                    db.session.delete(assoc)

            for tag_id in new_tag_ids:
                if tag_id not in current_tag_ids:
                    new_assoc = RuleTagAssociation(
                        uuid=str(uuid.uuid4()),
                        rule_id=rule.id,
                        tag_id=tag_id,
                        user_id=current_user.id,
                        added_at=datetime.datetime.now(tz=datetime.timezone.utc)
                    )
                    db.session.add(new_assoc)
                    
        except Exception as e:
            pass

    db.session.commit()
    return True, rule

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

    rules = Rule.query.filter(Rule.id.in_(rule_ids)).all()

    sources = []
    seen_sources = set()

    for rule in rules:
        src = rule.source
        if src and src not in seen_sources and is_valid_github_url(src):
            sources.append(src)
            seen_sources.add(src)

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

def get_rule(id, include_deleted=False) -> Rule:
    """Return the rule from id"""
    if include_deleted:
        return Rule.query.get(id)
    return _active().filter(Rule.id == id).first()

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

def _normalize_github_url(url: str) -> str:
    """Strip trailing slash and .git suffix for consistent URL comparison."""
    if not url:
        return url
    url = url.rstrip('/')
    if url.endswith('.git'):
        url = url[:-4]
    return url.rstrip('/')


def get_rule_from_a_github(title, filepath_in_the_repo, repo_source, original_uuid, content=None) -> tuple[Rule | None, str]:
    clean_uuid = str(original_uuid).strip().lower()
    forbidden = ["none", "null", "unknown", "n/a", "undefined", ""]

    if original_uuid and clean_uuid not in forbidden:
        rule = Rule.query.filter_by(original_uuid=original_uuid).first()
        if rule:
            return rule, "Rule found in Rulezet with this original_uuid"

    # Content match is the strongest signal available — a rule renamed or
    # moved to a different path/file upstream still has byte-identical
    # content. Checking this before the title/path heuristics below is what
    # keeps "new rule found" from flagging something add_rule_core() would
    # immediately reject as "already exists (content matches)".
    if content:
        rule = get_rule_by_content(content)
        if rule:
            return rule, "Rule found in Rulezet with matching content"

    # Build a set of equivalent URLs to handle .git suffix mismatches
    norm_source = _normalize_github_url(repo_source)
    source_variants = list({repo_source, norm_source}) if norm_source != repo_source else [repo_source]

    # check by github_path first — most reliable for NSE/formats without uuid
    if filepath_in_the_repo:
        # normalize: use only the filename as fallback
        normalized = os.path.basename(filepath_in_the_repo)
        rule = Rule.query.filter(
            Rule.source.in_(source_variants)
        ).filter(
            db.or_(
                Rule.github_path == filepath_in_the_repo,
                Rule.github_path == normalized,
                Rule.github_path.like(f"%{normalized}")
            )
        ).first()
        if rule:
            return rule, "Rule found in Rulezet with this github_path"

    # check by title + source
    query = Rule.query.filter(Rule.title == title, Rule.source.in_(source_variants))
    count_title = query.count()

    if count_title == 0:
        return None, "[new rule]"
    if count_title == 1:
        rule = query.first()
        # Compare normalized paths to avoid absolute-vs-relative mismatches
        stored_basename = os.path.basename(rule.github_path) if rule.github_path else None
        repo_basename = os.path.basename(filepath_in_the_repo) if filepath_in_the_repo else None
        if rule.github_path and filepath_in_the_repo:
            if rule.github_path != filepath_in_the_repo and stored_basename != repo_basename:
                return None, "[new rule]"
        return rule, "Rule found in Rulezet with this title"

    query_path = query.filter(
        db.or_(
            Rule.github_path == filepath_in_the_repo,
            Rule.github_path.like(f"%{os.path.basename(filepath_in_the_repo)}") if filepath_in_the_repo else False
        )
    )
    count_path = query_path.count()

    if count_path == 1:
        return query_path.first(), "Rule found in Rulezet with this title and this github_path"
    if count_path > 1:
        return None, "Impossible to find the real rule — multiple rules found"

    return None, "[new rule]"


def get_rule_by_source(source_) -> str:
    """Return all active (non-deleted) rules from the source."""
    return _active().filter(Rule.source == source_).all()

def get_related_rules_meta(rule):
    """Check whether other active rules share this rule's source, falling back to
    its author when the source doesn't match anything else.
    Returns (matched_field, matched_value, total_count) — matched_field is 'source',
    'author' or None. Uses the same substring (ILIKE) matching as filter_rules()/
    get_rules_data_table() so total_count matches what /rule/data_table will
    paginate over when the detail page points its <rule-list> widget at it."""
    base = _active().filter(Rule.id != rule.id)
    if rule.source:
        total = base.filter(Rule.source.ilike(f"%{rule.source}%")).count()
        if total:
            return 'source', rule.source, total
    if rule.author:
        total = base.filter(Rule.author.ilike(f"%{rule.author}%")).count()
        if total:
            return 'author', rule.author, total
    return None, None, 0

def get_rule_id_by_title(title) -> int:
    """Return the rule ID from the title"""
    rule = Rule.query.filter_by(title=title).first()
    return rule.id if rule else None

def get_total_rules_count() -> int:
    """Return the count of active (non-deleted) rules."""
    return _active().count()

def get_rule_user_id(rule_id: int) -> int:
    """Return the user id (the user who import or create this rule) of the rule """
    rule = get_rule(rule_id)
    if rule:
        return rule.user_id  
    return None  

def get_last_rules_from_db(limit=12) -> Rule:
    """Get last rules (non-deleted only)."""
    return _active().order_by(
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
    return _active().filter(Rule.source == source, Rule.user_id == current_user.id).paginate(page=page, per_page=30, max_per_page=30)

def get_concerned_rule_count(source):
    return _active().filter(Rule.source == source, Rule.user_id == current_user.id).count()

def get_concerned_rules_admin_page(source, page, user_id_concerned):
    return _active().filter(Rule.source == source, Rule.user_id == user_id_concerned).paginate(page=page, per_page=30, max_per_page=30)

def get_all_rules_by_user(user_id) -> Rule:
    return _active().filter(Rule.user_id == user_id).all()

def get_concerned_rule_admin_count(source, page, user_id_concerned):
    return _active().filter(Rule.source == source, Rule.user_id == user_id_concerned).count()

def get_concerned_rules(source):
    return _active().filter(Rule.source == source, Rule.user_id == current_user.id).all()

def get_concerned_rules_admin(source, user_id_to_send):
    return _active().filter(Rule.source == source, Rule.user_id == user_id_to_send).all()

def get_rules_by_ids(rule_ids) -> list:
    """Get all the rules with id"""
    rule_list = []
    for rule_id in rule_ids:
        rule = get_rule(rule_id)
        if rule:
            rule_list.append(rule)
        
    return rule_list
            

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

        sourceFilter = sourceFilter.rstrip("/")
        if sourceFilter.endswith(".git"):
            sourceFilter = sourceFilter[:-4]

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

def get_rules_page_favorite(page, id_user, search=None, author=None, sort_by=None, rule_type=None, per_page=30):
    """Get paginated favorite rules of a user with optional filters"""

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


##########################
#   Voted (liked) rule   #
##########################

def get_rules_page_voted(page, id_user, vote_type=None, search=None, author=None, rule_type=None, per_page=30):
    """Get paginated rules the user has liked/disliked.

    vote_type: 'up' (liked), 'down' (disliked), or None/'both' for either.
    """
    query = _active()\
        .join(RuleVote, Rule.id == RuleVote.rule_id)\
        .filter(RuleVote.user_id == id_user)

    if vote_type in ('up', 'down'):
        query = query.filter(RuleVote.vote_type == vote_type)

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

    query = query.order_by(RuleVote.created_at.desc())

    return query.paginate(page=page, per_page=per_page, error_out=False)


#########################
#   Propose edit rule   #
#########################

# CRUD

# Create
def propose_edit_core(form , user_id) -> bool:
    """create an issue for a rule"""
    if not form or not user_id:
        return False , None
    rule_id = form.get("rule_id")
    if not rule_id:
        return False , None
    rule = get_rule(rule_id)
    if not rule:
        return False , None
    
    proposed_content = form.get("proposed_content") or rule.to_string or "No content provided"
    message = form.get("message") or "No message provided"
    timestamp = datetime.datetime.now(tz=datetime.timezone.utc) or form.get("timestamp")
    status = form.get("status") or "pending"
    edit_type = form.get("edit_type") or "content_update"
    change_score = calculate_diff_score(rule.to_string or "", proposed_content)
    

    new_proposal = RuleEditProposal(
        rule_id=rule_id,
        user_id=user_id,
        proposed_content=proposed_content,
        old_content =rule.to_string,
        edit_type=edit_type,
        message=message,
        timestamp=timestamp,
        status=status,
        change_score=change_score or 0.0,
    )
    db.session.add(new_proposal)
    db.session.commit()
    return True , new_proposal.id


def bulk_manage_proposals(action: str, mode: str, selected_ids: list, excluded_ids: list, reviewed_by_id: int, is_admin: bool = False) -> dict:
    """Bulk accept or reject proposals.

    Non-admins may only ever affect proposals against rules they own — this
    is enforced at the query level (not just checked-and-skipped per item)
    so "mode=all" for a regular user means "all of my rules' pending
    proposals", never every pending proposal system-wide.
    """
    import datetime

    try:
        if mode == "all":
            query = RuleEditProposal.query.filter_by(status="pending")
            if not is_admin:
                query = query.join(Rule, Rule.id == RuleEditProposal.rule_id).filter(Rule.user_id == reviewed_by_id)
            if excluded_ids:
                query = query.filter(~RuleEditProposal.id.in_(excluded_ids))
            proposals = query.all()
        else:
            query = RuleEditProposal.query.filter(
                RuleEditProposal.id.in_(selected_ids),
                RuleEditProposal.status == "pending"
            )
            if not is_admin:
                query = query.join(Rule, Rule.id == RuleEditProposal.rule_id).filter(Rule.user_id == reviewed_by_id)
            proposals = query.all()

        if not proposals:
            return {"success": False, "message": "No proposals found."}

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        count = 0

        for proposal in proposals:
            # Ownership already enforced above at the query level for
            # non-admins; this just fetches the rule to update its content.
            rule = get_rule(proposal.rule_id)
            if not rule:
                continue
            if not is_admin and rule.user_id != reviewed_by_id:
                continue

            proposal.status = "accepted" if action == "accept" else "rejected"
            proposal.reviewed_by_id = reviewed_by_id
            proposal.reviewed_at = now

            if action == "accept":
                # update the rule content
                rule.to_string = proposal.proposed_content
                db.session.add(rule)

                # contribution
                create_contribution(proposal.user_id, proposal.id)

                # history
                result = {
                    "id": rule.id,
                    "title": rule.title,
                    "success": True,
                    "message": "accepted",
                    "new_content": proposal.proposed_content,
                    "old_content": proposal.old_content,
                    "manual_submit": True,
                }
                create_rule_history(result)

                # gamification
                gamification = AccountModel.get_or_create_gamification_profile(proposal.user_id)
                if gamification:
                    AccountModel.update_propose_edit_gamification(gamification.id, "add_one_to_accepted")
            else:
                # gamification
                gamification = AccountModel.get_or_create_gamification_profile(proposal.user_id)
                if gamification:
                    AccountModel.update_propose_edit_gamification(gamification.id, "add_one_to_rejected")

            db.session.add(proposal)
            count += 1

        db.session.commit()
        action_label = "accepted" if action == "accept" else "rejected"
        return {"success": True, "message": f"{count} proposal(s) {action_label} successfully."}

    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Error: {str(e)}"}


def calculate_diff_score(old_content, new_content) -> float:
    from rapidfuzz import fuzz
    return round(fuzz.ratio(old_content, new_content), 2)

# Read

def get_rules_edit_propose_page(page) -> RuleEditProposal:
    return RuleEditProposal.query.join(RuleEditProposal.rule).filter(
        Rule.user_id == current_user.id,
        Rule.is_deleted == False,
        RuleEditProposal.status != 'pending'
    ).paginate(page=page, per_page=20, max_per_page=20)

def get_rules_edit_propose_page_pending(page) -> RuleEditProposal:
    return RuleEditProposal.query.join(Rule).filter(
        Rule.user_id == current_user.id,
        Rule.is_deleted == False,
        RuleEditProposal.status == 'pending'
    ).options(joinedload(RuleEditProposal.rule)).paginate(page=page, per_page=20, max_per_page=20)

def get_rules_edit_propose_page_admin(page) -> RuleEditProposal:
    return RuleEditProposal.query.join(RuleEditProposal.rule).filter(
        Rule.is_deleted == False,
        RuleEditProposal.status != 'pending'
    ).paginate(page=page, per_page=20, max_per_page=20)

def get_rules_edit_propose_page_pending_admin(page) -> RuleEditProposal:
    return RuleEditProposal.query.join(RuleEditProposal.rule).filter(
        Rule.is_deleted == False,
        RuleEditProposal.status == 'pending'
    ).paginate(page=page, per_page=20, max_per_page=20)

def get_all_rules_edit_propose_page(page, rule_id) -> RuleEditProposal:
    return RuleEditProposal.query.join(RuleEditProposal.rule).filter(
        RuleEditProposal.rule_id == rule_id,
        Rule.is_deleted == False,
    ).paginate(page=page, per_page=20, max_per_page=20)
def get_rule_proposal(id) -> RuleEditProposal:
    """Return the rule"""
    return RuleEditProposal.query.get(id)

def get_rule_proposal_user_id(proposal_id) -> id:
    """Get the user id of a proposal"""
    rule_proposal = get_rule_proposal(proposal_id)
    if not rule_proposal:
        return None
    return rule_proposal.user_id

def get_all_rule_proposal_user_id(user_id) -> RuleEditProposal:
    """Get all the rule edit porposal where the current user has part of """
    return RuleEditProposal.query.filter(RuleEditProposal.user_id == user_id).all()

def get_my_proposals_page(page: int, user_id: int, search: str = '', status: str = ''):
    query = RuleEditProposal.query.filter_by(user_id=user_id)
    if search:
        query = query.join(Rule, RuleEditProposal.rule_id == Rule.id).filter(
            db.or_(
                Rule.title.ilike(f'%{search}%'),
                RuleEditProposal.message.ilike(f'%{search}%')
            )
        )
    if status:
        query = query.filter(RuleEditProposal.status == status)
    return query.order_by(RuleEditProposal.timestamp.desc()).paginate(page=page, per_page=10, error_out=False)


def get_rules_propose_edit_page(page: int, user_id: int, is_admin: bool = False):
    """Pending proposals — admin sees all, owner sees only proposals on their rules"""
    query = RuleEditProposal.query.filter_by(status='pending')
    if not is_admin:
        owned_rule_ids = db.session.query(Rule.id).filter_by(user_id=user_id)
        query = query.filter(RuleEditProposal.rule_id.in_(owned_rule_ids))
    return query.order_by(RuleEditProposal.timestamp.desc()).paginate(page=page, per_page=10, error_out=False)
def get_all_rules_edit_propose_user_part_from_page(page: int, user_id: int, search: str = '', status: str = '') -> list:
    """Get all proposals where the user participated (submitted or commented)"""

    # proposals submitted by the user
    submitted_ids = db.session.query(RuleEditProposal.id).filter_by(user_id=user_id)

    # proposals where the user commented
    commented_ids = db.session.query(RuleEditComment.proposal_id).filter_by(user_id=user_id)

    query = RuleEditProposal.query.filter(
        db.or_(
            RuleEditProposal.id.in_(submitted_ids),
            RuleEditProposal.id.in_(commented_ids)
        )
    )

    if search:
        query = query.join(Rule, RuleEditProposal.rule_id == Rule.id).filter(
            db.or_(
                Rule.title.ilike(f'%{search}%'),
                RuleEditProposal.message.ilike(f'%{search}%')
            )
        )

    if status:
        query = query.filter(RuleEditProposal.status == status)

    return query.order_by(RuleEditProposal.timestamp.desc()).paginate(page=page, per_page=10, error_out=False)

def get_rules_propose_edit_history_page(page: int, search: str = '', status: str = '',
                                         user_id: int = None, is_admin: bool = False):
    query = RuleEditProposal.query.filter(
        RuleEditProposal.status.in_(['accepted', 'rejected', 'pending'])
    )

    # filter by ownership unless admin
    if not is_admin and user_id:
        owned_rule_ids = db.session.query(Rule.id).filter_by(user_id=user_id)
        query = query.filter(RuleEditProposal.rule_id.in_(owned_rule_ids))

    if search:
        query = query.join(Rule, RuleEditProposal.rule_id == Rule.id).filter(
            db.or_(
                Rule.title.ilike(f'%{search}%'),
                RuleEditProposal.message.ilike(f'%{search}%')
            )
        )

    if status:
        query = query.filter(RuleEditProposal.status == status)

    total_pending = query.filter(RuleEditProposal.status == 'pending').count()

    return query.order_by(RuleEditProposal.timestamp.desc()).paginate(
        page=page, per_page=10, error_out=False
    ), total_pending

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

def has_already_vote(rule_id, user_id):
    """Return (already_voted: bool, vote_type: str|None)"""
    vote = RuleVote.query.filter_by(rule_id=rule_id, user_id=user_id).first()
    if vote:
        return True, vote.vote_type
    return False, None

def process_vote(rule_id, user_id, vote_type):
    """
    Handle a vote in a single DB round-trip + single commit.
    Returns (vote_up, vote_down, like_delta, dislike_delta).
    """
    rule = get_rule(rule_id)
    if not rule:
        return None

    existing_vote = RuleVote.query.filter_by(rule_id=rule_id, user_id=user_id).first()

    like_delta = 0
    dislike_delta = 0

    if vote_type == 'up':
        if existing_vote is None:
            rule.vote_up += 1
            db.session.add(RuleVote(rule_id=rule_id, user_id=user_id, vote_type='up'))
            like_delta = 1
        elif existing_vote.vote_type == 'up':
            rule.vote_up -= 1
            db.session.delete(existing_vote)
            like_delta = -1
        else:
            # switch down → up
            rule.vote_up += 1
            rule.vote_down -= 1
            existing_vote.vote_type = 'up'
            like_delta = 1
            dislike_delta = -1

    elif vote_type == 'down':
        if existing_vote is None:
            rule.vote_down += 1
            db.session.add(RuleVote(rule_id=rule_id, user_id=user_id, vote_type='down'))
            dislike_delta = 1
        elif existing_vote.vote_type == 'down':
            rule.vote_down -= 1
            db.session.delete(existing_vote)
            dislike_delta = -1
        else:
            # switch up → down
            rule.vote_down += 1
            rule.vote_up -= 1
            existing_vote.vote_type = 'down'
            dislike_delta = 1
            like_delta = -1

    db.session.commit()
    return rule.vote_up, rule.vote_down, like_delta, dislike_delta


#############
#   Filter  #
#############

def parse_facet_filters(args, exclude=()) -> dict:
    """Build filter_rules() kwargs from Flask's request.args — this is what
    lets every sidebar facet (tags, sources, licenses, CVEs, ATT&CK,
    authors/editors) stay scoped to the rules matching every OTHER currently
    active filter, instead of counting across the whole table.

    `exclude` names the dimension a given facet endpoint is itself counting
    (e.g. 'tags' for the tags endpoint) — that dimension's own filter must
    never be applied to its own count, or picking one value would hide every
    other value in the same dropdown.
    """
    def _csv(key):
        v = (args.get(key) or '').strip()
        return [x.strip() for x in v.split(',') if x.strip()] or None

    ids_csv = _csv('ids')

    filters = {
        'search':          args.get('search') or None,
        'search_field':    args.get('search_field') or 'all',
        'exact_match':     args.get('exact_match') == 'true',
        'rule_type':       args.get('rule_type') or None,
        'source':          _csv('sources'),
        'license':         _csv('licenses'),
        'tags':            _csv('tags'),
        'vulnerabilities': _csv('vulnerabilities'),
        'attacks':         _csv('attacks'),
        'author':          _csv('authors'),
        'editor_names':    _csv('editors'),
        'user_id':         args.get('user_id', type=int),
        'ids':             [int(i) for i in ids_csv if i.isdigit()] if ids_csv else None,
    }
    for key in exclude:
        filters[key] = None
    return filters


def filter_rules(search=None, search_field="all", author=None, sort_by=None, rule_type=None, vulnerabilities: list[str] | None = None, source=None, user_id=None, license=None, tags: list[str] | None = None, exact_match=False, editor_names: list[str] | None = None, bundle_id=None, attacks: list[str] | None = None, status=None, workspace_uuid=None, exclude_workspace_uuid=None, ids: list[int] | None = None) -> Rule:
    """Filter the rules with specific field targeting"""
    query = _active()

    if ids:
        query = query.filter(Rule.id.in_(ids))

    if search:
        search = search.strip()



        if exact_match is True:

            if search_field == "title":
                # Strict case-sensitive equality
                query = query.filter(Rule.title == search)

            elif search_field == "content":
                # Case-sensitive exact substring match
                query = query.filter(Rule.to_string.like(f"%{search}%"))

            else:
                # If "all":
                # Title = strict equality
                # Content = case-sensitive substring
                query = query.filter(
                    or_(
                        Rule.title == search,
                        Rule.to_string.like(f"%{search}%")
                    )
                )

        search_lower = f"%{search.lower()}%"
        
        if search_field == "title":
            query = query.filter(Rule.title.ilike(search_lower))
        elif search_field == "content":
            query = query.filter(Rule.to_string.ilike(search_lower))
        else:
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

    if tags:
        tags_lowercase = [t.lower() for t in tags]

        found_tags = Tag.query.filter(
            func.lower(Tag.name).in_(tags_lowercase)
        ).all()
        
        tag_ids = [tag.id for tag in found_tags]

        if tag_ids:
            query = query.join(RuleTagAssociation).filter(
                RuleTagAssociation.tag_id.in_(tag_ids)
            ).distinct()
        else:
            # Tag requested but doesn't exist in DB → no rules can match
            query = query.filter(False)

    if attacks:
        from app.core.db_class.db import RuleAttackAssociation as _RAA
        upper = [a.upper() for a in attacks]
        query = (query
                 .join(_RAA, _RAA.rule_id == Rule.id)
                 .filter(_RAA.technique_id.in_(upper))
                 .distinct())

    if source:
        source_list = [s.strip() for s in source.split(',')] if isinstance(source, str) else source
        query = query.filter(or_(*[Rule.source.ilike(f"%{s}%") for s in source_list]))

    if license:
        license_list = [l.strip() for l in license.split(',')] if isinstance(license, str) else license
        query = query.filter(or_(*[Rule.license.ilike(f"%{l}%") for l in license_list]))

    if author:
        author_list = author if isinstance(author, list) else [author]
        query = query.filter(or_(*[Rule.author.ilike(f"%{a}%") for a in author_list]))

    if editor_names:
        editor_col = func.coalesce(User.username, func.concat(User.first_name, ' ', User.last_name))
        query = (query
                 .join(User, User.id == Rule.user_id)
                 .filter(or_(*[editor_col.ilike(f"%{e}%") for e in editor_names])))

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

    if bundle_id:
        query = query.join(BundleRuleAssociation, BundleRuleAssociation.rule_id == Rule.id).filter(
            BundleRuleAssociation.bundle_id == bundle_id
        )

    if workspace_uuid:
        from app.core.db_class.db import WorkspaceRule, Workspace
        from sqlalchemy import false as _false
        ws = Workspace.query.filter_by(uuid=workspace_uuid).first()
        if ws:
            ws_rule_ids = [wr.rule_id for wr in WorkspaceRule.query.filter_by(workspace_id=ws.id).all()]
            query = query.filter(Rule.id.in_(ws_rule_ids))
        else:
            query = query.filter(_false())

    if exclude_workspace_uuid:
        from app.core.db_class.db import WorkspaceRule, Workspace
        ex_ws = Workspace.query.filter_by(uuid=exclude_workspace_uuid).first()
        if ex_ws:
            ex_ids = [wr.rule_id for wr in WorkspaceRule.query.filter_by(workspace_id=ex_ws.id).all()]
            if ex_ids:
                query = query.filter(~Rule.id.in_(ex_ids))

    if status:
        query = query.filter(Rule.status == status)

    return query




def get_rules_page_filter_bundle_page(search=None, author=None, sort_by=None, rule_type=None,page=1, bundle_id=None, per_page=10) -> Rule:
    """Filter the rules"""
    query = _active()
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

def filter_rules_owner(search=None, author=None, sort_by=None, rule_type=None, source=None) -> Rule:
    """Filter the rules"""
    query = _active().filter(Rule.user_id == current_user.id)
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
    query = _active().filter(Rule.user_id == current_user.id)

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

def add_comment_core(rule_id, content, user, parent_comment_id=None):
    if not content.strip():
        return False, "Comment cannot be empty."
    comment = Comment(
        uuid=str(uuid.uuid4()),
        rule_id=rule_id,
        user_id=user.id,
        user_name=user.first_name + " " + (user.last_name or ""),
        content=content.strip(),
        created_at=datetime.datetime.now(tz=datetime.timezone.utc),
        updated_at=datetime.datetime.now(tz=datetime.timezone.utc),
        parent_comment_id=parent_comment_id,
    )
    db.session.add(comment)
    db.session.commit()

    try:
        rule = _active().filter_by(id=rule_id).first()
        link = f'/rule/detail_rule/{rule_id}'
        from app.features.notification.notification_core import (
            notify_owner_new_comment, notify_followers_new_comment, notify_comment_reply)
        if rule:
            notify_owner_new_comment(rule.user_id, user.id, 'rule_comment', rule.title, link)
        notify_followers_new_comment(user.id, rule.title if rule else '', link, is_public=True)
        if parent_comment_id:
            parent = Comment.query.get(parent_comment_id)
            if parent:
                notify_comment_reply(parent.user_id, user.id, rule.title if rule else '', link)
    except Exception as _e:
        print(f"[rule_core] add_comment_core notification error: {_e}")

    return True, "Comment posted successfully."


def get_comment_by_id(comment_id) -> Comment | None:
    return Comment.query.get(comment_id)


def get_comments_for_rule(rule_id, page, user_id=None):
    """Paginated top-level comments (no replies) — mirrors bundle system."""
    pagination = (Comment.query
                  .filter_by(rule_id=rule_id, parent_comment_id=None)
                  .order_by(Comment.created_at.desc())
                  .paginate(page=page, per_page=10))
    return pagination, [c.to_json(user_id=user_id) for c in pagination.items]


def get_comment_page(page, rule_id) -> object:
    return Comment.query.filter_by(rule_id=rule_id).paginate(page=page, per_page=20, max_per_page=20)


def get_total_comments_count() -> int:
    return Comment.query.count()


def get_latest_comment_for_user_and_rule(user_id: int, rule_id: int) -> Comment | None:
    return Comment.query.filter_by(user_id=user_id, rule_id=rule_id).order_by(Comment.id.desc()).first()


def update_comment(comment_id, new_content) -> Comment | None:
    comment = get_comment_by_id(comment_id)
    if comment:
        comment.content = new_content
        comment.updated_at = datetime.datetime.now(tz=datetime.timezone.utc)
        db.session.commit()
    return comment


def delete_comment(comment_id) -> bool:
    comment = get_comment_by_id(comment_id)
    if comment:
        db.session.delete(comment)
        db.session.commit()
        return True
    return False


def add_reaction_to_rule_comment(comment_id, user_id, reaction_type):
    from app.core.db_class.db import RuleCommentReaction
    comment = get_comment_by_id(comment_id)
    if not comment:
        return False, "Comment not found"

    existing = RuleCommentReaction.query.filter_by(
        comment_id=comment_id, user_id=user_id, reaction_type=reaction_type).first()

    if existing:
        # toggle off
        db.session.delete(existing)
        if reaction_type == 'like':
            comment.likes = max(0, (comment.likes or 0) - 1)
        elif reaction_type == 'dislike':
            comment.dislikes = max(0, (comment.dislikes or 0) - 1)
        db.session.commit()
        return True, f"Removed {reaction_type}"

    # remove opposite vote first
    if reaction_type in ('like', 'dislike'):
        opposite = 'dislike' if reaction_type == 'like' else 'like'
        opp = RuleCommentReaction.query.filter_by(
            comment_id=comment_id, user_id=user_id, reaction_type=opposite).first()
        if opp:
            db.session.delete(opp)
            if opposite == 'like':
                comment.likes = max(0, (comment.likes or 0) - 1)
            else:
                comment.dislikes = max(0, (comment.dislikes or 0) - 1)

    db.session.add(RuleCommentReaction(
        uuid=str(uuid.uuid4()),
        rule_id=comment.rule_id,
        comment_id=comment_id,
        user_id=user_id,
        reaction_type=reaction_type,
    ))
    if reaction_type == 'like':
        comment.likes = (comment.likes or 0) + 1
    elif reaction_type == 'dislike':
        comment.dislikes = (comment.dislikes or 0) + 1
    db.session.commit()
    return True, f"Added {reaction_type}"

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

def create_repport(user_id, rule_id, message, reason):
    """Create a new report, unless an identical one already exists.
    Returns (report, is_new): is_new=False when a duplicate was found."""

    existing = RepportRule.query.filter_by(
        user_id=user_id,
        rule_id=rule_id,
        message=message,
        reason=reason
    ).first()

    if existing:
        return existing, False

    repport = RepportRule(
        user_id=user_id,
        rule_id=rule_id,
        message=message,
        reason=reason,
        created_at=datetime.datetime.now(datetime.timezone.utc)
    )
    db.session.add(repport)
    db.session.commit()
    return repport, True



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
        return None

def was_last_history_manuel(rule_id):
    """
    Return True if the last history entry for the given rule_id was a manual submission, False otherwise.
    """
    history_rule = RuleUpdateHistory.query.filter_by(rule_id=rule_id)\
                                          .order_by(RuleUpdateHistory.id.desc())\
                                          .first()
    if history_rule and history_rule.manuel_submit:
        return True
    return False

def manage_history_rule(rule_id: int, manual_submit: bool) -> bool:
    """Set the manual_submit flag on the last history entry for the given rule."""
    history_rule = RuleUpdateHistory.query.filter_by(rule_id=rule_id)\
                                          .order_by(RuleUpdateHistory.id.desc())\
                                          .first()
    if not history_rule:
        return False

    history_rule.manuel_submit = manual_submit
    db.session.commit()
    return history_rule.manuel_submit

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
    counts = dict(
        db.session.query(
            func.lower(func.trim(Rule.format)),
            func.count(Rule.id)
        )
        .group_by(func.lower(func.trim(Rule.format)))
        .all()
    )

    formats = (
        FormatRule.query
        .filter(FormatRule.name != 'no format')
        .order_by(FormatRule.name.asc())
        .all()
    )

    result = []
    for fmt in formats:
        data = fmt.to_json_light()  
        data['number_of_rule_with_this_format'] = counts.get(fmt.name.lower(), 0)
        result.append(data)

    return result

# def get_last_cve_rules(limit: int = 12) -> list:
#    
#     return (
#         Rule.query
#         .filter(
#             Rule.cve_id.isnot(None),
#             ~Rule.cve_id.in_(['', '[]', 'null', '[""]'])
#         )
#         .order_by(Rule.last_modif.desc())
#         .limit(limit)
#         .all()
#     )


def get_last_cve_rules(limit: int = 12) -> list:

    def extract_max_cve_year(rule):
        if not rule.cve_id:
            return 0
        years = re.findall(r'CVE-(\d{4})-', rule.cve_id, re.IGNORECASE)
        return max((int(y) for y in years), default=0)

    rules = (
        _active()
        .filter(
            Rule.cve_id.isnot(None),
            ~Rule.cve_id.in_(['', '[]', 'null', '[""]'])
        )
        .all()
    )

    rules.sort(
        key=lambda r: (extract_max_cve_year(r), r.last_modif or datetime.datetime.min),
        reverse=True
    )

    return rules[:limit]

def get_all_rule_format_with_count():
    """Return formats as dicts with rule count — for API use only."""
    from sqlalchemy import func
    counts = dict(
        db.session.query(
            func.lower(func.trim(Rule.format)),
            func.count(Rule.id)
        )
        .group_by(func.lower(func.trim(Rule.format)))
        .all()
    )
    formats = get_all_rule_format()
    result = []
    for fmt in formats:
        data = fmt.to_json_light()
        data['number_of_rule_with_this_format'] = counts.get(fmt.name.lower(), 0)
        result.append(data)
    return result


def get_all_rule_format_page(page):
    """Get all rule format in page (20 per pages)"""
    return FormatRule.query.paginate(page=page, per_page=20, error_out=False)


def get_rule_format_with_id(id):
    """Get the rule format with id"""
    return FormatRule.query.get(id)

def add_format_rule(format_name: str, user_id: int, can_be_execute: bool) -> tuple[bool, str]:
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

def get_optimized_github_data(page: int = 1, search: str = None, search_field: str = 'url', format_filter: str = None, author_filter: str = None):
    github_pattern = r'^https?://(www\.)?github\.com/[\w\-_]+/[\w\-_]+'
    author_expr = func.substring(Rule.source, r'github\.com/([^/]+)')
    query = db.session.query(
        Rule.source.label("url"),
        author_expr.label("author"),
        func.count(Rule.id).label("rule_count"),
        func.string_agg(Rule.format.distinct(), text("','")).label("formats"),
        func.sum(
            case(
                (and_(Rule.cve_id.isnot(None), Rule.cve_id != '[]', Rule.cve_id != ''), 1),
                else_=0
            )
        ).label("cve_count"),
        func.max(
            db.session.query(func.count(RuleSimilarity.id))
            .filter(RuleSimilarity.rule_id == Rule.id)
            .filter(RuleSimilarity.score > 0.99)
            .as_scalar()
        ).label("has_high_similarity")
    ).filter(Rule.source.op('~')(github_pattern), Rule.is_deleted == False)

    if format_filter:
        query = query.filter(Rule.format == format_filter)

    if author_filter and author_filter != "":
        query = query.filter(author_expr.ilike(f"%{author_filter}%"))

    if search:
        if search_field == 'url':
            query = query.filter(Rule.source.ilike(f"%{search}%"))
        else:
            query = query.filter(
                or_(
                    Rule.source.ilike(f"%{search}%"),
                    Rule.format.ilike(f"%{search}%"),
                    Rule.title.ilike(f"%{search}%")
                )
            )

    query = query.group_by(Rule.source)
    
    pagination = query.paginate(page=page, per_page=20)
    
    github_data = []
    for row in pagination.items:
        url = row.url
        
        last_import = ImporterResult.query.filter(ImporterResult.info.ilike(f"%{url}%"))\
            .order_by(ImporterResult.query_date.desc()).first()
            
        last_update = UpdateResult.query.filter(
            or_(
                UpdateResult.info.ilike(f"%{url}%"),
                UpdateResult.repo_sources.ilike(f"%{url}%")
            )
        ).order_by(UpdateResult.query_date.desc()).first()

        github_data.append({
            "url": url,
            "author": row.author,
            "rule_count": row.rule_count,
            "formats": row.formats.split(',') if row.formats else [],
            "cve_count": row.cve_count,
            "has_conflicts": (row.has_high_similarity or 0) > 0,
            "last_import": {
                "date": last_import.query_date.strftime('%Y-%m-%d %H:%M') if last_import else None,
                "url_imported": "/rule/import_loading/"+ last_import.uuid if last_import else None,
                "imported": last_import.imported if last_import else 0,
                "bad_rules": last_import.bad_rules if last_import else 0,
                "total": last_import.total if last_import else 0
            } if last_import else None,
            "last_update": {
                "date": last_update.query_date.strftime('%Y-%m-%d %H:%M') if last_update else None,
                "updated": last_update.updated if last_update else 0,
                "url_updated": "/rule/update_loading/"+ last_update.uuid if last_update else None,
                "new_rules_count": len(last_update.new_rules) if last_update else 0,
                "found": last_update.found if last_update else 0
            } if last_update else None
        })

    return github_data, pagination.total, pagination.pages


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
            .filter(Rule.is_deleted == False)
        )

        if search:
            query = query.filter(Rule.source.ilike(f"%{search}%"))

        query = query.group_by(Rule.source).order_by(func.count(Rule.id).desc())

        total_count = query.count()
        pagination = query.paginate(page=page, per_page=20, max_per_page=20)

        return pagination, total_count

_DATA_TABLE_SORT_KEYS = {
    'title':         Rule.title,
    'author':        Rule.author,
    'format':        Rule.format,
    'license':       Rule.license,
    'creation_date': Rule.creation_date,
    'last_modif':    Rule.last_modif,
    'vote_up':       Rule.vote_up,
}


def get_rules_data_table(page=1, per_page=10, search=None, sort=None,
                         direction='asc', source=None, user_id=None,
                         search_field='all', exact_match=False, rule_type=None,
                         author=None, vulnerabilities=None, licenses=None,
                         tags=None, editor_names=None, bundle_id=None, attacks=None,
                         status=None, workspace_uuid=None, exclude_workspace_uuid=None,
                         ids=None, has_cve=False):
    """Generic paginated / searchable / sortable rule listing consumed by the
    rule-data-table component. Filtering is delegated to filter_rules() so the
    advanced filter bar (tags, licenses, vulnerabilities, sources, exact
    match…) works identically everywhere. Returns a pagination object."""
    query = filter_rules(
        search=search,
        search_field=search_field or 'all',
        author=author,
        sort_by='newest',
        rule_type=rule_type,
        vulnerabilities=vulnerabilities,
        source=source,
        user_id=user_id,
        license=licenses,
        tags=tags,
        exact_match=exact_match,
        editor_names=editor_names,
        bundle_id=bundle_id,
        attacks=attacks,
        status=status,
        workspace_uuid=workspace_uuid,
        exclude_workspace_uuid=exclude_workspace_uuid,
        ids=ids,
    )

    if ids:
        from app.core.db_class.db import Rule as _Rule
        query = query.filter(_Rule.id.in_(ids))

    if has_cve:
        query = query.filter(
            Rule.cve_id.isnot(None),
            ~Rule.cve_id.in_(['', '[]', 'null', '[""]']),
        )

    col = _DATA_TABLE_SORT_KEYS.get(sort)
    if col is not None:
        # Replace filter_rules' default ordering with the requested column sort
        query = query.order_by(None).order_by(
            col.desc() if direction == 'desc' else col.asc()
        )

    per_page = max(1, min(100, per_page))
    return query.paginate(page=page, per_page=per_page, error_out=False)


def get_active_rules_by_ids(ids: list) -> list:
    """Active (non-deleted) rules matching the given id list."""
    if not ids:
        return []
    return _active().filter(Rule.id.in_(ids)).all()


def get_github_source_stats(url: str) -> dict:
    """Aggregate stats about all rules imported from one GitHub source URL —
    feeds the header of the GitHub source dashboard page."""
    url = url.rstrip('/')
    if url.endswith('.git'):
        url = url[:-4]
    source_filter = or_(
        Rule.source.ilike(f"{url}%"),
        Rule.source.ilike(f"{url}.git%"),
    )
    base = _active().filter(source_filter)

    total = base.count()
    formats = (
        db.session.query(Rule.format, func.count(Rule.id))
        .filter(Rule.is_deleted == False, source_filter)
        .group_by(Rule.format)
        .order_by(func.count(Rule.id).desc())
        .all()
    )
    authors_count = (
        db.session.query(func.count(func.distinct(Rule.author)))
        .filter(Rule.is_deleted == False, source_filter)
        .scalar()
    ) or 0
    licenses_count = (
        db.session.query(func.count(func.distinct(Rule.license)))
        .filter(Rule.is_deleted == False, source_filter, Rule.license.isnot(None))
        .scalar()
    ) or 0
    last = base.order_by(Rule.last_modif.desc()).first()
    first = base.order_by(Rule.creation_date.asc()).first()

    # Distinct CVEs referenced by this source's rules — cve_id is a JSON-encoded
    # list per rule (see add_rule_core()), so this can't be a plain SQL DISTINCT;
    # accumulate a set in Python instead. Bounded to this source's rule count,
    # not the whole table, so this stays cheap even on a large instance.
    rule_ids = [r_id for (r_id,) in base.with_entities(Rule.id).all()]
    cve_set = set()
    for (raw,) in base.with_entities(Rule.cve_id).all():
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                cve_set.update(v for v in parsed if v)
        except (TypeError, ValueError):
            pass

    attack_count = 0
    if rule_ids:
        attack_count = (
            db.session.query(func.count(func.distinct(RuleAttackAssociation.technique_id)))
            .filter(RuleAttackAssociation.rule_id.in_(rule_ids))
            .scalar()
        ) or 0

    return {
        'total_rules':    total,
        'formats':        [{'name': f or 'unknown', 'count': c} for f, c in formats],
        'authors_count':  authors_count,
        'licenses_count': licenses_count,
        'cve_count':      len(cve_set),
        'attack_count':   attack_count,
        'last_update':    last.last_modif.strftime('%Y-%m-%d %H:%M') if last else None,
        'first_import':   first.creation_date.strftime('%Y-%m-%d %H:%M') if first else None,
    }


def get_all_rule_by_url_github_page(page: int = 1, search: str = None, url: str = None):
    """Get paginated list of Rules whose source matches a specific GitHub project URL."""

    query = _active().filter(Rule.source.isnot(None))

    if url:
        url = url.rstrip("/")
        if url.endswith(".git"):
            url = url[:-4]
        query = query.filter(
            or_(
                Rule.source.ilike(f"{url}%"),
                Rule.source.ilike(f"{url}.git%")
            )
        )
    
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

def get_all_rule_by_url_github(url: str = None, current_user_: User = None):
    """Get list of Rules whose source contains a specific GitHub project URL."""
    query = _active().filter(Rule.source.isnot(None))

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
    query = _active().filter(
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

def get_updater_result_new_rule_page(sid: str, page: int, per_page: int = 30,
                                      f_syntax_valid=None,
                                      f_accept=None,
                                      f_error=None):
    """
    Retrieve paginated NewRule entries. Each filter is None (any) | True | False.
    """
    update_result = UpdateResult.query.filter_by(uuid=sid).first()
    if not update_result:
        return None

    q = _new_rule_still_pending_filter(
        NewRule.query.filter_by(update_result_id=update_result.id)
    )
    if f_syntax_valid is not None:
        q = q.filter(NewRule.rule_syntax_valid == f_syntax_valid)
    if f_accept is not None:
        q = q.filter(NewRule.accept == f_accept)
    if f_error is not None:
        q = q.filter(NewRule.error == f_error)
    return q.paginate(page=page, per_page=per_page, error_out=False)


def count_updates_available(sid: str) -> int:
    """Count RuleStatus rows with update_available=True for a session."""
    update_result = UpdateResult.query.filter_by(uuid=sid).first()
    if not update_result:
        return 0
    return RuleStatus.query.filter_by(
        update_result_id=update_result.id, update_available=True
    ).count()


def count_up_to_date(sid: str) -> int:
    """Count RuleStatus rows found with no pending update — i.e. currently up
    to date. Computed live (not the UpdateResult.skipped snapshot column,
    which is only ever set once when the scan itself finishes) so it reflects
    rules the user has since accepted/rejected too."""
    update_result = UpdateResult.query.filter_by(uuid=sid).first()
    if not update_result:
        return 0
    return RuleStatus.query.filter_by(
        update_result_id=update_result.id, found=True, update_available=False
    ).count()


def count_rules_not_found(sid: str) -> int:
    """Count RuleStatus rows never located in the repo. Live, same rationale
    as count_up_to_date()."""
    update_result = UpdateResult.query.filter_by(uuid=sid).first()
    if not update_result:
        return 0
    return RuleStatus.query.filter_by(
        update_result_id=update_result.id, found=False
    ).count()


def count_pending_new_rules(sid: str) -> int:
    """Count NewRule rows not yet imported or rejected for a session."""
    update_result = UpdateResult.query.filter_by(uuid=sid).first()
    if not update_result:
        return 0
    return _new_rule_still_pending_filter(
        NewRule.query.filter_by(update_result_id=update_result.id)
    ).count()


def get_updater_result_rule_page(sid: str, page: int, per_page: int = 30,
                                  f_update_available=None,
                                  f_found=None,
                                  f_error=None,
                                  f_syntax_valid=None):
    """Retrieve paginated RuleStatus entries. Each filter is None (any) | True | False."""
    update_result = UpdateResult.query.filter_by(uuid=sid).first()
    if not update_result:
        return None
    q = RuleStatus.query.filter_by(update_result_id=update_result.id)
    if f_update_available is not None:
        q = q.filter(RuleStatus.update_available == f_update_available)
    if f_found is not None:
        q = q.filter(RuleStatus.found == f_found)
    if f_error is not None:
        q = q.filter(RuleStatus.error == f_error)
    if f_syntax_valid is not None:
        q = q.filter(RuleStatus.rule_syntax_valid == f_syntax_valid)
    return q.order_by(RuleStatus.update_available.desc(), RuleStatus.date.asc())\
             .paginate(page=page, per_page=per_page, error_out=False)


def get_rule_update_list_filtered(sid: str,
                                   f_found=None,
                                   f_error=None,
                                   f_syntax_valid=None):
    """Return RuleStatus with update_available=True, optionally narrowed by extra filters."""
    update_result = UpdateResult.query.filter_by(uuid=sid).first()
    if not update_result:
        return [], 0
    q = RuleStatus.query.filter_by(update_result_id=update_result.id, update_available=True)
    if f_found is not None:
        q = q.filter(RuleStatus.found == f_found)
    if f_error is not None:
        q = q.filter(RuleStatus.error == f_error)
    if f_syntax_valid is not None:
        q = q.filter(RuleStatus.rule_syntax_valid == f_syntax_valid)
    rules = q.all()
    return rules, len(rules)


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

def accept_all_update(rule_udpate_list, on_progress=None, should_stop=None):
    """on_progress(n, rule), if given, is called after the n-th rule commits —
    lets a caller (e.g. a BackgroundJob) surface real per-rule progress
    instead of only finding out once the entire list is done.
    should_stop(), if given, is checked before each rule — a truthy return
    stops the loop early (already-committed rules stay committed; the caller
    decides what "stopped early" means, e.g. a paused/cancelled job)."""
    # for each rule take the history_id associated
    try:
        for i, rule in enumerate(rule_udpate_list):
            if should_stop and should_stop():
                return True
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
            if on_progress:
                on_progress(i + 1, rule)
            db.session.commit()
        return True
    except Exception as e:
        return False


def reject_all_update(rule_update_list, on_progress=None, should_stop=None):
    """See accept_all_update() for on_progress / should_stop."""
    try:
        for i, rule in enumerate(rule_update_list):
            if should_stop and should_stop():
                return True
            rule.update_available = False
            rule.message = "Rejected"
            history = RuleUpdateHistory.query.filter_by(id=rule.history_id).first()
            if history:
                history.message = "rejected"
            if on_progress:
                on_progress(i + 1, rule)
            db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False


def _new_rule_still_pending_filter(query):
    """A NewRule is "still pending" (needs a decision) unless it was already
    imported/rejected, or add_rule_core() already rejected it as a permanent
    duplicate ("error: ..." — retrying would just fail identically, since the
    content match that caused it doesn't change). Without excluding the
    "error: ..." case here, a duplicate that failed to add keeps reappearing
    in both the pending list and every future "Add all" retry forever."""
    return query.filter(
        NewRule.message != 'imported',
        NewRule.message != 'rejected',
        db.or_(NewRule.message.is_(None), ~NewRule.message.like('error:%')),
    )


def get_valid_new_rules_by_sid(sid):
    updater = get_updater_result(sid)
    if not updater:
        return []
    return _new_rule_still_pending_filter(
        NewRule.query.filter_by(update_result_id=updater.id, rule_syntax_valid=True)
    ).all()


def reject_all_new_rules_by_sid(sid):
    updater = get_updater_result(sid)
    if not updater:
        return False
    rules = NewRule.query.filter_by(update_result_id=updater.id).filter(
        NewRule.message != 'imported'
    ).all()
    for r in rules:
        r.message = 'rejected'
    db.session.commit()
    return True


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
    reel_rule = get_rule(rule.rule_id, include_deleted=True)
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
    base = [
        RuleUpdateHistory.message != "accepted",
        RuleUpdateHistory.message != "rejected",
        RuleUpdateHistory.manuel_submit != True,   # already-applied entries (connector pull etc.)
    ]
    if current_user.is_admin():
        return RuleUpdateHistory.query.filter(*base).all()
    else:
        return RuleUpdateHistory.query.filter(
            *base,
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

def delete_all_rule_by_url(urls, user_id: int = 0):
    """Soft-delete all rules from the given GitHub source URLs (moves them to trash)."""
    return soft_delete_all_by_url(urls, user_id)

def count_rules_by_url(url):
    if not url:
        return 0
    return _active().filter(Rule.source == url.strip()).count()

def get_all_github_sources(exclude_urls=None):
    """Returns unique active GitHub repository URLs (excludes trash)."""
    query = db.session.query(Rule.source).distinct()
    query = query.filter(Rule.source.like('https://github.com/%'))
    query = query.filter(Rule.is_deleted == False)
    if exclude_urls:
        query = query.filter(Rule.source.notin_(exclude_urls))
    return [r[0] for r in query.all()]


def export_rules_by_urls_as_zip(urls):
    """
    Exports rules into a ZIP file structure.
    Structure:
    /repo_name/info.json
    /repo_name/rules/rule_1.json
    /repo_name/rules/rule_2.json
    """
    if isinstance(urls, str):
        target_urls = [urls.strip()]
    else:
        target_urls = [u.strip() for u in urls]

    memory_file = io.BytesIO()
    
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for url in target_urls:
            folder_name = url.replace('https://', '').replace('http://', '').replace('/', '_').strip('_')
            
            rules = _active().filter(Rule.source == url).all()
            

            repo_info = {
                "repository_url": url,
                "exported_at": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
                "total_rules_found": len(rules),
                "platform": "rulezet.org"
            }

            zf.writestr(f"{folder_name}/info.json", json.dumps(repo_info, indent=4))
            
            for rule in rules: 
                rule_filename = f"{folder_name}/rules/rule_{rule.title}_{rule.id}.json"
                

                rule_data = rule.to_json() 
                
                zf.writestr(rule_filename, json.dumps(rule_data, indent=4))


    memory_file.seek(0)
    
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"github_rules_export_{datetime.date.today()}.zip"
    )

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
    
def get_rules_vulnerabilities_usage(filters: dict = None):
    """
    Retrieves and counts vulnerability identifiers from rules matching every
    OTHER currently active filter (see parse_facet_filters — 'vulnerabilities'
    must already be excluded from `filters`).
    """
    base_ids = filter_rules(**(filters or {})).order_by(None).with_entities(Rule.id).subquery()

    query = db.session.query(Rule.cve_id).filter(
        Rule.id.in_(db.session.query(base_ids)),
        Rule.cve_id.isnot(None),
        Rule.cve_id != '',
        Rule.cve_id != '[]'
    )

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
    


def get_sources_usage_with_filter(search_term, filters: dict = None):
    """
    Groups rules by source and counts them, scoped to rules matching every
    OTHER currently active filter ('source' must already be excluded from
    `filters` — see parse_facet_filters). `search_term` filters the source
    names themselves (the dropdown's own search box), independent of that.
    """
    base_ids = filter_rules(**(filters or {})).order_by(None).with_entities(Rule.id).subquery()

    query = db.session.query(
        Rule.source.label('source'),
        func.count(Rule.id).label('count')
    ).filter(Rule.id.in_(db.session.query(base_ids)), Rule.source != None, Rule.source != '')

    if search_term:
        query = query.filter(Rule.source.ilike(f'%{search_term}%'))

    return query.group_by(Rule.source).order_by(func.count(Rule.id).desc()).all()

def get_licenses_usage_with_filter(search_query, filters: dict = None):
    """
    Groups rules by license and counts them, scoped to rules matching every
    OTHER currently active filter ('license' must already be excluded from
    `filters`).
    """
    base_ids = filter_rules(**(filters or {})).order_by(None).with_entities(Rule.id).subquery()

    query = db.session.query(
        Rule.license.label('license'),
        func.count(Rule.id).label('count')
    ).filter(Rule.id.in_(db.session.query(base_ids)),
             Rule.license != None, Rule.license != '', Rule.license != '[]')

    if search_query:
        query = query.filter(Rule.license.ilike(f'%{search_query}%'))

    return query.group_by(Rule.license).order_by(func.count(Rule.id).desc()).all()


def get_authors_usage_with_filter(search_query=None, filters: dict = None):
    """Distinct rule authors with usage counts, scoped to rules matching every
    OTHER currently active filter ('author' must already be excluded from
    `filters`)."""
    base_ids = filter_rules(**(filters or {})).order_by(None).with_entities(Rule.id).subquery()

    query = db.session.query(
        Rule.author.label('author'),
        func.count(Rule.id).label('count')
    ).filter(Rule.id.in_(db.session.query(base_ids)),
             Rule.author.isnot(None), Rule.author != '', Rule.author != 'Unknown')

    if search_query:
        query = query.filter(Rule.author.ilike(f'%{search_query}%'))

    return query.group_by(Rule.author).order_by(func.count(Rule.id).desc()).all()


def get_editors_usage_with_filter(search_query=None, filters: dict = None):
    """Distinct Rulezet editors (uploaders) with usage counts, scoped to rules
    matching every OTHER currently active filter ('editor_names' must already
    be excluded from `filters`)."""
    base_ids = filter_rules(**(filters or {})).order_by(None).with_entities(Rule.id).subquery()

    editor_col = func.coalesce(User.username, func.concat(User.first_name, ' ', User.last_name))
    query = (db.session.query(
        editor_col.label('name'),
        func.count(Rule.id).label('count')
    )
    .join(User, User.id == Rule.user_id)
    .filter(Rule.id.in_(db.session.query(base_ids))))

    if search_query:
        query = query.filter(editor_col.ilike(f'%{search_query}%'))

    return query.group_by(editor_col).order_by(func.count(Rule.id).desc()).all()


def get_tags_for_rule(rule_id: int) -> List[Tag]:
    """
    Retrieve a list of active Tag objects associated with a rule.
    Users see only 'public' tags, while Admins see 'public' and 'private' tags.
    """
    query = (
        db.session.query(Tag)
        .join(RuleTagAssociation, RuleTagAssociation.tag_id == Tag.id)
        .filter(
            RuleTagAssociation.rule_id == rule_id,
            Tag.is_active == True
        )
    )

    if current_user.is_authenticated:
        if not current_user.is_admin():
            query = query.filter(
                or_(
                    Tag.visibility.ilike('public'),
                    and_(
                        Tag.visibility.ilike('private'), 
                        Tag.created_by == current_user.id
                    )
                )
            )
    else:
        query = query.filter(Tag.visibility.ilike('public'))

    return query.all()


def get_tags_for_rules_batch(rule_ids: List[int]) -> dict:
    """Return {rule_id: [Tag, ...]} for all given rule IDs in one query."""
    if not rule_ids:
        return {}

    query = (
        db.session.query(RuleTagAssociation.rule_id, Tag)
        .join(Tag, RuleTagAssociation.tag_id == Tag.id)
        .filter(
            RuleTagAssociation.rule_id.in_(rule_ids),
            Tag.is_active == True,
        )
    )

    if current_user.is_authenticated:
        if not current_user.is_admin():
            query = query.filter(
                or_(
                    Tag.visibility.ilike('public'),
                    and_(
                        Tag.visibility.ilike('private'),
                        Tag.created_by == current_user.id,
                    ),
                )
            )
    else:
        query = query.filter(Tag.visibility.ilike('public'))

    result: dict = {}
    for rule_id, tag in query.all():
        result.setdefault(rule_id, []).append(tag)
    return result


def get_all_used_tags_with_counts(filters: dict = None):
    """
    Returns tags with their usage count, scoped to rules matching every OTHER
    currently active filter ('tags' must already be excluded from `filters`
    — see parse_facet_filters).
    """
    base_ids = filter_rules(**(filters or {})).order_by(None).with_entities(Rule.id).subquery()

    query = (
        db.session.query(
            Tag,
            func.count(func.distinct(RuleTagAssociation.rule_id)).label('usage_count')
        )
        .join(RuleTagAssociation, Tag.id == RuleTagAssociation.tag_id)
        .filter(Tag.is_active.is_(True))
        .filter(RuleTagAssociation.rule_id.in_(db.session.query(base_ids)))
    )

    if current_user.is_authenticated:
        if not current_user.is_admin():
            query = query.filter(
                or_(
                    Tag.visibility.ilike('public'),
                    and_(
                        Tag.visibility.ilike('private'),
                        Tag.created_by == current_user.id
                    )
                )
            )
    else:
        query = query.filter(Tag.visibility.ilike('public'))


    results = (
        query.group_by(Tag.id)
        .order_by(func.count(func.distinct(RuleTagAssociation.rule_id)).desc(), Tag.name.asc())
        .all()
    )

    tags_list = []
    for tag_obj, count in results:
        tag_data = tag_obj.to_json()
        tag_data['usage_count'] = count
        tags_list.append(tag_data)
    return tags_list

def get_tags_for_rule(rule_id: int) -> List[Tag]:
    """
    Retrieve a list of active Tag objects associated with a rule.
    Users see only 'public' tags, while Admins see 'public' and 'private' tags.
    """
    query = (
        db.session.query(Tag)
        .join(RuleTagAssociation, RuleTagAssociation.tag_id == Tag.id)
        .filter(
            RuleTagAssociation.rule_id == rule_id,
            Tag.is_active == True
        )
    )

    if current_user.is_authenticated:
        if not current_user.is_admin():
            query = query.filter(
                or_(
                    Tag.visibility.ilike('public'),
                    and_(
                        Tag.visibility.ilike('private'), 
                        Tag.created_by == current_user.id
                    )
                )
            )
    else:
        query = query.filter(Tag.visibility.ilike('public'))    


    return query.all()



def get_similarity_result(sid: str):
    return SimilarResult.query.filter_by(uuid=sid).first()

def get_similar_rules_query(rule_id):
    """
    Returns a query object for similarities related to a specific rule.
    """
    RuleSource = aliased(Rule)
    RuleTarget = aliased(Rule)

    # We return the query object itself, WITHOUT .all()
    return db.session.query(RuleSimilarity, RuleSource, RuleTarget)\
        .join(RuleSource, RuleSimilarity.rule_id == RuleSource.id)\
        .join(RuleTarget, RuleSimilarity.similar_rule_id == RuleTarget.id)\
        .filter(RuleSimilarity.rule_id == rule_id)\
        .order_by(RuleSimilarity.score.desc())

def get_top_global_duplicates_query(min_score=0.85, filters=None):
    RuleA = aliased(Rule)
    RuleB = aliased(Rule)
    
    query = db.session.query(RuleSimilarity, RuleA, RuleB)\
        .join(RuleA, RuleSimilarity.rule_id == RuleA.id)\
        .join(RuleB, RuleSimilarity.similar_rule_id == RuleB.id)\
        .filter(
            RuleSimilarity.score >= min_score,
            RuleSimilarity.rule_id < RuleSimilarity.similar_rule_id 
        )

    if filters:
        if filters.get('format'):
            query = query.filter(or_(
                RuleA.format == filters['format'],
                RuleB.format == filters['format']
            ))
        source_mode = filters.get('source_mode')
        if source_mode == 'same':
            query = query.filter(RuleA.source == RuleB.source)
        elif source_mode == 'different':
            query = query.filter(RuleA.source != RuleB.source)


        author_mode = filters.get('author_mode')
        if author_mode == 'same':
            query = query.filter(RuleA.author == RuleB.author)
        elif author_mode == 'different':
            query = query.filter(RuleA.author != RuleB.author)
        

    return query.order_by(RuleSimilarity.score.desc())

def get_similarity_list_page(page: int = 1):
    if current_user.is_admin():
        return SimilarResult.query.paginate(page=page, per_page=20, max_per_page=20)
    else :
        return SimilarResult.query.filter_by(user_id=str(current_user.id)).paginate(page=page, per_page=20, max_per_page=20)
    

def delete_similarity_history(uuid: str):
    try:
        RuleSimilarity.query.filter_by(result_uuid=uuid).delete()

        
        SimilarResult.query.filter_by(uuid=uuid).delete()

        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        return False
    

def get_similar_rule(rule_id: int = None, number: int = None):
    query = db.session.query(RuleSimilarity, Rule).join(
        Rule, RuleSimilarity.similar_rule_id == Rule.id
    ).order_by(RuleSimilarity.score.desc())

    if rule_id:
        query = query.filter(RuleSimilarity.rule_id == rule_id)
    
    if number:
        query = query.limit(number)
    
    return query.all()
   

# ── Rule Scope ─────────────────────────────────────────────────────────────────

def get_scopes(rule_id: int, current_user_id: int = None):
    """Return all scope declarations for a rule plus works/nworks counts and the current user's scope."""
    scopes = RuleScope.query.filter_by(rule_id=rule_id).order_by(RuleScope.created_at.desc()).all()
    works_count  = sum(1 for s in scopes if s.works)
    nworks_count = len(scopes) - works_count
    my_scope = None
    if current_user_id:
        my = RuleScope.query.filter_by(rule_id=rule_id, user_id=current_user_id).first()
        if my:
            my_scope = my.to_json()
    return [s.to_json() for s in scopes], works_count, nworks_count, my_scope


def upsert_scope(rule_id: int, user_id: int, works: bool, entries: list, comment: str):
    """Create or update a user's scope declaration for a rule. Returns (scope_json, is_new)."""
    existing = RuleScope.query.filter_by(rule_id=rule_id, user_id=user_id).first()
    is_new = existing is None
    if is_new:
        existing = RuleScope(
            uuid=str(uuid.uuid4()),
            rule_id=rule_id,
            user_id=user_id,
        )
        db.session.add(existing)
    existing.works   = works
    existing.entries = entries
    existing.comment = comment or None
    existing.updated_at = datetime.datetime.now(tz=datetime.timezone.utc)
    db.session.commit()
    return existing.to_json(), is_new


def delete_scope(rule_id: int, user_id: int):
    """Delete a user's scope declaration. Returns True if found and deleted."""
    scope = RuleScope.query.filter_by(rule_id=rule_id, user_id=user_id).first()
    if not scope:
        return False
    db.session.delete(scope)
    db.session.commit()
    return True
