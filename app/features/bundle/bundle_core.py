import datetime
import uuid
from sqlalchemy import Tuple, and_, or_
from flask_login import current_user
from ... import db
from ...core.db_class.db import *
from app.core.db_class.db import Bundle, BundleRuleAssociation
from typing import Dict, Any, Union , List
from ..rule import rule_core as RuleModel
import json
from collections import Counter

"""
CRUD operations for Bundle model.

- create_bundle: Create a new bundle.
- get_bundle_by_id: Retrieve a bundle by its ID.
- get_all_bundles: List all bundles with optional pagination.
- update_bundle: Update fields of an existing bundle.
- delete_bundle: Delete a bundle by ID.
"""

def create_bundle(form_dict , user) -> Bundle:
    """
    Create a new Bundle.
    :param name: Name of the bundle (required).
    :param description: Description of the bundle.
    :param user_id: ID of the user who creates the bundle (required).
    :return: The created Bundle instance.
    """

    creator_type = form_dict.get("created_by") or "user"
    is_public = form_dict.get("public", True)
    
    if user.is_admin():
        verified = True
    else:
        verified = form_dict.get("is_verified", False)

    new_bundle = Bundle(
        uuid=str(uuid.uuid4()),
        name=form_dict.get("name"),
        description=form_dict.get("description"),
        user_id=user.id,
        access=is_public,
        created_by=creator_type,
        is_verified=verified,
        view_count=0,
        download_count=0,
        created_at=datetime.datetime.now(tz=datetime.timezone.utc),
        vulnerability_identifiers=json.dumps(form_dict.get("vulnerability_identifiers", [])),
    )

   
    try:
        db.session.add(new_bundle)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise e

    try:
        from app.features.notification.notification_core import notify_followers_new_bundle
        notify_followers_new_bundle(new_bundle, user.id)
    except Exception:
        pass

    return new_bundle

def add_rules_to_bundle(bundle_id: int, rule_ids: list[int]) -> bool:
    try:
        existing_rule_ids = {
            res[0] for res in db.session.query(BundleRuleAssociation.rule_id)
            .filter(BundleRuleAssociation.bundle_id == bundle_id)
            .filter(BundleRuleAssociation.rule_id.in_(rule_ids))
            .all()
        }

        new_rules_added = False
        for rule_id in rule_ids:
            if rule_id not in existing_rule_ids:
                association = BundleRuleAssociation(bundle_id=bundle_id, rule_id=rule_id)
                db.session.add(association)
                new_rules_added = True
        
        if new_rules_added:
            db.session.commit()
            success, msg = update_bundle_from_rule_id_into_structure(bundle_id)
            if not success:
                return False, msg

        return True, "Successfully added rules to bundle"
    except Exception as e:
        db.session.rollback()
        return False, str(e)



def get_bundle_by_id(bundle_id: int) -> Bundle | None:
    """
    Retrieve a Bundle by its ID.
    :param bundle_id: ID of the bundle.
    :return: Bundle instance or None if not found.
    """
    return Bundle.query.get(bundle_id)
def get_all_bundles_by_user(user_id: int):
     return Bundle.query.filter_by(user_id=user_id).all()

def get_bundle_by_uuid(uuid: str) -> Bundle | None:
    """
    Retrieve a Bundle by its ID.
    :param bundle_id: ID of the bundle.
    :return: Bundle instance or None if not found.
    """
    return Bundle.query.filter_by(uuid=uuid).first()

def add_view(bundle_id: int) -> bool:
    bundle = Bundle.query.get(bundle_id)
    if bundle:
        bundle.view_count += 1
        db.session.commit()
        return True
    return False
def  get_association_by_id(association_id: int) -> Bundle | None:
    """
    Retrieve a Bundle by its ID.
    :param bundle_id: ID of the bundle.
    :return: Bundle instance or None if not found.
    """
    return BundleRuleAssociation.query.get(association_id)
def get_all_bundles_page(page: int, search: str | None, own: bool, tag_names: list[str] | None = None, vulnerabilities: list[str] | None = None):
    query = Bundle.query

    if search:
        like_pattern = f"%{search}%"
        query = query.filter(or_(Bundle.name.ilike(like_pattern), Bundle.description.ilike(like_pattern)))

    if tag_names:
        query = query.join(BundleTagAssociation).join(Tag)\
                     .filter(Tag.name.in_(tag_names))\
                     .distinct()

    if vulnerabilities:
        vuln_filters = []
        for v in vulnerabilities:
            search_pattern = '%"' + v + '"%'
            vuln_filters.append(Bundle.vulnerability_identifiers.ilike(search_pattern))
        query = query.filter(or_(*vuln_filters))

    if own and current_user.is_authenticated:
        query = query.filter_by(user_id=current_user.id)

    if current_user.is_authenticated:
        if not current_user.is_admin():
            query = query.filter(or_(Bundle.access.is_(True), Bundle.user_id == current_user.id))
    else:
        query = query.filter_by(access=True)

    return query.order_by(Bundle.created_at.desc()).paginate(page=page, per_page=20)

def get_all_bundles(search: str | None, own: bool):
    """
    Return a list of filtered bundles (no pagination).
    """
    query = Bundle.query

    # Search filter
    if search:
        like_pattern = f"%{search}%"
        query = query.filter(
            or_(
                Bundle.name.ilike(like_pattern),
                Bundle.description.ilike(like_pattern)
            )
        )

    # Filter by owner
    if own:
        if current_user.is_authenticated:
            query = query.filter_by(user_id=current_user.id)
    query = query.filter_by(access=True)

    # Execute query
    items = query.order_by(Bundle.created_at.desc()).all()

    return {
        "total": len(items),
        "items": items
    }


def get_total_bundles_count() -> int:
    """
    get the count of bundles
    :return: int the number of bundles.
    """
    return Bundle.query.count()



def update_bundle(bundle_id: int, form_dict: dict ) -> Bundle | None:
    """
    Update a bundle's details.
    :param bundle_id: ID of the bundle to update.
    :param name: New name (optional).
    :param description: New description (optional).
    :return: Updated Bundle instance or None if not found.
    """
    bundle = Bundle.query.get(bundle_id)
    if not bundle:
        return None
    
    v_raw = form_dict.get("vulnerabilities") 
    
   
    if isinstance(v_raw, list):
        vulnerabilities_json = json.dumps(v_raw)
    elif isinstance(v_raw, str) and v_raw.strip():
        try:
            json.loads(v_raw) 
            vulnerabilities_json = v_raw
        except:
            vulnerabilities_json = "[]"
    else:
        vulnerabilities_json = "[]"

    if form_dict is not None:
        bundle.updated_at = datetime.datetime.now(tz=datetime.timezone.utc)
        bundle.name = form_dict["name"]
        bundle.description = form_dict["description"]
        bundle.access = form_dict["public"]
        bundle.vulnerability_identifiers = vulnerabilities_json
    db.session.commit()
    return bundle


def delete_bundle(bundle_id: int) -> bool:
    """
    Delete a bundle by its ID.
    :param bundle_id: ID of the bundle to delete.
    :return: True if deleted, False if not found.
    """
    bundle = Bundle.query.get(bundle_id)
    if not bundle:
        return False
    db.session.delete(bundle)
    db.session.commit()
    return True


def add_rule_to_bundle(bundle_id: int, rule_id: int , description: str) -> bool:
    """
    Add a single rule to a bundle.
    :param bundle_id: ID of the bundle.
    :param rule_id: ID of the rule to add.
    :return: Bool
    """
    if not bundle_id or not rule_id:
        return False

    # Ensure bundle and rule exist
    bundle = get_bundle_by_id(bundle_id)
    if not bundle:
        return False
    rule = RuleModel.get_rule(rule_id)
    if not rule or rule.is_deleted:
        return False

    # Check if association already exists
    existing = BundleRuleAssociation.query.filter_by(bundle_id=bundle_id, rule_id=rule_id).first()
    if existing:
        return True   # Avoid duplicates

    assoc = BundleRuleAssociation(
        description=description,
        bundle_id=bundle_id,
        rule_id=rule_id,
        added_at=datetime.datetime.now(tz=datetime.timezone.utc)
    )
    db.session.add(assoc)
    db.session.commit()
    if assoc:
        return True
    return False 

def update_bundle_tags(bundle_id: int, tags: List[int], user: User) -> bool:
    """
    Syncs the tags associated with a bundle without deleting existing ones
    that are still present in the new list.
    """
    bundle = get_bundle_by_id(bundle_id)
    if not bundle:
        return False

    try:
        current_associations = BundleTagAssociation.query.filter_by(bundle_id=bundle_id).all()
        
        current_tag_ids = {assoc.tag_id for assoc in current_associations}
        new_tag_ids = set(tags)

        

        ids_to_remove = current_tag_ids - new_tag_ids
        

        ids_to_add = new_tag_ids - current_tag_ids


        if ids_to_remove:
            BundleTagAssociation.query.filter(
                BundleTagAssociation.bundle_id == bundle_id,
                BundleTagAssociation.tag_id.in_(ids_to_remove)
            ).delete(synchronize_session=False)


        for tag_id in ids_to_add:
            assoc = BundleTagAssociation(
                bundle_id=bundle_id,
                tag_id=tag_id,
                added_at=datetime.datetime.now(tz=datetime.timezone.utc),
                user_id=user.id,
                uuid=str(uuid.uuid4())
            )
            db.session.add(assoc)

        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def get_tag_ids_for_bundle(bundle_id: int) -> List[int]:
    """
    Retrieve a list of active and public tag IDs associated with a bundle.
    """
    # We query only the tag_id column
    results = (
        db.session.query(BundleTagAssociation.tag_id)
        .join(Tag, BundleTagAssociation.tag_id == Tag.id)
        .filter(
            BundleTagAssociation.bundle_id == bundle_id,
            Tag.is_active == True,
            Tag.visibility == 'public'
        )
        .all()
    )

    # results is [(1,), (5,)], we convert it to [1, 5]
    return [tag_id for (tag_id,) in results]

def get_tags_for_bundle(bundle_id: int) -> List[Tag]:
    """
    Retrieve a list of active Tag objects associated with a bundle.
    Users see only 'public' tags, while Admins see 'public' and 'private' tags.
    """
    query = (
        db.session.query(Tag)
        .join(BundleTagAssociation, BundleTagAssociation.tag_id == Tag.id)
        .filter(
            BundleTagAssociation.bundle_id == bundle_id,
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


def get_vulnerabilities_for_bundle(bundle_id: int):
    """
    Retrieve the list of vulnerability strings stored in the bundle.
    """
    bundle = get_bundle_by_id(bundle_id)
    if not bundle or not bundle.vulnerability_identifiers:
        return []
    
    # vulnerability_identifiers is a string like '["CVE-2024-1234", "GHSA-xxxx"]'
    try:
        return json.loads(bundle.vulnerability_identifiers)
    except (json.JSONDecodeError, TypeError):
        return []
def get_tags_for_bundle_json(bundle_id: int, user_id=None) -> List[dict]:
    """
    Retrieve a list of active Tag dictionaries associated with a bundle.
    Normal users see only 'public' tags; Admins see both 'public' and 'private'.
    """
    query = (
        db.session.query(Tag)
        .join(BundleTagAssociation, BundleTagAssociation.tag_id == Tag.id)
        .filter(
            BundleTagAssociation.bundle_id == bundle_id,
            Tag.is_active == True
        )
    )
    if user_id:
        # Only show tags that the user has created
        query = query.filter(Tag.created_by == user_id)
    else:
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

    tags = query.all()
    return [tag.to_json() for tag in tags]

def get_all_rule_bundles_page(page: int, bundle_id: int) -> list[Rule]:
    """
    List all rules from a bundle (paginated).
    :param page: Page number.
    :param bundle_id: ID of the bundle to get rules from.
    :return: Pagination object of Rule.
    """
    query = (
        db.session.query(Rule)
        .join(BundleRuleAssociation, BundleRuleAssociation.rule_id == Rule.id)
        .filter(BundleRuleAssociation.bundle_id == bundle_id)
        .filter(Rule.is_deleted == False)
        .order_by(Rule.creation_date.desc())
    )

    return query.paginate(page=page, per_page=20)

def get_total_rule_from_bundle_count(bundle_id: int) -> int:
    """
    Count the total number of rules in a given bundle.
    :param bundle_id: ID of the bundle.
    :return: Total number of rules in the bundle.
    """
    return (
        db.session.query(BundleRuleAssociation)
        .join(Rule, Rule.id == BundleRuleAssociation.rule_id)
        .filter(BundleRuleAssociation.bundle_id == bundle_id)
        .filter(Rule.is_deleted == False)
        .count()
    )

def remove_rule_from_bundle(bundle_id: int, rule_id: int) -> bool:
    """
    Remove a single rule from a bundle.
    :param bundle_id: ID of the bundle.
    :param rule_id: ID of the rule to remove.
    :return: True if removed, False if not found.
    """
    existing = BundleRuleAssociation.query.filter_by(bundle_id=bundle_id, rule_id=rule_id).first()
    if not existing:
        return False  # No association found

    db.session.delete(existing)
    db.session.commit()
    return True

def get_full_rule_bundle_info(rule_id: int) -> Union[Dict[str, Any], Dict[str, str]]:
    """
    Retrieve combined JSON data for a given rule_id, including:
    - the Rule data,
    - the BundleRuleAssociation data (first association found),
    - the associated Bundle data.

    Args:
        rule_id (int): The ID of the Rule to retrieve.

    Returns:
        dict: A dictionary containing the combined JSON data with keys:
            - "rule": dict with rule details,
            - "association": dict with bundle-rule association details,
            - "bundle": dict with bundle details.
        
        If the rule, association or bundle is not found, returns a dict with an "error" message.
    """
    rule = Rule.query.get(rule_id)
    if not rule or rule.is_deleted:
        return {"error": f"No rule found with id {rule_id}"}

    assoc = BundleRuleAssociation.query.filter_by(rule_id=rule_id).first()
    if not assoc:
        return {"error": f"No bundle association found for rule_id {rule_id}"}


    return {
        "rule": rule.to_json(),
        "association": assoc.to_json()
        # "bundle": bundle.to_json()
    }

def get_rule_ids_by_bundle(bundle_id: int) -> Union[Dict[str, str], List[int]]:
    """
    Retrieve a list of rule IDs associated with a given bundle ID.

    Args:
        bundle_id (int): The ID of the bundle.

    Returns:
        list[int]: A list of rule IDs linked to the bundle.
        dict: If no bundle found or no associated rules, returns a dict with an error message.
    """
    bundle = Bundle.query.get(bundle_id)
    if not bundle:
        return {"error": f"No bundle found with id {bundle_id}"}


    associations = (
        db.session.query(BundleRuleAssociation)
        .join(Rule, Rule.id == BundleRuleAssociation.rule_id)
        .filter(BundleRuleAssociation.bundle_id == bundle_id)
        .filter(Rule.is_deleted == False)
        .all()
    )
    if not associations:
        return {"error": f"No rules associated with bundle id {bundle_id}"}

    rule_ids = [assoc.rule_id for assoc in associations]
    return rule_ids
def get_rules_from_bundle(bundle_id: int) -> List[Rule]:
    """
    Retrieve all Rule objects associated with a given bundle.

    Args:
        bundle_id (int): The ID of the bundle whose rules should be retrieved.

    Returns:
        List[Rule]: A list of Rule objects that are part of the specified bundle.
    """
    return (
        db.session.query(Rule)
        .join(BundleRuleAssociation, BundleRuleAssociation.rule_id == Rule.id)
        .filter(BundleRuleAssociation.bundle_id == bundle_id)
        .filter(Rule.is_deleted == False)
        .all()
    )

def get_bundles_by_rule(rule_id: int) -> List[Bundle]:
    """
    Retrieve all bundles that contain a specific rule and are publicly accessible.
    
    :param rule_id: ID of the rule to search for.
    :return: List of Bundle instances containing the specified rule and with access=True.
    """
    return (
        db.session.query(Bundle)
        .join(BundleRuleAssociation, BundleRuleAssociation.bundle_id == Bundle.id)
        .filter(
            BundleRuleAssociation.rule_id == rule_id,
            Bundle.access.is_(True) 
        )
        .all()
    )


def toggle_bundle_accessibility(bundle_id: int) -> bool:
    """
    Toggle the accessibility of a bundle between public and private.
    :param bundle_id: ID of the bundle to toggle.
    :return: True if toggled successfully, False if bundle not found.
    """
    bundle = Bundle.query.get(bundle_id)
    if not bundle:
        return False , "Bundle not found"
    bundle.access = not bundle.access
    db.session.commit()
    return True , "Bundle access toggled successfully"

def get_bundles_of_user_with_id_page(
    user_id: int, 
    page: int, 
    search: str = None, 
    sort_by: str = "newest", 
    rule_type: str = None
) -> dict:
    """
    List all accessible bundles of a specific user, paginated and optionally filtered by search, rule_type and sort.
    """

    # Base query
    query = Bundle.query.filter(
        Bundle.user_id == user_id,
        Bundle.access.is_(True)
    )

    # Search filter
    if search:
        like_pattern = f"%{search}%"
        query = query.filter(
            or_(
                Bundle.name.ilike(like_pattern),
                Bundle.description.ilike(like_pattern)
            )
        )

    # Rule type filter (bundles containing rules of a given type)
    if rule_type:
        normalized_type = rule_type.strip().lower()
        query = (
            query.join(Bundle.rules_assoc)
                 .join(BundleRuleAssociation.rule)
                 .filter(func.lower(Rule.format) == normalized_type)
                 .filter(Rule.is_deleted == False)
                 .distinct()
        )

    # Sorting options
    if sort_by == "newest":
        query = query.order_by(Bundle.created_at.desc())
    elif sort_by == "oldest":
        query = query.order_by(Bundle.created_at.asc())
    elif sort_by == "most_rules":
        query = query.outerjoin(Bundle.rules_assoc).group_by(Bundle.id).order_by(func.count(BundleRuleAssociation.id).desc())
    elif sort_by == "least_rules":
        query = query.outerjoin(Bundle.rules_assoc).group_by(Bundle.id).order_by(func.count(BundleRuleAssociation.id).asc())
    elif sort_by == "most_likes":
        query = query.order_by(Bundle.vote_up.desc())
    elif sort_by == "least_likes":
        query = query.order_by(Bundle.vote_up.asc())

    # Pagination
    pagination = query.paginate(page=page, per_page=20)

    return pagination

def has_already_vote(bundle_id, user_id) -> bool:
    """Test if an user has ever vote"""
    vote =  BundleVote.query.filter_by(bundle_id=bundle_id, user_id=user_id).first()
    if vote:
        return True , vote.vote_type
    return False , None

def has_voted(vote,bundle_id , id) -> bool:
    """Set a vote"""
    user_id = id or current_user.id
    vote = BundleVote(bundle_id=bundle_id, user_id=user_id, vote_type=vote)
    db.session.add(vote)    
    db.session.commit()
    return True

# Update

def increment_up(id) -> None:
    """Increment the like section"""
    bundle = get_bundle_by_id(id)
    bundle.vote_up = bundle.vote_up + 1
    db.session.commit()

def decrement_up(id) -> None:
    """Increment the dislike section"""
    bundle = get_bundle_by_id(id)
    bundle.vote_down = bundle.vote_down + 1
    db.session.commit()

def remove_one_to_increment_up(id) -> None:
    """Decrement the dislike section"""
    bundle = get_bundle_by_id(id)
    bundle.vote_up = bundle.vote_up - 1
    db.session.commit()

def remove_one_to_decrement_up(id) -> None:
    """Decrement the dislike section"""
    bundle = get_bundle_by_id(id)
    bundle.vote_down = bundle.vote_down - 1
    db.session.commit()

# Remove

def remove_has_voted(vote, bundle_id , id) -> bool:
    """Remove a vote"""
    user_id = id or current_user.id
    existing_vote = BundleVote.query.filter_by(bundle_id=bundle_id, user_id=user_id, vote_type=vote).first()
    if existing_vote:
        db.session.delete(existing_vote)
        db.session.commit()
        return True 
    return False 


def save_workspace(bundle_id, structure):
    """
    Docstring for save_workspace
    
    :param bundle_id: Description
    :param structure: Description
    """
    try:
        BundleNode.query.filter_by(bundle_id=bundle_id).delete()

        def save_recursive(nodes, parent_id=None):
            for node in nodes:
                new_node = BundleNode(
                    bundle_id=bundle_id,
                    parent_id=parent_id,
                    name=node.get('name', 'unnamed'),
                    node_type=node.get('type', 'file'),
                    rule_id=node.get('rule_id'),
                    custom_content=node.get('content') if not node.get('rule_id') else None
                )
                db.session.add(new_node)
                db.session.flush() 
                
                if node.get('children'):
                    save_recursive(node['children'], new_node.id)

        save_recursive(structure)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        return False
def get_only_root_nodes(bundle_id):
    return BundleNode.query.filter_by(bundle_id=bundle_id, parent_id=None).all()

def extract_rule_ids(structure):
    """Recursively extract all rule_id values from the tree structure."""
    found_ids = set()
    for node in structure:
        rid = node.get('rule_id')
        if rid:
           
            found_ids.add(int(rid))
        

        if 'children' in node and node['children']:
            found_ids.update(extract_rule_ids(node['children']))
    return found_ids

def update_bundle_from_structure(bundle_id, structure):
    """
    Syncs the BundleRuleAssociation table with the current UI structure.
    1. Removes rules no longer in the structure.
    2. Adds new rules found in the structure.
    3. Increments view_count for rules.
    """
    bundle = Bundle.query.get(bundle_id)
    if not bundle:
        return False

   
    new_rule_ids = extract_rule_ids(structure)

    existing_assocs = BundleRuleAssociation.query.filter_by(bundle_id=bundle_id).all()
    existing_rule_ids = {assoc.rule_id for assoc in existing_assocs}

    try:

        for assoc in existing_assocs:
            if assoc.rule_id not in new_rule_ids:
                db.session.delete(assoc)

        for rid in new_rule_ids:
            rule = Rule.query.get(rid)
            if not rule or rule.is_deleted:
                continue

           

            if rid not in existing_rule_ids:
                new_assoc = BundleRuleAssociation(
                    bundle_id=bundle_id,
                    rule_id=rid,
                    description=f"Added via Workspace Editor on {datetime.datetime.now().strftime('%Y-%m-%d')}"
                )
                db.session.add(new_assoc)

        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False
    

def update_bundle_from_rule_id_into_structure(bundle_id):
    """
    Ensure every rule in BundleRuleAssociation has a matching BundleNode,
    without touching the existing folder structure. Rules that don't have a
    node yet are appended into an "Unsorted" root folder (created on demand);
    existing folders and nodes are left untouched.
    """
    try:
        bundle = Bundle.query.get(bundle_id)
        if not bundle:
            return False, "Bundle not found"

        bundle_rules = BundleRuleAssociation.query.filter_by(bundle_id=bundle_id).all()

        existing_node_rule_ids = {
            rid for (rid,) in db.session.query(BundleNode.rule_id)
                .filter(BundleNode.bundle_id == bundle_id, BundleNode.rule_id.isnot(None))
        }
        missing_rules = [r for r in bundle_rules if r.rule_id not in existing_node_rule_ids]

        if not missing_rules:
            return True, "Structure already up to date"

        unsorted = BundleNode.query.filter_by(
            bundle_id=bundle_id, parent_id=None, node_type="folder", name="Unsorted"
        ).first()
        if not unsorted:
            unsorted = BundleNode(
                bundle_id=bundle_id,
                parent_id=None,
                name="Unsorted",
                node_type="folder",
                rule_id=None,
                custom_content=None
            )
            db.session.add(unsorted)
            db.session.flush()

        for rule_assoc in missing_rules:
            db.session.add(BundleNode(
                bundle_id=bundle_id,
                parent_id=unsorted.id,
                name=rule_assoc.rule.title,
                node_type="file",
                rule_id=rule_assoc.rule_id,
                custom_content=None
            ))
        db.session.commit()
        return True, "Structure updated successfully"

    except Exception as e:
        db.session.rollback()
        return False, "Error updating bundle rules"
    

def increment_download_count(bundle_id: int) -> None:
    """
    Increment the download count for a bundle.
    :param bundle_id: ID of the bundle.
    """
    bundle = Bundle.query.get(bundle_id)
    if bundle:
        bundle.download_count += 1
        db.session.commit()


##############
#   Comment  #
##############

def add_comment_to_bundle(bundle_id: int, user: User, content: str , parent_comment_id: int = None) -> tuple[str, bool]:
    """
    Add a comment to a bundle.
    :param bundle_id: ID of the bundle.
    :param user: User who adds the comment.
    :param content: Content of the comment.
    :return: Tuple of (message, success).
    """
    if not bundle_id or not user or not content:
        return "Missing bundle_id, user, or content", False

    try:
        new_comment = CommentBundle(
            uuid=str(uuid.uuid4()),
            bundle_id=bundle_id,
            user_id=user.id,
            user_name=user.first_name + " " + user.last_name,
            content=content,
            created_at=datetime.datetime.now(tz=datetime.timezone.utc),
            updated_at=datetime.datetime.now(tz=datetime.timezone.utc),
            likes=0,
            dislikes=0,
            parent_comment_id=parent_comment_id
        )
        db.session.add(new_comment)
        db.session.commit()

        try:
            bundle = Bundle.query.get(bundle_id)
            link   = f'/bundle/detail/{bundle_id}'
            is_public = bool(bundle.access) if bundle else True
            from app.features.notification.notification_core import (
                notify_owner_new_comment, notify_followers_new_comment, notify_comment_reply)
            if bundle:
                # Always notify the owner of comment on their bundle (even private — they own it)
                notify_owner_new_comment(
                    bundle.user_id, user.id, 'bundle_comment', bundle.name, link)
            # Followers only see activity on public bundles
            notify_followers_new_comment(user.id, bundle.name if bundle else '', link,
                                         is_public=is_public)
            if parent_comment_id:
                from app.core.db_class.db import CommentBundle
                parent = CommentBundle.query.get(parent_comment_id)
                # Reply notification: only if the parent author can access the bundle
                # (i.e. they're the bundle owner, or the bundle is public)
                if parent and (is_public or parent.user_id == (bundle.user_id if bundle else None)):
                    notify_comment_reply(parent.user_id, user.id, bundle.name if bundle else '', link)
        except Exception as _e:
            print(f"[bundle_core] add_comment_to_bundle notification error: {_e}")

        return "Comment added successfully", True
    except Exception as e:
        db.session.rollback()
        return f"Error adding comment: {e}", False
def get_comments_for_bundle(bundle_id: int, page: int):
    """
    Retrieve comments for a specific bundle, paginated.
    :param bundle_id: ID of the bundle.
    :param page: Page number.
    :return: Pagination object with comments.
    """
    return CommentBundle.query.filter_by(bundle_id=bundle_id, parent_comment_id=None).order_by(CommentBundle.created_at.desc()).paginate(page=page, per_page=10)

def get_comment_bundle_by_id(comment_id: int):
    """
    Retrieve a comment by its ID.
    :param comment_id: ID of the comment.
    :return: Comment object.
    """
    return CommentBundle.query.get(comment_id)

def delete_comment_bundle(comment_id: int) -> bool:
    """
    Delete a comment by its ID.
    :param comment_id: ID of the comment to delete.
    :return: True if deleted, False if not found.
    """
    comment = CommentBundle.query.get(comment_id)
    if not comment:
        return False
    db.session.delete(comment)
    db.session.commit()
    return True

def edit_comment_bundle(comment_id: int, content: str) -> bool:
    """
    Edit a comment by its ID.
    :param comment_id: ID of the comment to edit.
    :param content: New content of the comment.
    :return: True if edited, False if not found.
    """
    comment = CommentBundle.query.get(comment_id)
    if not comment:
        return False
    comment.content = content
    db.session.commit()
    return True

def add_reaction_to_comment(comment_id: int, user_id: int, reaction_type: str, bundle_id: int) -> tuple[bool, str]:
    comment = CommentBundle.query.get(comment_id)
    if not comment:
        return False, "Comment not found"

    thumb_types = ['like', 'dislike']
    is_thumb = reaction_type in thumb_types

    try:
        if is_thumb:
            existing_thumb = BundleReactionComment.query.filter(
                BundleReactionComment.comment_id == comment_id,
                BundleReactionComment.user_id == user_id,
                BundleReactionComment.reaction_type.in_(thumb_types)
            ).first()

            if existing_thumb:
                if existing_thumb.reaction_type == reaction_type:
                    if reaction_type == 'like': comment.likes = max(0, (comment.likes or 0) - 1)
                    else: comment.dislikes = max(0, (comment.dislikes or 0) - 1)
                    db.session.delete(existing_thumb)
                else:
                    if existing_thumb.reaction_type == 'like':
                        comment.likes = max(0, (comment.likes or 0) - 1)
                        comment.dislikes = (comment.dislikes or 0) + 1
                    else:
                        comment.dislikes = max(0, (comment.dislikes or 0) - 1)
                        comment.likes = (comment.likes or 0) + 1
                    existing_thumb.reaction_type = reaction_type
            else:
                new_thumb = BundleReactionComment(
                    comment_id=comment_id, user_id=user_id, bundle_id=bundle_id,
                    uuid=str(uuid.uuid4()), reaction_type=reaction_type
                )
                db.session.add(new_thumb)
                if reaction_type == 'like': comment.likes = (comment.likes or 0) + 1
                else: comment.dislikes = (comment.dislikes or 0) + 1

        else:
            existing_emoji = BundleReactionComment.query.filter(
                BundleReactionComment.comment_id == comment_id,
                BundleReactionComment.user_id == user_id,
                ~BundleReactionComment.reaction_type.in_(thumb_types) 
            ).first()

            if existing_emoji:
                if existing_emoji.reaction_type == reaction_type:
                    db.session.delete(existing_emoji)
                else:
                    existing_emoji.reaction_type = reaction_type
            else:
                new_emoji = BundleReactionComment(
                    comment_id=comment_id, user_id=user_id, bundle_id=bundle_id,
                    uuid=str(uuid.uuid4()), reaction_type=reaction_type
                )
                db.session.add(new_emoji)

        db.session.commit()
        return True, "Reaction updated"

    except Exception as e:
        db.session.rollback()
        return False, f"Error: {str(e)}"


def get_all_used_tags_with_counts():
    """
    Returns tags with their usage count.
    """
   
    query = (
        db.session.query(
            Tag, 
            func.count(BundleTagAssociation.id).label('usage_count')
        )
        .join(BundleTagAssociation, Tag.id == BundleTagAssociation.tag_id)
        .join(Bundle, Bundle.id == BundleTagAssociation.bundle_id)
        .filter(Tag.is_active.is_(True)) 
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

    if current_user.is_authenticated:
        if not current_user.is_admin():
            query = query.filter(
                or_(Bundle.id.is_(None), Bundle.access.is_(True), Bundle.user_id == current_user.id)
            )
    else:
        query = query.filter(or_(Bundle.id.is_(None), Bundle.access.is_(True)))

    results = (
        query.group_by(Tag.id)
        .order_by(func.count(BundleTagAssociation.id).desc(), Tag.name.asc())
        .all()
    )
    

    tags_list = []
    for tag_obj, count in results: 
        tag_data = tag_obj.to_json()
        tag_data['usage_count'] = count
        tags_list.append(tag_data)
    return tags_list

def get_all_vulnerabilities_with_counts():
    """
    Retrieves and counts vulnerability identifiers while respecting access control:
    - Admins see everything.
    - Authenticated users see public bundles OR their own private bundles.
    - Anonymous users see only public bundles.
    """
    
    # Start the query
    query = db.session.query(Bundle.vulnerability_identifiers).filter(
        Bundle.vulnerability_identifiers.isnot(None),
        Bundle.vulnerability_identifiers != '',
        Bundle.vulnerability_identifiers != '[]'
    )

    # Apply Access Control Logic
    if current_user.is_authenticated:
        if not current_user.is_admin():
            query = query.filter(
                or_(Bundle.access.is_(True), Bundle.user_id == current_user.id)
            )

    else:

        query = query.filter(Bundle.access.is_(True))

    all_bundles_vulns = query.all()
    
    vulnerability_counter = Counter()
    
    for (raw_json,) in all_bundles_vulns:
        try:
            vuln_list = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            if isinstance(vuln_list, list):
                vulnerability_counter.update(vuln_list)
        except (json.JSONDecodeError, TypeError):
            continue


    return [
        {
            "name": vuln_id,
            "usage_count": count
        }
        for vuln_id, count in vulnerability_counter.most_common()
    ]
   
def get_bundles_by_user_id(user_id):
    return Bundle.query.filter(Bundle.user_id == user_id).all()



def get_paginated_rules_info_by_bundle(bundle_id: int, page: int):
    """
    Returns a pagination object containing combined info for rules in a bundle.
    """

    query = BundleRuleAssociation.query.filter_by(bundle_id=bundle_id)
    

    pagination = query.paginate(page=page, per_page=20, error_out=False)
    

    enriched_items = []
    for assoc in pagination.items:
        rule = Rule.query.get(assoc.rule_id)
        if rule and not rule.is_deleted:
            enriched_items.append({
                "rule": rule.to_json(),
                "association": assoc.to_json()
            })
    

    pagination.items = enriched_items
    return pagination

def get_bundle_by_id(bundle_id: int):
    return Bundle.query.get(bundle_id)

def get_only_root_nodes(bundle_id: int):
    return BundleNode.query.filter_by(bundle_id=bundle_id, parent_id=None).all()


# ─────────────────────────────────────────────────────────────────────────────
# ATT&CK Coverage
# ─────────────────────────────────────────────────────────────────────────────

import re as _re
from collections import defaultdict as _dd

_TACTIC_ORDER = [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact',
]

_TACTIC_LABELS = {
    'reconnaissance':      'Reconnaissance',
    'resource-development':'Resource Development',
    'initial-access':      'Initial Access',
    'execution':           'Execution',
    'persistence':         'Persistence',
    'privilege-escalation':'Privilege Escalation',
    'defense-evasion':     'Defense Evasion',
    'credential-access':   'Credential Access',
    'discovery':           'Discovery',
    'lateral-movement':    'Lateral Movement',
    'collection':          'Collection',
    'command-and-control': 'Command and Control',
    'exfiltration':        'Exfiltration',
    'impact':              'Impact',
}

_TACTIC_ALIASES = {
    'resource_development':  'resource-development',
    'initial_access':        'initial-access',
    'privilege_escalation':  'privilege-escalation',
    'defense_evasion':       'defense-evasion',
    'credential_access':     'credential-access',
    'lateral_movement':      'lateral-movement',
    'command_and_control':   'command-and-control',
}

_TECH_RE = _re.compile(r'\bT(\d{4})(?:\.(\d{3}))?\b', _re.IGNORECASE)


def _norm_tactic(raw: str) -> str:
    k = raw.lower().replace(' ', '-').replace('_', '-')
    return _TACTIC_ALIASES.get(k.replace('-', '_'), k)


def _parse_sigma(content: str):
    """Return (tactics: list[str], techniques: list[str]) from a Sigma rule."""
    tactics, techs = [], []
    in_tags = False
    for line in content.split('\n'):
        s = line.strip()
        if s.startswith('tags:'):
            in_tags = True
            continue
        if in_tags:
            if s.startswith('- attack.'):
                val = s[9:].strip().lower()
                m = _re.match(r'^(t\d{4})(\.\d{3})?$', val)
                if m:
                    techs.append(val.upper())
                else:
                    tactics.append(_norm_tactic(val))
            elif s and not s.startswith('-') and not s.startswith('#'):
                in_tags = False
    return tactics, techs


def _parse_generic(content: str):
    """Extract technique IDs from any rule content (YARA meta, comments, etc.)."""
    return [f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else '')
            for m in _TECH_RE.finditer(content)]


def get_attack_coverage(bundle_id: int) -> dict:
    """
    Return MITRE ATT&CK coverage data for all rules in a bundle.
    Reads from RuleAttackAssociation (populated by the auto-parse job).
    Falls back to on-the-fly parsing when the DB has no associations yet.
    """
    from app.core.db_class.db import RuleAttackAssociation, AttackTechnique

    bundle = Bundle.query.get(bundle_id)
    if not bundle:
        return None

    # All rule IDs in the bundle
    rule_rows = (
        db.session.query(Rule.id, Rule.title, Rule.uuid)
        .join(BundleRuleAssociation, Rule.id == BundleRuleAssociation.rule_id)
        .filter(BundleRuleAssociation.bundle_id == bundle_id, Rule.is_deleted == False)
        .all()
    )
    total_rules = len(rule_rows)
    rule_map = {r.id: {'id': r.id, 'name': r.title or '', 'uuid': str(r.uuid) if r.uuid else ''}
                for r in rule_rows}
    rule_ids = list(rule_map.keys())

    # Fetch associations from DB
    assoc_rows = (
        db.session.query(
            RuleAttackAssociation.rule_id,
            RuleAttackAssociation.technique_id,
            AttackTechnique.tactic_keys,
        )
        .join(AttackTechnique, RuleAttackAssociation.technique_id == AttackTechnique.technique_id)
        .filter(RuleAttackAssociation.rule_id.in_(rule_ids))
        .all()
    ) if rule_ids else []

    # If no DB associations, fall back to parsing
    use_fallback = not assoc_rows and rule_ids

    if use_fallback:
        return _get_attack_coverage_parsed(bundle_id, rule_map, total_rules)

    # tactic_key -> technique_id -> list of rule dicts
    coverage: dict = _dd(lambda: _dd(list))
    rules_with_attack: set = set()

    for rule_id, technique_id, tactic_keys in assoc_rows:
        info = rule_map.get(rule_id)
        if not info:
            continue
        rules_with_attack.add(rule_id)
        tactics = tactic_keys or ['unknown']
        for tac in tactics:
            coverage[tac][technique_id].append(info)

    # Build ordered output
    tactics_out = []
    all_techs: set = set()
    covered_count = 0

    for key in _TACTIC_ORDER:
        tac_techs = coverage.get(key, {})
        techs_out = []
        for tid, rules in tac_techs.items():
            if tid:
                all_techs.add(tid)
                techs_out.append({'id': tid, 'count': len(rules),
                                  'rules': rules})
        techs_out.sort(key=lambda x: x['id'])
        is_covered = bool(techs_out)
        if is_covered:
            covered_count += 1
        tactics_out.append({
            'key':            key,
            'label':          _TACTIC_LABELS.get(key, key.replace('-', ' ').title()),
            'covered':        is_covered,
            'technique_count': len(techs_out),
            'rule_count':     sum(t['count'] for t in techs_out),
            'techniques':     techs_out,
        })

    return {
        'tactics': tactics_out,
        'stats': {
            'covered_tactics':    covered_count,
            'total_tactics':      len(_TACTIC_ORDER),
            'unique_techniques':  len(all_techs),
            'rules_with_attack':  len(rules_with_attack) if isinstance(rules_with_attack, set) else rules_with_attack,
            'total_rules':        total_rules,
        },
    }


def _get_attack_coverage_parsed(bundle_id: int, rule_map: dict, total_rules: int) -> dict:
    """Fallback: parse rule content directly when no DB associations exist yet."""
    rows = (
        db.session.query(Rule.id, Rule.format, Rule.to_string)
        .join(BundleRuleAssociation, Rule.id == BundleRuleAssociation.rule_id)
        .filter(BundleRuleAssociation.bundle_id == bundle_id, Rule.is_deleted == False)
        .all()
    )

    coverage: dict = _dd(lambda: _dd(list))
    rules_with_attack: set = set()

    for rule_id, fmt, content in rows:
        info = rule_map.get(rule_id, {'id': rule_id, 'name': '', 'uuid': ''})
        content = content or ''

        if fmt == 'sigma':
            tactics, techs = _parse_sigma(content)
        else:
            tactics, techs = [], _parse_generic(content)

        if not tactics and not techs:
            continue
        rules_with_attack.add(rule_id)

        if tactics and techs:
            for tac in tactics:
                for tech in techs:
                    coverage[tac][tech].append(info)
        elif tactics:
            for tac in tactics:
                coverage[tac][''].append(info)
        else:
            for tech in techs:
                coverage['unknown'][tech].append(info)

    # Build ordered output (shared logic)
    tactics_out = []
    all_techs: set = set()
    covered_count = 0

    for key in _TACTIC_ORDER:
        tac_techs = coverage.get(key, {})
        techs_out = []
        for tid, rule_list in tac_techs.items():
            if tid:
                all_techs.add(tid)
                techs_out.append({'id': tid, 'count': len(rule_list), 'rules': rule_list})
        techs_out.sort(key=lambda x: x['id'])
        is_covered = bool(techs_out)
        if is_covered:
            covered_count += 1
        tactics_out.append({
            'key': key,
            'label': _TACTIC_LABELS.get(key, key.replace('-', ' ').title()),
            'covered': is_covered,
            'technique_count': len(techs_out),
            'rule_count': sum(t['count'] for t in techs_out),
            'techniques': techs_out,
        })

    return {
        'tactics': tactics_out,
        'stats': {
            'covered_tactics':   covered_count,
            'total_tactics':     len(_TACTIC_ORDER),
            'unique_techniques': len(all_techs),
            'rules_with_attack': len(rules_with_attack),
            'total_rules':       total_rules,
            'source':            'parsed',   # hint for frontend
        },
    }