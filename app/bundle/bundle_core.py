import datetime
import uuid
from sqlalchemy import Tuple, and_, or_
from flask_login import current_user
from .. import db
from ..db_class.db import *
from app.db_class.db import Bundle, BundleRuleAssociation
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
def get_all_bundles_page(page: int, search: str | None, own: bool, tag_ids: list[int] | None = None, vulnerabilities: list[str] | None = None) -> dict:
    query = Bundle.query    

    if search:
        like_pattern = f"%{search}%"
        query = query.filter(or_(Bundle.name.ilike(like_pattern), Bundle.description.ilike(like_pattern)))


    if tag_ids:
        query = query.join(BundleTagAssociation).filter(BundleTagAssociation.tag_id.in_(tag_ids)).distinct()

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
            query = query.filter(
                or_(Bundle.access.is_(True), Bundle.user_id == current_user.id)
            )
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
    if not bundle_id or not rule_id or not description:
        return False
    
    # Ensure bundle and rule exist
    bundle = get_bundle_by_id(bundle_id)
    if not bundle:
        return False
    rule = RuleModel.get_rule(rule_id)
    if not rule:
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
        .filter(BundleRuleAssociation.bundle_id == bundle_id)
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
    if not rule:
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


    associations = BundleRuleAssociation.query.filter_by(bundle_id=bundle_id).all()
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
        print(e)
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
            if not rule:
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
        print(f"Error updating bundle rules: {e}")
        return False
    

def update_bundle_from_rule_id_into_structure(bundle_id):
    """
    Update the UI structure to include all rules associated with the bundle.
    """
    try:

        bundle = Bundle.query.get(bundle_id)
        if not bundle:
            return False, "Bundle not found"

        bundle_rules = BundleRuleAssociation.query.filter_by(bundle_id=bundle_id).all()
        
        BundleNode.query.filter_by(bundle_id=bundle_id).delete()
        db.session.commit()


        folder = BundleNode(
            bundle_id=bundle_id,
            parent_id=None,
            name=bundle.name,
            node_type="folder",
            rule_id=None,
            custom_content=None
        )
        db.session.add(folder)
        db.session.commit()
        folder_id = folder.id

        for rule in bundle_rules:
            rule_node = BundleNode(
                bundle_id=bundle_id,
                parent_id=folder_id,
                name=rule.rule.title,
                node_type="file",
                rule_id=rule.rule_id,
                custom_content=None
            )
            db.session.add(rule_node)
        db.session.commit()
        return True, "Structure updated successfully" 

    except Exception as e:
        db.session.rollback()
        print(f"Error updating bundle rules: {e}")
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
        if rule:
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