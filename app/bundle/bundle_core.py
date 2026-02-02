import datetime
import uuid
from sqlalchemy import or_
from flask_login import current_user
from .. import db
from ..db_class.db import *
from app.db_class.db import Bundle, BundleRuleAssociation
from typing import Dict, Any, Union , List
from ..rule import rule_core as RuleModel


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
        created_at=datetime.datetime.now(tz=datetime.timezone.utc)
    )

    try:
        db.session.add(new_bundle)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise e
        
    return new_bundle


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

def get_all_bundles_page(page: int, search: str| None, own: bool) -> dict:
    """
    List all bundles paginated, with optional search filter.
    :param page: Page number.
    :param search: The search string to filter by name or description.
    :return: Pagination object with filtered bundles.
    """
    query = Bundle.query    

    if search:
        like_pattern = f"%{search}%"
        query = query.filter(
            or_(
                Bundle.name.ilike(like_pattern),
                Bundle.description.ilike(like_pattern)
            )
        )
    if own:
        if current_user.is_authenticated:   
            query = query.filter_by(user_id=current_user.id)    
    if current_user.is_authenticated:
        # if admin see all elif not admin see only public and user connected see also his private
        if not current_user.is_admin():
            query = query.filter(
                or_(
                    Bundle.access.is_(True),
                    Bundle.user_id == current_user.id
                )
            )
        else:
            pass  
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
    if form_dict is not None:
        bundle.updated_at = datetime.datetime.now(tz=datetime.timezone.utc)
        bundle.name = form_dict["name"]
        bundle.description = form_dict["description"]
        bundle.access = form_dict["public"]
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
    # Get the Rule
    rule = Rule.query.get(rule_id)
    if not rule:
        return {"error": f"No rule found with id {rule_id}"}

    # Get the BundleRuleAssociation (first found)
    assoc = BundleRuleAssociation.query.filter_by(rule_id=rule_id).first()
    if not assoc:
        return {"error": f"No bundle association found for rule_id {rule_id}"}

    # Return combined data
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

    # Query all associated BundleRuleAssociation entries for this bundle
    associations = BundleRuleAssociation.query.filter_by(bundle_id=bundle_id).all()
    if not associations:
        return {"error": f"No rules associated with bundle id {bundle_id}"}

    # Extract rule IDs from associations
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
            Bundle.access.is_(True)  # Only include bundles where access == True
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
        # 1. Clear old structure to rebuild (Simple approach)
        # Because of cascade delete, deleting the root nodes will clean the rest
        

        BundleNode.query.filter_by(bundle_id=bundle_id).delete()

        def save_recursive(nodes, parent_id=None):
            for node in nodes:
                # If it's the 'root' folder from your Vue state, we might skip it 
                # or treat it as the top level.
                new_node = BundleNode(
                    bundle_id=bundle_id,
                    parent_id=parent_id,
                    name=node.get('name', 'unnamed'),
                    node_type=node.get('type', 'file'),
                    rule_id=node.get('rule_id'), # Present if added from Rule DB
                    custom_content=node.get('content') if not node.get('rule_id') else None
                )
                db.session.add(new_node)
                db.session.flush() # Get the new ID for children
                
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
            # Handle cases where rule_id might be a string or int
            found_ids.add(int(rid))
        
        # Recursive call for children
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

    # 1. Get all rule_ids currently present in the Vue.js tree
    new_rule_ids = extract_rule_ids(structure)

    # 2. Get existing associations from the DB
    # We fetch them to compare which ones need to be deleted
    existing_assocs = BundleRuleAssociation.query.filter_by(bundle_id=bundle_id).all()
    existing_rule_ids = {assoc.rule_id for assoc in existing_assocs}

    try:
        # --- DELETE PHASE ---
        # Remove associations that are in DB but NOT in the new structure
        for assoc in existing_assocs:
            if assoc.rule_id not in new_rule_ids:
                db.session.delete(assoc)

        # --- ADD & UPDATE PHASE ---
        for rid in new_rule_ids:
            rule = Rule.query.get(rid)
            if not rule:
                continue

           
            # If the rule is NEW to the bundle, create the association
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
        
        # create a folder and put in there all the rule to have the same structure in the db BundleNode
        # and resgister in the db BundleNode
        # create the folder 

        # delete all the children of the folder to create a clean structure
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