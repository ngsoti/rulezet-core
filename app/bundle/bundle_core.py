import datetime
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

    new_bundle = Bundle(
        name=form_dict["name"],
        description=form_dict["description"],
        user_id=user.id,
        access=form_dict["public"],
        created_at=datetime.datetime.now(tz=datetime.timezone.utc)
    )
    db.session.add(new_bundle)
    db.session.commit()
    return new_bundle


def get_bundle_by_id(bundle_id: int) -> Bundle | None:
    """
    Retrieve a Bundle by its ID.
    :param bundle_id: ID of the bundle.
    :return: Bundle instance or None if not found.
    """
    return Bundle.query.get(bundle_id)


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

    return query.order_by(Bundle.created_at.desc()).paginate(page=page, per_page=20)



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


def add_rules_to_bundle(bundle_id: int, rule_ids: list[int]) -> list[BundleRuleAssociation]:
    """
    Add multiple rules to a bundle.
    :param bundle_id: ID of the bundle.
    :param rule_ids: List of rule IDs to add.
    :return: List of created BundleRuleAssociation objects (skips duplicates).
    """
    added_associations = []
    for rule_id in rule_ids:
        existing = BundleRuleAssociation.query.filter_by(bundle_id=bundle_id, rule_id=rule_id).first()
        if not existing:
            assoc = BundleRuleAssociation(
                bundle_id=bundle_id,
                rule_id=rule_id,
                added_at=datetime.datetime.now(tz=datetime.timezone.utc)
            )
            db.session.add(assoc)
            added_associations.append(assoc)
    db.session.commit()
    return added_associations

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

    # # Get the associated Bundle
    # bundle = assoc.bundle
    # if not bundle:
    #     return {"error": f"No bundle found for bundle_id {assoc.bundle_id}"}

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


def get_all_bundles_own_page(page: int, search: str| None) -> dict:
    """
    List all bundles paginated, with optional search filter (own by current user).
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
    query = query.filter_by(user_id=current_user.id)
    return query.order_by(Bundle.created_at.desc()).paginate(page=page, per_page=20)


def get_total_bundles_count_own() -> int:
    """
    get the count of bundles (own by current user)
    :return: int the number of bundles.
    """
    return Bundle.query.filter_by(user_id=current_user.id).count()

def get_bundles_by_rule(rule_id: int) -> List[Bundle]:
    """
    Retrieve all bundles that contain a specific rule.
    :param rule_id: ID of the rule to search for.
    :return: List of Bundle instances containing the specified rule.
    """
    return (
        db.session.query(Bundle)
        .join(BundleRuleAssociation, BundleRuleAssociation.bundle_id == Bundle.id)
        .filter(BundleRuleAssociation.rule_id == rule_id)
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