import json
from pymisp import MISPEvent, MISPObject

from app.features.misp.rule.misp_object import content_convert_to_misp_object, create_rulezet_metadata_misp_object
from ...bundle import bundle_core as BundleModel

###############################################
#   Get bundle in MISP Object or MISP Event   #
###############################################

def get_bundle_misp_event(bundle_id: int) -> dict | None:
    """
    Build a complete MISP event for a bundle:
    - bundle metadata object
    - each rule: metadata + content objects with references
    - tags at event level
    - vulnerabilities as event-level attributes
    Returns a dict (JSON-serializable).
    """
    bundle = BundleModel.get_bundle_by_id(bundle_id)
    if not bundle:
        return None

    event = MISPEvent()
    event.info = f"Bundle {bundle_id} - {bundle.name}"

    # 1. Bundle metadata object
    bundle_obj = create_bundle_misp_object(bundle_id)
    if bundle_obj:
        event.add_object(bundle_obj)

    # 2. Rules objects
    for assoc in bundle.rules_assoc:
        rule = assoc.rule
        if not rule:
            continue
        _add_rule_objects_to_event(event, rule, bundle_obj)

    # 3. Tags
    _add_bundle_tags_to_event(event, bundle_id)

    # 4. Vulnerabilities as event-level attributes
    _add_bundle_vulnerabilities_to_event(event, bundle, bundle_obj)

    return json.loads(event.to_json())


###############################################
#   Internal helpers                          #
###############################################

def _add_rule_objects_to_event(event: MISPEvent, rule, bundle_obj: MISPObject | None):
    """Add rulezet-metadata + content object for a rule, with references."""
    metadata_obj = create_rulezet_metadata_misp_object(rule.id)
    content_obj = content_convert_to_misp_object(rule.id)

    if metadata_obj:
        event.add_object(metadata_obj)
        # bundle contains this rule metadata
        if bundle_obj:
            bundle_obj.add_reference(metadata_obj.uuid, 'contains')

    if content_obj:
        event.add_object(content_obj)
        # metadata related to content
        if metadata_obj:
            metadata_obj.add_reference(content_obj.uuid, 'related-to')


def _add_bundle_tags_to_event(event: MISPEvent, bundle_id: int):
    """Add bundle tags to the MISP event."""
    try:
        tags = BundleModel.get_tags_for_bundle(bundle_id)
        if not tags:
            return
        for tag in tags:
            if tag.external_id:
                event.add_tag(**{'name': tag.name, 'uuid': tag.external_id})
            else:
                event.add_tag(tag.name)
    except Exception:
        pass


def _add_bundle_vulnerabilities_to_event(event: MISPEvent, bundle, bundle_obj: MISPObject | None):
    """Add vulnerability identifiers as event-level attributes linked to bundle object."""
    if not bundle.vulnerability_identifiers:
        return
    try:
        vulns = json.loads(bundle.vulnerability_identifiers)
        for vuln in vulns:
            vuln = vuln.strip() if isinstance(vuln, str) else str(vuln)
            if vuln:
                attribute = event.add_attribute('vulnerability', vuln)
                if bundle_obj:
                    bundle_obj.add_reference(attribute.uuid, 'related-to')
    except (json.JSONDecodeError, AttributeError):
        pass


#####################################
#   Create rulezet-bundle object    #
#####################################

def create_bundle_misp_object(bundle_id: int) -> MISPObject | None:
    """
    Specific mapper for Rulezet bundle based on the 'rulezet-bundle' object template.
    """
    bundle = BundleModel.get_bundle_by_id(bundle_id)
    if not bundle:
        return None

    misp_object = MISPObject(name='rulezet-bundle', ignore_warning=False)

    # Required fields
    misp_object.add_attribute('name', value=bundle.name)
    misp_object.add_attribute('uuid', value=bundle.uuid)

    # Optional fields
    if bundle.description:
        misp_object.add_attribute('description', value=bundle.description)

    author = bundle.get_username_by_id()
    if author:
        misp_object.add_attribute('author', value=author)

    user_name = bundle.get_rule_user_first_name_by_id()
    if user_name:
        misp_object.add_attribute('user-name', value=user_name)

    if bundle.user_id:
        misp_object.add_attribute('user-id', value=str(bundle.user_id))

    if bundle.access is not None:
        misp_object.add_attribute('access', value=str(bundle.access))

    if bundle.created_at:
        misp_object.add_attribute('created-at', value=bundle.created_at)

    if bundle.updated_at:
        misp_object.add_attribute('updated-at', value=bundle.updated_at)

    if bundle.created_by:
        misp_object.add_attribute('created-by', value=str(bundle.created_by))

    if bundle.is_verified is not None:
        misp_object.add_attribute('is-verified', value=bundle.is_verified)

    if bundle.vote_up is not None:
        misp_object.add_attribute('vote-up', value=bundle.vote_up)

    if bundle.vote_down is not None:
        misp_object.add_attribute('vote-down', value=bundle.vote_down)

    if bundle.download_count is not None:
        misp_object.add_attribute('download-count', value=bundle.download_count)

    if bundle.view_count is not None:
        misp_object.add_attribute('view-count', value=bundle.view_count)

    number_of_rules = len(bundle.rules_assoc.all())
    misp_object.add_attribute('number-of-rules', value=number_of_rules)

    formats = list(set([
        assoc.rule.format for assoc in bundle.rules_assoc
        if assoc.rule and assoc.rule.format
    ]))
    for fmt in formats:
        misp_object.add_attribute('rule-format', value=fmt)

    if bundle.vulnerability_identifiers:
        try:
            vulns = json.loads(bundle.vulnerability_identifiers)
            for vuln in vulns:
                vuln = vuln.strip() if isinstance(vuln, str) else str(vuln)
                if vuln:
                    misp_object.add_attribute('vulnerability-identifier', value=vuln)
        except (json.JSONDecodeError, AttributeError):
            pass

    return misp_object