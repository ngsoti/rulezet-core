# create a misp object for rule rulezet-metadata + relationship with rule-object
import json
from pymisp import MISPEvent, MISPObject
from ..rule import rule_core as RuleModel

#################################################
#   MISP object : rulezet-metadata              #
#################################################

def create_rulezet_metadata_misp_object(rule_id: int) -> MISPObject:
    """
    Specific mapper for Rulezet metadata based on the 'rulezet-metadata' object template.
    """
    misp_object = MISPObject(name='rulezet-metadata', ignore_warning=False)

    rule = RuleModel.get_rule(rule_id)
    if not rule:
        print(f"Rule with ID {rule_id} not found.")
        return None

    # Required fields
    misp_object.add_attribute('title', rule.title)
    misp_object.add_attribute('uuid', value=rule.uuid)

    # Optional fields
    if rule.version:
        misp_object.add_attribute('version', value=rule.version)

    if rule.format:
        misp_object.add_attribute('format', value=rule.format)

    if rule.license:
        misp_object.add_attribute('license', value=rule.license)

    if rule.description:
        misp_object.add_attribute('description', value=rule.description)

    if rule.source:
        misp_object.add_attribute('source', value=rule.source)

    if rule.author:
        misp_object.add_attribute('author', value=rule.author)

    if rule.original_uuid:
        misp_object.add_attribute('original-uuid', value=rule.original_uuid)

    if rule.user_id:
        misp_object.add_attribute('user-id', value=str(rule.user_id))

    if rule.creation_date:
        misp_object.add_attribute('creation-date', value=rule.creation_date)

    if rule.last_modif:
        misp_object.add_attribute('last-modif', value=rule.last_modif)

    if rule.vote_up is not None:
        misp_object.add_attribute('vote-up', value=rule.vote_up)

    if rule.vote_down is not None:
        misp_object.add_attribute('vote-down', value=rule.vote_down)

    # if rule.to_string:
    #     misp_object.add_attribute('to-string', value=rule.to_string)

    if rule.github_path:
        misp_object.add_attribute('github-path', value=rule.github_path)

    # cve_id stored as comma-separated string → multiple attributes
    if rule.cve_id:
        try:
            cve_list = json.loads(rule.cve_id) if isinstance(rule.cve_id, str) else rule.cve_id
            for cve in cve_list:
                cve = cve.strip()
                if cve:
                    misp_object.add_attribute('cve-id', value=cve)
        except (json.JSONDecodeError, AttributeError):
            pass


    return misp_object


#################################################################
#   Rulezet base object with metadata + content + relationship  #
#################################################################


def get_rule_misp_object_base(rule_id: int):
    """Get a MISP object for a specific rule, including metadata and content. (list of objects)"""

    event = MISPEvent()
    metadata_object_rule = event.add_object(create_rulezet_metadata_misp_object(rule_id))
    content_object_rule = event.add_object(content_convert_to_misp_object(rule_id))

    metadata_object_rule.add_reference(content_object_rule.uuid, 'related-to')

    return event







def get_rule_misp_object(rule_id: int):
    event = get_rule_misp_object_base(rule_id)
    event = json.loads(event.to_json())
    return {key: value for key, value in event.items() if key == "Object"}

def get_rule_misp_event(rule_id: int):
    rule_ = RuleModel.get_rule(rule_id)
    if not rule_:
        return None
    event = get_rule_misp_object_base(rule_id)
    event.info = f"Rule {rule_id} - {rule_.title}"

    rule_object = event.objects[1] 

    if rule_.cve_id:
        # convert string to list
        vuln_list = json.loads(rule_.cve_id)


        for value in vuln_list:
            attribute =  event.add_attribute('vulnerability', value)
            rule_object.add_reference(attribute.uuid, 'related-to')

    tags = RuleModel.get_tags_for_rule(rule_id)
    if tags:
        for tag in tags:
            if tag.external_id:
                event.add_tag(**{'name': tag.name, 'uuid': tag.external_id})
                continue
            event.add_tag(tag.name)



    return json.loads(event.to_json())


def content_convert_to_misp_object(rule_id: int) -> MISPObject | None:
    """
    Convert a rule into a MISP object with validation.
    """
    try:
        rule = RuleModel.get_rule(rule_id)
        if not rule:    
            return None

        fmt = rule.format.lower() if rule.format else ""

        if fmt == "yara":
            misp_object = create_yara_misp_object(rule)
        elif fmt == "sigma":
            misp_object = create_sigma_misp_object(rule)
        elif fmt == "suricata":
            misp_object = create_suricata_misp_object(rule)
        elif fmt == "wazuh":
            misp_object = create_wazuh_misp_object(rule)
        elif fmt == "nse":
            misp_object = create_nse_misp_object(rule)
        elif fmt == "crs":
            misp_object = create_crs_misp_object(rule)            


        elif fmt == "nova":
            misp_object = create_nova_misp_object(rule)
        else:
            # Generic fallback
            misp_object = MISPObject(name=fmt, ignore_warning=True)
            if rule.to_string:
                misp_object.add_attribute(fmt, value=rule.to_string)


        return misp_object

    except Exception as e:
        return None

def create_yara_misp_object(rule) -> MISPObject:
    """
    Specific mapper for YARA rules to match the MISP 'yara' object template.
    """
    try:
        misp_object = MISPObject(name='yara', ignore_warning=False)
        # "meta-category": "misc",
        misp_object['meta-category'] = "misc"

        # Required: YARA rule content
        if rule.to_string:
            misp_object.add_attribute('yara', value=rule.to_string)

        # Required: Rule name
        if rule.title:
            misp_object.add_attribute('yara-rule-name', value=rule.title)

        return misp_object
    except Exception as e:
        return None , str(e)

def create_sigma_misp_object(rule) -> MISPObject:
    """
    Specific mapper for Sigma rules based on the 'sigma' object template.
    """
    misp_object = MISPObject(name='sigma', ignore_warning=False)
    # "meta-category": "misc",
    misp_object['meta-category'] = "misc"

    if rule.to_string:
        misp_object.add_attribute(
            'sigma', 
            value=rule.to_string, 
            type='sigma', 
            to_ids=True
        )

    if rule.title:
        misp_object.add_attribute(
            'sigma-rule-name', 
            value=rule.title, 
            type='text'
        )

    return misp_object

def create_suricata_misp_object(rule) -> MISPObject:
    """
    Specific mapper for Suricata rules based on the 'suricata' object template.
    """
    misp_object = MISPObject(name='suricata', ignore_warning=False)
    # "meta-category": "network",
    misp_object['meta-category'] = "network"

    if rule.to_string:
        misp_object.add_attribute(
            'suricata', 
            value=rule.to_string, 
            type='snort', 
            to_ids=True
        )

    if rule.source:
        misp_object.add_attribute(
            'ref', 
            value=rule.source, 
            type='link'
        )

    return misp_object

def create_nse_misp_object(rule) -> MISPObject:
    """
    Specific mapper for Nmap NSE scripts based on the 'nse' object template.
    """
    misp_object = MISPObject(name='nse', ignore_warning=False)

    misp_object['meta-category'] = "network"

    misp_object.uuid = rule.uuid

    if rule.to_string:
        misp_object.add_attribute(
            'nse', 
            value=rule.to_string, 
            type='text'
        )


    if rule.title:
        misp_object.add_attribute(
            'nse-script-name', 
            value=rule.title, 
            type='text'
        )

    return misp_object
def create_wazuh_misp_object(rule) -> MISPObject:
    """
    Specific mapper for Wazuh rules based on the 'wazuh-rule' object template.
    """
    
    misp_object = MISPObject(name='wazuh-rule', ignore_warning=False)

    misp_object['meta-category'] = "misc"

    if rule.to_string:
        misp_object.add_attribute(
            'wazuh-rule', 
            value=rule.to_string, 
            type='text'
        )

    if rule.title:
        misp_object.add_attribute(
            'rule-id', 
            value=rule.title, 
            type='text'
        )

    return misp_object

def create_crs_misp_object(rule) -> MISPObject:
    """
    Specific mapper for OWASP CRS (WAF) rules based on the 'owasp-crs-rule' template.
    """
    misp_object = MISPObject(name='owasp-crs-rule' ,ignore_warning=False)
    
    misp_object['meta-category'] = 'network'

    if rule.title:
        misp_object.add_attribute('rule-id', value=rule.title, type='text')
    
    if rule.to_string:
        misp_object.add_attribute('raw-rule', value=rule.to_string, type='text')

    return misp_object

def create_nova_misp_object(rule) -> MISPObject:
    """
    Specific mapper for NOVA prompt detection rules based on the 'nova-rule' template.
    """

    misp_object = MISPObject(name='nova-rule', ignore_warning=False)

    #   "meta-category": "detection"
    misp_object['meta-category'] = "detection"

    if rule.to_string:
        misp_object.add_attribute('raw-rule', value=rule.to_string, type='text')


    if rule.title:
        misp_object.add_attribute('rule-name', value=rule.title, type='text')

    return misp_object