from flask import json
from pymisp import MISPObject, MISPEvent
from pymisp import InvalidMISPObject

from ..rule import rule_core as RuleModel
from app.features.rule.rule_core import get_all_format
import requests

def content_convert_to_misp_object(rule_id: int) -> str:
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


        # If valid, wrap and export
        event = MISPEvent()
        # add meta catgeory 
        event.info = f"Rule {rule.title} converted to MISP object"
        event.add_object(misp_object)
        return event.to_json(indent=2)

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

        # Optional fields
        if rule.version:
            misp_object.add_attribute('version', value=rule.version)
        if rule.description:
            misp_object.add_attribute('comment', value=rule.description)
        if rule.source:
            misp_object.add_attribute('reference', value=rule.source)    

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

    if rule.source:
        misp_object.add_attribute(
            'reference', 
            value=rule.source, 
            type='link'
        )

    if rule.description:
        misp_object.add_attribute(
            'comment', 
            value=rule.description, 
            type='comment'
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

    if rule.version:
        misp_object.add_attribute(
            'version', 
            value=rule.version, 
            type='text'
        )

    if rule.description:
        misp_object.add_attribute(
            'comment', 
            value=rule.description, 
            type='comment'
        )

    return misp_object

def create_nse_misp_object(rule) -> MISPObject:
    """
    Specific mapper for Nmap NSE scripts based on the 'nse' object template.
    """
    misp_object = MISPObject(name='nse', ignore_warning=False)

    misp_object['meta-category'] = "network"

    if rule.to_string:
        misp_object.add_attribute(
            'nse', 
            value=rule.to_string, 
            type='text'
        )

    print(rule.to_string)

    if rule.title:
        misp_object.add_attribute(
            'nse-script-name', 
            value=rule.title, 
            type='text'
        )

    if rule.author:
        misp_object.add_attribute('author', value=rule.author, type='text')
    
    if rule.license:
        misp_object.add_attribute('license', value=rule.license, type='text')

    if rule.description:
        misp_object.add_attribute('description', value=rule.description, type='text')
    
    if rule.version:
        misp_object.add_attribute('version', value=rule.version, type='text')

    if rule.source:
        misp_object.add_attribute('reference', value=rule.source, type='link')

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

    if rule.description:
        misp_object.add_attribute(
            'description', 
            value=rule.description, 
            type='text'
        )

    if rule.version:
        misp_object.add_attribute(
            'version', 
            value=rule.version, 
            type='text'
        )

    if rule.source:
        misp_object.add_attribute(
            'reference', 
            value=rule.source, 
            type='link'
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
    
    if rule.description:
        misp_object.add_attribute('message', value=rule.description, type='text')

    if rule.to_string:
        misp_object.add_attribute('raw-rule', value=rule.to_string, type='text')

    if rule.version:
        misp_object.add_attribute('crs-version', value=rule.version, type='text')
    
    if rule.source:
        misp_object.add_attribute('reference', value=rule.source, type='link')





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

    if rule.author:
        misp_object.add_attribute('author', value=rule.author, type='text')
    
    if rule.description:
        misp_object.add_attribute('description', value=rule.description, type='text')


    if rule.source:
        misp_object.add_attribute('reference', value=rule.source, type='link')
        

    return misp_object
def convert_misp_to_stix(misp_object: json) -> dict | None:
    """Converts a MISP object to STIX via the cti-transmute.org API."""
    try:
        response = requests.post(
            "https://cti-transmute.org/api/convert/misp_to_stix",
            json=misp_object,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.raise_for_status()

        return response.json()
    except requests.RequestException as e:
        return None
    


