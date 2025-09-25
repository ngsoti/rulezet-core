from pymisp import MISPObject, MISPEvent
import json
from ..rule import rule_core as RuleModel
from app.rule.rule_core import get_all_format


def content_convert_to_misp_object(rule_id: int) -> dict:
    """
    Convert a detection rule into a MISP object.

    Args:
        rule_id (int): ID of the rule to export.

    Returns:
        dict: JSON representation of the MISP object
    """
   
    try:
        # Fetch the rule
        rule = RuleModel.get_rule(rule_id)
        if not rule:
            raise ValueError(f"[ERROR] Rule with id={rule_id} not found")

        # Get all formats available in DB
        available_formats = [f["name"].lower() for f in get_all_format()]

        # Ensure the rule format is valid
        if not rule.format or rule.format.lower() not in available_formats:
            raise ValueError(
                f"[ERROR] Rule format '{rule.format}' is not supported. Available formats: {available_formats}"
            )

        fmt = rule.format.lower()

        # Create the MISP custom object with the rule format as name
        misp_object = MISPObject(name=fmt, ignore_warning=True)

        # Add content
        misp_object.add_attribute(
            object_relation=fmt,
            value=rule.to_string,
            type=fmt,
            to_ids=True
        )

        # Add rule name
        misp_object.add_attribute(
            object_relation=f"{fmt}-rule-name",
            value=rule.title,
            type='text'
        )

        # Add description if exists
        if rule.description:
            misp_object.add_attribute(
                object_relation='comment',
                value=rule.description,
                type='comment'
            )

        # Wrap inside a MISP Event to be a valid object export
        event = MISPEvent()
        event.add_object(misp_object)

        object_json = event.to_json(indent=2)

        return object_json
    except Exception as e:
        return None





#  # Create a custom MISP object (no template required)
#     misp_object = MISPObject(name='yara', ignore_warning=True)

#     # Add YARA content
#     misp_object.add_attribute(
#         object_relation='yara',
#         value=rule.to_string,
#         type='yara',
#         to_ids=True
#     )

#     # Add rule name
#     misp_object.add_attribute(
#         object_relation='yara-rule-name',
#         value=rule.title,
#         type='text'
#     )

#     # Add description if exists
#     if rule.description:
#         misp_object.add_attribute(
#             object_relation='comment',
#             value=rule.description,
#             type='comment'
#         )

#     # Export the object as standalone JSON
#     object_json = misp_object.to_json(indent=2)

#     # produce only a json with atribut .... but no Object found by MISP import

#     # To encapsule an object in event ( create )
#     # uuid	"45f2e110-1743-47f8-b998-47974583da4a"
#     # Object	[ {…} ]
#     # info	"test"

#     event = MISPEvent()
#     event.add_object(misp_object)
#     object_json = event.to_json(indent=2)