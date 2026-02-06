from app.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult, load_all_rule_formats
from .. import db
from ..db_class.db import *
from app.rule_format.available_format import * 

from ..rule import rule_core as RuleModel
from flask_login import current_user

#############################################################################################
# Map format -> class                                                                       #
#                                                                                           #
# /!\   If you want to add a format, you can add the name in the format_classes dict        #
#       If you have implement the format's class (validate()), the programme gonna do       #
#       all the verification. No code to add, juste in the dict                             #
##############################################################################################


def Process_rules_by_format(format_files: list, format_rule: dict, info: dict, format_name: str , user: User) -> int:
    imported = 0
    skipped = 0
    bad_rules = 0

    for filepath in format_files:
        rules = format_rule.extract_rules_from_file(filepath)
        for rule_text in rules:    
            # enrich info with filepath
            enriched_info = {**info, "filepath": filepath}
            # Validate
            validation_result  = format_rule.validate(rule_text)
            # Parse metadata
            metadata = format_rule.parse_metadata(rule_text , enriched_info , validation_result)

            result_dict = {
                "validation": {
                    "ok": validation_result.ok,
                    "errors": validation_result.errors,
                    "warnings": validation_result.warnings
                },
                "rule": metadata,
                "raw_rule": rule_text,
                "file": filepath
            }

            # Attempt to create rule if validation is OK
            if validation_result.ok:
                success = RuleModel.add_rule_core(result_dict["rule"], user)
                if success:
                    imported += 1
                else:
                    skipped += 1
            else:
                RuleModel.save_invalid_rule(
                    form_dict=metadata,
                    to_string=rule_text,
                    rule_type=format_name,
                    error=validation_result.errors,
                    user=user
                )

                bad_rules += 1

    return bad_rules, imported, skipped


async def extract_rule_from_repo(repo_dir: str, info: dict, user: User):
    """
    Test all rules in a repo for all formats, returns results .
    """

    bad_rules = 0
    imported = 0
    skipped = 0

    # Get all subclasses of RuleType
    subclasses = RuleType.__subclasses__()

    # __subclasses__() : 
    # Thanks to that methode we can add new format without changing this function
    # The function is able to parse all the formats implemented in the rule_formats folder
    # Just need to add the new class in the rule_formats folder and implement the abstract methods
    # No need to change this function

    for RuleClass in subclasses:
        rule_instance = RuleClass()

        format_name = rule_instance.format       
        #class_name = rule_instance.get_class()  

        files = rule_instance.get_rule_files(repo_dir)

        bad, imported_count, skipped_count = Process_rules_by_format(
            files, rule_instance, info, format_name, user
        )

        bad_rules += bad
        imported += imported_count
        skipped += skipped_count

    return bad_rules, imported, skipped


def verify_syntax_rule_by_format(rule_dict: dict) -> tuple[bool, str]:
    """
    Verify the syntax of the rule based on its format to accept or reject its creation.
    Returns (True, "") if the syntax is valid, (False, error_message) otherwise.
    """

    rule_format = rule_dict.get("format", "").lower()
    if not rule_format:
        return False, "Missing rule format."
    load_all_rule_formats()
    matching_class = None
    for cls in RuleType.__subclasses__():
        try:
            if cls().format.lower() == rule_format:
                matching_class = cls
                break
        except Exception as e:
            continue
    if not matching_class:
        return False, f"Format '{rule_format}' is not supported."

    # Class instantiation
    rule_instance: RuleType = matching_class()

    # Get the rule content to validate
    content = rule_dict.get("to_string", "")
    if not content:
        return False, "Rule content ('to_string') is empty."

    try:
        result: ValidationResult = rule_instance.validate(content)

        if result.ok:
            return True, ""
        else:
            error_msg = "; ".join(result.errors) if result.errors else "Unknown validation error"
            return False, error_msg

    except Exception as e:
        return False, str(e)

# The rule_dict :

# {'format': 'sigma', 'title': 'q', 'license': '0BSD', 'description': 'No description for the rule', 'source': 'admin admin',
#   'version': '1.0', 'to_string': 'q', 'cve_id': [], 'author': 'admin', 'creation_date': (datetime.datetime(2025, 9, 10, 12, 9, 47, 2389, tzinfo=datetime.timezone.utc),)}


def process_and_import_fixed_rule(bad_rule_obj: InvalidRuleModel, raw_content: str):
    """
    Process a corrected bad rule from InvalidRuleModel and attempt to import it using format-specific classes.
    """

    try:
        rule_dict = {
            "format": bad_rule_obj.rule_type,
            "to_string": raw_content,
            "license": bad_rule_obj.license,
            "file_name": getattr(bad_rule_obj, "file_name", None),
            "user_id": bad_rule_obj.user_id
        }

        is_valid, error_msg = verify_syntax_rule_by_format(rule_dict)
        if not is_valid:
            bad_rule_obj.error_message = error_msg
            db.session.commit()
            return False, error_msg, None

        rule_format = bad_rule_obj.rule_type.lower()
        matching_class = None
        for cls in RuleType.__subclasses__():
            try:
                if cls().format.lower() == rule_format:
                    matching_class = cls
                    break
            except Exception:
                continue

        if not matching_class:
            return False, f"Format '{rule_format}' is not supported.", None

        rule_instance: RuleType = matching_class()

        info = {
            "license": bad_rule_obj.license,
            "author": getattr(current_user, "first_name", "Unknown"),
            "repo_url": bad_rule_obj.url
        }


        validation_result: ValidationResult = rule_instance.validate(raw_content)
        metadata = rule_instance.parse_metadata(raw_content, info, validation_result)
        print(bad_rule_obj.github_path)
        metadata["github_path"] = bad_rule_obj.github_path

        result_dict = {
            "validation": {
                "ok": validation_result.ok,
                "errors": validation_result.errors,
                "warnings": validation_result.warnings
            },
            "rule": metadata,
            "raw_rule": raw_content,
            "file": bad_rule_obj.url
        }


        if validation_result.ok:
            success , msg = RuleModel.add_rule_core(result_dict["rule"], current_user)
            if success:
                db.session.delete(bad_rule_obj)
                db.session.commit()
                return True, "", success
            else:
                return False, "Rule already exists or failed to insert.", None
        else:
            return False, "Validate has been out passed! The rule syntax is corrupt.", None

    except Exception as e:
        db.session.rollback()
        return False, str(e), None
    



def parse_rule_by_format(rule_content: str, user: User, format_name: str, url_repo=None, github_path=None):
    """
    Parse a rule content based on its format.
    """

    load_all_rule_formats()
    matching_class = None
    for RuleClass in RuleType.__subclasses__():
        try:
            if RuleClass().format.lower() == format_name.lower():
                matching_class = RuleClass
                break
        except Exception:
            continue

    if not matching_class:
        return False, f"Format '{format_name}' is not supported.", None

    rule_instance = matching_class()

    validation_result = rule_instance.validate(rule_content)

    info = {
        "license": getattr(user, "license", None) or "Unknown",
        "author": getattr(user, "first_name", "Unknown"),
        "repo_url": url_repo or None,
        "source": current_user.first_name + current_user.last_name or "Unknown",
    }

    metadata = rule_instance.parse_metadata(rule_content, info, validation_result)

    if not validation_result.ok:
        RuleModel.save_invalid_rule(
            form_dict=metadata,
            to_string=rule_content,
            rule_type=format_name,
            error=validation_result.errors,
            user=user,
            github_path=github_path
        )
        return False, "Invalid rule", None

    exists, rule_id = RuleModel.rule_exists(metadata)
    if exists == True:
        rule = RuleModel.get_rule(rule_id)
        return False, "Rule already exists", rule

    if github_path:
        metadata["github_path"] = github_path

    rule, msg = RuleModel.add_rule_core(metadata, user)
    if rule:
        return True, "Rule created", rule
    else:
        print("j'ai pas ete cree")
        RuleModel.save_invalid_rule(
            form_dict=metadata,
            to_string=rule_content,
            rule_type=format_name,
            error=["Failed to insert rule into DB"],
            user=user,
            github_path=github_path
        )
        return False, "Failed to insert rule", None
