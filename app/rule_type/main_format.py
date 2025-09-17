from app.rule_type.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from app.rule_type.rule_formats.crs_format import CRSRule
from app.rule_type.rule_formats.nova_format import NovaRule
from app.rule_type.rule_formats.sigma_format import SigmaRule
from app.rule_type.rule_formats.suricata_format import SuricataRule
from app.rule_type.rule_formats.yara_format import YaraRule
from app.rule_type.rule_formats.zeek_format import ZeekRule
from ..rule import rule_core as RuleModel
from flask_login import current_user

def Process_rules_by_format(format_files: list, format_rule: dict, info: dict, format_name: str) -> int:
    imported = 0
    skipped = 0
    bad_rules = 0

    for filepath in format_files:
        rules = format_rule.extract_rules_from_file(filepath)
        for rule_text in rules:
            # Validate
                validation_result  = format_rule.validate(rule_text)
                # Parse metadata
                metadata = format_rule.parse_metadata(rule_text , info , validation_result)
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
                    success = RuleModel.add_rule_core(result_dict["rule"], current_user)
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
                    )

                    bad_rules += 1
            # try:
                
                    
            # except Exception as e:
            #     # RuleModel.save_invalid_rule(
            #     #     form_dict=metadata if "metadata" in locals() else {},
            #     #     to_string=rule_text,
            #     #     rule_type=format_name,
            #     #     error=f"Unexpected parsing error: {e}",
            #     # )
            #     # bad_rules += 1
            #     print("nonnnnnnnnnnnnnn")
            #     print(str(e))

    return bad_rules, imported, skipped

async def extract_rule_from_repo(repo_dir: str , info: dict):
    """
    Test all YARA rules in a repo, returns results and classifies as valid or invalid.
    """
    imported = 0
    skipped = 0
    bad_rules = 0
    
    # Get all file in each format 

    yara_rule = YaraRule()
    yara_files = yara_rule.get_rule_files(repo_dir)

    sigma_rule = SigmaRule()
    sigma_files = sigma_rule.get_rule_files(repo_dir)

    suricata_rule = SuricataRule()
    suricata_files = suricata_rule.get_rule_files(repo_dir)

    crs_rule = CRSRule()
    crs_files = crs_rule.get_rule_files(repo_dir)

    zeek_rule = ZeekRule()
    zeek_files = zeek_rule.get_rule_files(repo_dir)

    nova_rule = NovaRule()
    nova_files = nova_rule.get_rule_files(repo_dir)
   
    # Process YARA rules
    bad_rules_yara, imported_yara, skipped_yara  = Process_rules_by_format(yara_files , yara_rule, info, "YARA")

    # Process Sigma rules
    bad_rules_sigma, imported_sigma, skipped_sigma  = Process_rules_by_format(sigma_files , sigma_rule, info, "SIGMA")

    # Process Suricata rules
    bad_rules_suricata, imported_suricata, skipped_suricata  = Process_rules_by_format(suricata_files , suricata_rule, info, "SURICATA")

    # Process CRS rules
    bad_rules_crs, imported_crs, skipped_crs  = Process_rules_by_format(crs_files , crs_rule, info, "CRS")

    # Process Zeek rules
    bad_rules_zeek, imported_zeek, skipped_zeek  = Process_rules_by_format(zeek_files , zeek_rule, info, "ZEEK")

    # Process Nova rules
    bad_rules_nova, imported_nova, skipped_nova  = Process_rules_by_format(nova_files , nova_rule, info, "NOVA")

    # Calculate all imported... rules

    bad_rules = bad_rules_yara + bad_rules_sigma + bad_rules_suricata + bad_rules_crs + bad_rules_zeek + bad_rules_nova
    imported = imported_yara + imported_sigma + imported_suricata + imported_crs + imported_zeek + imported_nova 
    skipped = skipped_yara + skipped_sigma + skipped_suricata + skipped_crs + skipped_zeek + skipped_nova

    

    return bad_rules, imported, skipped



def verify_syntax_rule_by_format(rule_dict: dict) -> tuple[bool, str]:
    """
    Verify the syntax of the rule based on its format to accept or reject its creation.
    Returns (True, "") if the syntax is valid, (False, error_message) otherwise.
    """
    # Map format -> class

    # /!\   If you want to add a format, you can add the name in the format_classes dict
    #       If you have implement the format's class (validate()), the programme gonna do
    #       all the verification. No code to add, juste in the dict

    format_classes = {
        "yara": YaraRule,
        "sigma": SigmaRule,
        "suricata": SuricataRule,
        "crs": CRSRule,
        "zeek": ZeekRule,
        "nova": NovaRule
        # write ear if you want to add a format 
        # "format_name": FormatclassRule
    }

    rule_format = rule_dict.get("format", "").lower()

    if rule_format not in format_classes:
        return False, f"Format '{rule_format}' is not supported."

    # Instantiate the corresponding class
    rule_instance: RuleType = format_classes[rule_format]()

    # Get the rule content to validate
    content = rule_dict.get("to_string", "")
    if not content:
        return False, "Rule content ('to_string') is empty."

    try:
        # Use the validate() method which returns a ValidationResult
        result: ValidationResult = rule_instance.validate(content)

        if result.ok:
            return True, ""
        else:
            # Concatenate error messages if any
            error_msg = "; ".join(result.errors) if result.errors else "Unknown validation error"
            return False, error_msg

    except Exception as e:
        return False, str(e)


# The rule_dict :

# {'format': 'sigma', 'title': 'q', 'license': '0BSD', 'description': 'No description for the rule', 'source': 'admin admin',
#   'version': '1.0', 'to_string': 'q', 'cve_id': 'None', 'author': 'admin', 'creation_date': (datetime.datetime(2025, 9, 10, 12, 9, 47, 2389, tzinfo=datetime.timezone.utc),)}


