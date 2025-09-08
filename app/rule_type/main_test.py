import os
from typing import List, Dict, Any
from app.rule_type.rule_formats.sigma_format import SigmaRule
from app.rule_type.rule_formats.suricata_format import SuricataRule
from app.rule_type.rule_formats.yara_format import YaraRule
from ..rule import rule_core as RuleModel
from flask_login import current_user

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


    ### --- Extract each rule by format --- ###
     
    # Process YARA rules
    for filepath in yara_files:
        rules = yara_rule.extract_rules_from_file(filepath)
        for rule_text in rules:
            try:
                # Validate
                validation_result  = yara_rule.validate(rule_text)
                # Parse metadata
                metadata = yara_rule.parse_metadata(rule_text , info , validation_result)
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
                        rule_type="YARA",
                        error=validation_result.errors,
                    )

                    bad_rules += 1
                    
            except Exception as e:
                RuleModel.save_invalid_rule(
                    form_dict=metadata if "metadata" in locals() else {},
                    to_string=rule_text,
                    rule_type="YARA",
                    error=f"Unexpected parsing error: {e}",
                )
                bad_rules += 1

     # Process Sigma rules
    for filepath in sigma_files:
        rules = sigma_rule.extract_rules_from_file(filepath)
        for rule_text in rules:
            try:
                validation_result = sigma_rule.validate(rule_text)
                metadata = sigma_rule.parse_metadata(rule_text, info, default_license=info.get("license"))

                result_dict = {
                    "validation": {
                        "ok": validation_result.ok,
                        "errors": validation_result.errors,
                        "warnings": validation_result.warnings,
                    },
                    "rule": metadata,
                    "raw_rule": rule_text,
                    "file": filepath,
                }

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
                        rule_type="SIGMA",
                        error=validation_result.errors,
                    )
                    bad_rules += 1

            except Exception as e:
                RuleModel.save_invalid_rule(
                    form_dict=metadata if "metadata" in locals() else {},
                    to_string=rule_text,
                    rule_type="SIGMA",
                    error=f"Unexpected parsing error: {e}",
                )
                bad_rules += 1

     # Process Suricata rules
    for filepath in suricata_files:
        rules = suricata_rule.extract_rules_from_file(filepath)
        for rule_text in rules:
            try:
                validation_result = suricata_rule.validate(rule_text)
                metadata = suricata_rule.parse_metadata(rule_text, info, default_license=info.get("license"))

                result_dict = {
                    "validation": {
                        "ok": validation_result.ok,
                        "errors": validation_result.errors,
                        "warnings": validation_result.warnings,
                    },
                    "rule": metadata,
                    "raw_rule": rule_text,
                    "file": filepath,
                }

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
                        rule_type="SURICATA",
                        error=validation_result.errors,
                    )
                    bad_rules += 1

            except Exception as e:
                RuleModel.save_invalid_rule(
                    form_dict=metadata if "metadata" in locals() else {},
                    to_string=rule_text,
                    rule_type="SURICATA",
                    error=f"Unexpected parsing error: {e}",
                )
                bad_rules += 1

    return bad_rules, imported, skipped