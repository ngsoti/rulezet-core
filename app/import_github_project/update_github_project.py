# #---------------------------------------------------------------------------------------------------Update--------------------------------------------------------------------------------------------------------------#


# from app.import_github_project.import_github_sigma import find_sigma_rule_by_title
# from app.import_github_project.import_github_suricata import find_suricata_rule_by_title
# from app.import_github_project.import_github_yara import find_yara_rule_by_title, get_yara_files_from_repo
# from app.import_github_project.untils_import import clone_or_access_repo, delete_existing_repo_folder, git_pull_repo
# from ..rule import rule_core as RuleModel



# def Check_for_rule_updates(rule_id):
#     """Check if a rule has been updated in its original GitHub repository."""
    
#     rule = RuleModel.get_rule(rule_id)
#     if not rule:
#         return {"message": f"No rule found with the id {rule_id}", "success": False}, False, None
    
#     repo_dir, exists = clone_or_access_repo(rule.source)
#     if not exists:
#         return {"message": "Repository could not be accessed", "success": False}, False, None
    

#     new_rule_str = None
#     try:
#         if rule.format.lower() == "yara":
#             new_rule_str = find_yara_rule_by_title(repo_dir, rule.title)
#         elif rule.format.lower() == "sigma":
#             new_rule_str = find_sigma_rule_by_title(repo_dir, rule.title)
#         elif rule.format.lower() == "suricata":
#             new_rule_str = find_suricata_rule_by_title(repo_dir, rule.title)
#         # elif rule.format.lower() == "zeek":
#         #     print("Searching ZEEK rule by title in repository...")
#         #     new_rule_str = find_zeek_rule_by_title(repo_dir, rule.title)
#         else:
#             return {"message": f"Unsupported rule format: {rule.format}", "success": False}, False, None
#     except Exception as e:
#         return {"message": f"Error during parsing: {str(e)}", "success": False}, False, None

#     if new_rule_str is None:
#         return {"message": "Rule not found in the GitHub repository", "success": False, "new_content": None}, False, None
    
#     if rule.to_string.strip() != new_rule_str.strip():
#         return {"message": "Update found for this rule", "success": True, "new_content": new_rule_str.strip()}, True, new_rule_str.strip()
#     else:
#         return {"message": "No change detected for this rule", "success": True, "new_content": None}, True, None

from app.rule_type.rule_formats.elastic_format import ElasticDetectionRule
from app.rule_type.rule_formats.yara_format import YaraRule
from app.rule_type.rule_formats.sigma_format import SigmaRule
from app.rule_type.rule_formats.suricata_format import SuricataRule
from app.rule_type.rule_formats.zeek_format import ZeekRule
from app.rule_type.rule_formats.crs_format import CRSRule
from app.rule_type.rule_formats.nova_format import NovaRule
from app.import_github_project.untils_import import clone_or_access_repo, git_pull_repo
from ..rule import rule_core as RuleModel

FORMAT_CLASSES = {
    "yara": YaraRule,
    "sigma": SigmaRule,
    "suricata": SuricataRule,
    "zeek": ZeekRule,
    "crs": CRSRule,
    "nova": NovaRule,
    "elastic": ElasticDetectionRule
}


def Check_for_rule_updates(rule_id: int):
    """
    Check if a rule has been updated in its original GitHub repository
    using the RuleType classes.
    """
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return {"message": f"No rule found with the id {rule_id}", "success": False}, False, None

    repo_dir, exists = clone_or_access_repo(rule.source)
    if not exists:
        return {"message": "Repository could not be accessed", "success": False}, False, None


    git_pull_repo(repo_dir)

    fmt = rule.format.lower()
    if fmt not in FORMAT_CLASSES:
        return {"message": f"Unsupported rule format: {rule.format}", "success": False}, False, None

    rule_class = FORMAT_CLASSES[fmt]()
    found_rule , success = rule_class.find_rule_in_repo(repo_dir, rule_id)

    if not success:
        return {"message": found_rule, "success": False}, False, None

    if rule.to_string != found_rule.strip():
        return {
            "message": "Update found for this rule",
            "success": True,
            "new_content": found_rule.strip()
        }, True, found_rule.strip()
    else:
        return {
            "message": "No change detected for this rule",
            "success": True,
            "new_content": None
        }, True, None
