#---------------------------------------------------------------------------------------------------Update--------------------------------------------------------------------------------------------------------------#


from app.import_github_project.import_github_sigma import find_sigma_rule_by_title
from app.import_github_project.import_github_suricata import find_suricata_rule_by_title
from app.import_github_project.import_github_yara import find_yara_rule_by_title, get_yara_files_from_repo
from app.import_github_project.untils_import import clone_or_access_repo, delete_existing_repo_folder, git_pull_repo
from ..rule import rule_core as RuleModel



def Check_for_rule_updates(rule_id):
    """Check if a rule has been updated in its original GitHub repository."""
    
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        
        return {"message": f"No rule found with the id {rule_id}", "success": False}, False, None
    



    repo_dir, exists = clone_or_access_repo(rule.source)
    if not exists:
        return {"message": "Repository could not be accessed", "success": False}, False, None
    

    new_rule_str = None
    try:
        if rule.format.lower() == "yara":
            new_rule_str = find_yara_rule_by_title(repo_dir, rule.title)
        elif rule.format.lower() == "sigma":
            new_rule_str = find_sigma_rule_by_title(repo_dir, rule.title)
        elif rule.format.lower() == "suricata":
            new_rule_str = find_suricata_rule_by_title(repo_dir, rule.title)
        # elif rule.format.lower() == "zeek":
        #     print("Searching ZEEK rule by title in repository...")
        #     new_rule_str = find_zeek_rule_by_title(repo_dir, rule.title)
        else:
            return {"message": f"Unsupported rule format: {rule.format}", "success": False}, False, None
    except Exception as e:
        return {"message": f"Error during parsing: {str(e)}", "success": False}, False, None

    if new_rule_str is None:
        return {"message": "Rule not found in the GitHub repository", "success": False, "new_content": None}, False, None
    
    if rule.to_string.strip() != new_rule_str.strip():
        return {"message": "Update found for this rule", "success": True, "new_content": new_rule_str.strip()}, True, new_rule_str.strip()
    else:
        return {"message": "No change detected for this rule", "success": True, "new_content": None}, True, None




# def Check_for_rule_updates(rule_id):
#     """Check if a rule has been updated in its original GitHub repository."""
    
#     print(f"🔍 Checking updates for rule ID: {rule_id}")
#     rule = RuleModel.get_rule(rule_id)
#     if not rule:
#         print(f"❌ Rule with ID {rule_id} not found in DB.")
#         return {"message": f"No rule found with the id {rule_id}", "success": False}, False, None

#     print(f"📦 Rule found: title='{rule.title}', format='{rule.format}', source='{rule.source}'")

#     repo_dir, exists = clone_or_access_repo(rule.source)
#     if not exists:
#         print("❌ Repository could not be accessed or cloned.")
#         return {"message": "Repository could not be accessed", "success": False}, False, None

#     new_rule_str = None
#     try:
#         print(f"🔎 Looking for rule '{rule.title}' in format '{rule.format.lower()}'")
#         if rule.format.lower() == "yara":
#             new_rule_str = find_yara_rule_by_title(repo_dir, rule.title)
#         elif rule.format.lower() == "sigma":
#             new_rule_str = find_sigma_rule_by_title(repo_dir, rule.title)
#         elif rule.format.lower() == "suricata":
#             print("🌐 Searching SURICATA rule by title in repository...")
#             new_rule_str = find_suricata_rule_by_title(repo_dir, rule.title)
#         else:
#             print(f"⚠️ Unsupported rule format: {rule.format}")
#             return {"message": f"Unsupported rule format: {rule.format}", "success": False}, False, None
#     except Exception as e:
#         print(f"💥 Exception during rule parsing: {str(e)}")
#         return {"message": f"Error during parsing: {str(e)}", "success": False}, False, None

#     if new_rule_str is None:
#         print(f"🔁 Rule '{rule.title}' not found in repo.")
#         return {"message": "Rule not found in the GitHub repository", "success": False, "new_content": None}, False, None

#     if rule.to_string.strip() != new_rule_str.strip():
#         print("✅ Update detected for the rule.")
#         return {"message": "Update found for this rule", "success": True, "new_content": new_rule_str.strip()}, True, new_rule_str.strip()
#     else:
#         print("🔄 No change detected.")
#         return {"message": "No change detected for this rule", "success": True, "new_content": None}, True, None
