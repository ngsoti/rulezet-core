import schedule
import time

from app.import_github_project.untils_import import clone_or_access_repo, git_pull_repo
from app.import_github_project.update_github_project import Check_for_rule_updates
from ..rule import rule_core as RuleModel


def update_github_rule_auto(schedule_id)-> None:
    """Update GitHub rule for a specific schedule."""
    current_schedule = RuleModel.get_schedule(schedule_id)
    print(f"Updating GitHub rule for : {current_schedule.name}")

    rule_items = RuleModel.get_rules_from_schedule(schedule_id)
    sources = RuleModel.get_sources_from_titles(rule_items)    
    
    for source in sources:
        repo_dir, exists = clone_or_access_repo(source)
        git_pull_repo(repo_dir)
            

    for item in rule_items:
        rule_id = item.get("id")
        title = item.get("title", "Unknown Title")
        message_dict, success, new_rule_content = Check_for_rule_updates(rule_id)
        rule = RuleModel.get_rule(rule_id)
        
        if success and new_rule_content:
            result = {
                "id": rule_id,
                "title": title,
                "success": success,
                "message": message_dict.get("message", "No message"),
                "new_content": new_rule_content,
                "old_content": rule.to_string if rule else "Error to charge the rule"
            }

            history_id = RuleModel.create_rule_history(result)
            if history_id:
                print(f"Rule {rule_id} updated successfully. History ID: {history_id}")
            else:
                print(f"Failed to create history for rule {rule_id}.")

            



schedule.every(30).seconds.do(update_github_rule_auto, schedule_id=1)

# while True:
#     schedule.run_pending()
#     time.sleep(1)