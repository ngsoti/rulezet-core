from app.import_github_project.untils_import import clone_or_access_repo, git_pull_repo
from app.import_github_project.update_github_project import Check_for_rule_updates
from app.rule import rule_core as RuleModel
import asyncio
import schedule
import time

APP = None

DAY_MAP = {
    "monday": schedule.every().monday,
    "tuesday": schedule.every().tuesday,
    "wednesday": schedule.every().wednesday,
    "thursday": schedule.every().thursday,
    "friday": schedule.every().friday,
    "saturday": schedule.every().saturday,
    "sunday": schedule.every().sunday,
}

# ✅ Dictionnaire global pour stocker les jobs planifiés par ID
SCHEDULED_JOBS = {}
DISABLED_SCHEDULES = set()


def set_app(flask_app):
    global APP
    APP = flask_app


def add_schedule_job(schedule_id: int, days: list[str], hour: int, minute: int):
    time_str = f"{hour:02d}:{minute:02d}"
    jobs = []

    for day in days:
        day_lower = day.lower()
        if day_lower in DAY_MAP:
            job = DAY_MAP[day_lower].at(time_str).do(async_job_wrapper, schedule_id)
            jobs.append(job)

    # Sauvegarde les jobs dans le dictionnaire
    SCHEDULED_JOBS[schedule_id] = jobs
    print(f"[🗓️] Schedule ajouté pour ID {schedule_id} à {time_str} les jours : {days}")


def remove_schedule_job(schedule_id: int):
    jobs = SCHEDULED_JOBS.pop(schedule_id, None)
    if jobs:
        for job in jobs:
            schedule.cancel_job(job)
        print(f"[🗑️] Jobs pour Schedule ID {schedule_id} supprimés.")
    else:
        print(f"[⚠️] Aucun job à supprimer pour Schedule ID {schedule_id}")


def modify_schedule_job(schedule_id: int, days: list[str], hour: int, minute: int):
    remove_schedule_job(schedule_id)
    add_schedule_job(schedule_id, days, hour, minute)
    print(f"[♻️] Schedule modifié pour ID {schedule_id}.")


def disable_schedule_job(schedule_id: int):
    jobs = SCHEDULED_JOBS.get(schedule_id, [])
    for job in jobs:
        schedule.cancel_job(job)
    DISABLED_SCHEDULES.add(schedule_id)
    print(f"[🚫] Schedule ID {schedule_id} désactivé.")


def enable_schedule_job(schedule_id: int, days: list[str], hour: int, minute: int):
    if schedule_id in DISABLED_SCHEDULES:
        DISABLED_SCHEDULES.remove(schedule_id)
        add_schedule_job(schedule_id, days, hour, minute)
        print(f"[▶️] Schedule ID {schedule_id} réactivé.")


def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)


def async_job_wrapper(schedule_id):
    asyncio.run(Check_for_rule_updates_async(schedule_id))


async def Check_for_rule_updates_async(schedule_id):
    if APP is None:
        return

    with APP.app_context():
        rule_items = RuleModel.get_rules_for_schedule(schedule_id)
        results = []

        sources = RuleModel.get_sources_from_titles_rule(rule_items)

        for source in sources:
            repo_dir, exists = clone_or_access_repo(source)
            if exists:
                git_pull_repo(repo_dir)

        for item in rule_items:
            rule_id = item.id
            title = item.title or "Unknown Title"

            message_dict, success, new_rule_content = Check_for_rule_updates(rule_id)
            rule = RuleModel.get_rule(rule_id)

            if success and new_rule_content:
                result = {
                    "id": rule_id,
                    "title": title,
                    "success": success,
                    "message": message_dict.get("message", "No message"),
                    "new_content": new_rule_content,
                    "old_content": rule.to_string if rule else "Error to charge the rule",
                    "schedule_id": schedule_id
                }

                history_id = RuleModel.create_rule_history(result)
                result["history_id"] = history_id if history_id is not None else None

                results.append(result)

        return results



# from app.import_github_project.untils_import import clone_or_access_repo, git_pull_repo
# from app.import_github_project.update_github_project import Check_for_rule_updates
# from app.rule import rule_core as RuleModel
# import asyncio
# import schedule
# import time

# APP = None

# DAY_MAP = {
#     "monday": schedule.every().monday,
#     "tuesday": schedule.every().tuesday,
#     "wednesday": schedule.every().wednesday,
#     "thursday": schedule.every().thursday,
#     "friday": schedule.every().friday,
#     "saturday": schedule.every().saturday,
#     "sunday": schedule.every().sunday,
# }

# def set_app(flask_app):
#     global APP
#     APP = flask_app

# def add_schedule_job(schedule_id: int, days: list[str], hour: int, minute: int):
#     time_str = f"{hour:02d}:{minute:02d}"

#     for day in days:
#         day_lower = day.lower()
#         if day_lower in DAY_MAP:
#             DAY_MAP[day_lower].at(time_str).do(async_job_wrapper, schedule_id)

# def run_scheduler():
#     while True:
#         schedule.run_pending()
#         time.sleep(1)

# def async_job_wrapper(schedule_id):
#     asyncio.run(Check_for_rule_updates_async(schedule_id))

# async def Check_for_rule_updates_async(schedule_id):
#     if APP is None:
#         return

#     with APP.app_context():
#         rule_items = RuleModel.get_rules_for_schedule(schedule_id)
#         results = []

#         sources = RuleModel.get_sources_from_titles_rule(rule_items)

#         for source in sources:
#             repo_dir, exists = clone_or_access_repo(source)
#             if exists:
#                 git_pull_repo(repo_dir)


#         for item in rule_items:
#             rule_id = item.id
#             title = item.title or "Unknown Title"

#             message_dict, success, new_rule_content = Check_for_rule_updates(rule_id)
#             rule = RuleModel.get_rule(rule_id)

#             if success and new_rule_content:

#                 result = {
#                     "id": rule_id,
#                     "title": title,
#                     "success": success,
#                     "message": message_dict.get("message", "No message"),
#                     "new_content": new_rule_content,
#                     "old_content": rule.to_string if rule else "Error to charge the rule",
#                     "schedule_id" : schedule_id if schedule_id else None
#                 }

#                 history_id = RuleModel.create_rule_history(result)

#                 if history_id is None:
#                     result["history_id"] = None
#                 else:
#                     result["history_id"] = history_id

#                 results.append(result)

#         return results


