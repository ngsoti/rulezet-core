import datetime
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
            #print(f"📆 Scheduled job for schedule_id={schedule_id} on {day_lower} at {time_str}")

    SCHEDULED_JOBS[schedule_id] = jobs


def remove_schedule_job(schedule_id: int):
    jobs = SCHEDULED_JOBS.pop(schedule_id, None)
    if jobs:
        for job in jobs:
            schedule.cancel_job(job)
        #print(f"❌ Removed scheduled job(s) for schedule_id={schedule_id}")


def modify_schedule_job(schedule_id: int, days: list[str], hour: int, minute: int):
    #print(f"🔁 Modifying schedule {schedule_id}")
    remove_schedule_job(schedule_id)
    add_schedule_job(schedule_id, days, hour, minute)


def disable_schedule_job(schedule_id: int):
    jobs = SCHEDULED_JOBS.get(schedule_id, [])
    for job in jobs:
        schedule.cancel_job(job)
    DISABLED_SCHEDULES.add(schedule_id)
    #print(f"⏸️ Disabled schedule {schedule_id}")


def enable_schedule_job(schedule_id: int, days: list[str], hour: int, minute: int):
    if schedule_id in DISABLED_SCHEDULES:
        DISABLED_SCHEDULES.remove(schedule_id)
        add_schedule_job(schedule_id, days, hour, minute)
        #print(f"▶️ Re-enabled schedule {schedule_id}")


def run_scheduler():
    #print("🚀 Scheduler started")
    while True:
        schedule.run_pending()
        time.sleep(1)


def async_job_wrapper(schedule_id):
    #print(f"\n⏱️ Executing scheduled job for schedule_id={schedule_id}")
    asyncio.run(Check_for_rule_updates_async(schedule_id))


async def Check_for_rule_updates_async(schedule_id):
    if APP is None:
        #print("⚠️ No Flask app context set. Skipping.")
        return

    with APP.app_context():
        #print(f"🔍 Fetching rules for schedule {schedule_id}...")
        rule_items = RuleModel.get_rules_for_schedule(schedule_id)
        #print(f"➡️ {len(rule_items)} rule(s) to check.")

        results = []
        sources = RuleModel.get_sources_from_titles_rule(rule_items)
        #print(f"📁 Found {len(sources)} source repo(s) to pull.")

        for source in sources:
            print(f"📦 Handling source: {source}")
            repo_dir, exists = clone_or_access_repo(source)
            if exists:
               # print(f"📥 Pulling latest changes for repo at {repo_dir}")
                git_pull_repo(repo_dir)

        for item in rule_items:
            rule_id = item.id
            title = item.title or "Unknown Title"
            #print(f"\n🔄 Checking update for rule: {title} (ID: {rule_id})")

            message_dict, success, new_rule_content = Check_for_rule_updates(rule_id)
            rule = RuleModel.get_rule(rule_id)

            if success and new_rule_content:
               # print(f"✅ Update found for rule {rule_id} — saving to history...")
                schedule_obj = RuleModel.get_schedule(schedule_id)
                message_base = message_dict.get("message", "No message")
                day = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%A")
                message_suffix = f" (from schedule {schedule_obj.name} at {schedule_obj.hour}:{schedule_obj.minute} [{day}])" if day else ""

                result = {
                    "id": rule_id,
                    "title": title,
                    "success": success,
                    "message": message_base + message_suffix,
                    "new_content": new_rule_content,
                    "old_content": rule.to_string if rule else "Error to charge the rule",
                    "schedule_id": schedule_id
                }

                history_id = RuleModel.create_rule_history(result)
                result["history_id"] = history_id if history_id is not None else None

                #print(f"📝 History created with ID: {history_id}")
                results.append(result)
            # else:
            #     print(f"❌ No update or failed to update rule {rule_id}")

        #print(f"\n📦 Finished schedule {schedule_id} with {len(results)} update(s) applied.\n")
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


