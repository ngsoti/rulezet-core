import datetime
import json
from queue import Queue
from threading import Thread
from typing import Optional
from uuid import uuid4

from app.rule_format.abstract_rule_type.rule_type_abstract import RuleType
from app.rule_format.utils_format.utils_import_update import clone_or_access_repo, delete_existing_repo_folder, git_pull_repo




from ... import db
from ...db_class.db import User
from ...db_class.db import ImporterResult
from ...rule import rule_core as RuleModel

from flask import current_app
from flask_login import current_user


sessions = list()


class Update_class:
    """
    Threaded class to manage large batch rule updates
    across multiple repositories or selected rules.
    """

    def __init__(self, repo_sources, user: User, info: dict, mode: str = "by_rule") -> None:
        """
        Args:
            repo_sources (list): list of rule IDs (mode='by_rule') or URLs (mode='by_url')
            user (User): current logged user object
            info (dict): metadata/context about this update operation
            mode (str): 'by_rule' or 'by_url'
        """
        self.uuid = str(uuid4())
        self.thread_count = 4
        self.jobs = Queue(maxsize=0)
        self.threads = []
        self.stopped = False

        self.repo_sources = repo_sources

        self.mode = mode
        self.current_user = user
        self.info = info
        self.repo_cache = {}

        # Stats
        self.bad_rules = 0




        self.updated = 0

        self.not_found = 0
        self.found = 0
        self.skipped = 0
        self.total = 0

        self.query_date = datetime.datetime.now(tz=datetime.timezone.utc)

    # ------------------ MAIN METHODS ------------------

    def start(self):
        """Start multi-threaded update workers"""
        cp = 0

        # Prepare queue items depending on mode
        if self.mode == "by_url":
            for url in self.repo_sources:
                repo_dir, exists = clone_or_access_repo(url)
                if not exists:
                    continue
                git_pull_repo(repo_dir)

                rule_items = RuleModel.get_all_rule_by_url_github(url)
                for rule in rule_items:
                    cp += 1
                    self.jobs.put((cp, repo_dir, rule))
        else:  # by_rule
            sources = RuleModel.get_sources_from_ids(self.repo_sources)
            for src in sources:
                repo_dir, exists = clone_or_access_repo(src)
                if exists:
                    git_pull_repo(repo_dir)
                    self.repo_cache[src] = repo_dir

            for rule_id in self.repo_sources:
                rule = RuleModel.get_rule(rule_id)
                if not rule:
                    continue
                repo_dir = self.repo_cache.get(rule.source)
                cp += 1
                self.jobs.put((cp, repo_dir, rule))

        self.total = cp

        # Spawn workers
        for _ in range(self.thread_count):
            worker = Thread(
                target=self.process,
                args=[current_app._get_current_object(), current_user._get_current_object()]
            )
            worker.daemon = True
            worker.start()
            self.threads.append(worker)

    def status(self):
        """Return current queue status"""
        if self.jobs.empty():
            self.stop()

        total = self.total
        remaining = max(self.jobs.qsize(), len(self.threads))
        complete = total - remaining

        return {
            "id": self.uuid,
            "total": total,
            "complete": complete,
            "remaining": remaining,
            "stopped": self.stopped,
            "found": self.found,
            "updated": self.updated,
            "skipped": self.skipped,
            "not_found": self.not_found,
            "bad_rules": self.bad_rules,
        }

    def stop(self):
        """Stop all worker threads and cleanup"""
        self.jobs.queue.clear()
        for worker in self.threads:
            worker.join(3.5)
        self.threads.clear()
        self.save_info()
        sessions.remove(self)
        delete_existing_repo_folder("Rules_Github")
        del self

    # ------------------ WORKER PROCESS ------------------

    def process(self, loc_app, user: User):
        """Worker thread logic"""
        with loc_app.app_context():
            while not self.jobs.empty():
                work = self.jobs.get()

                _, repo_dir, rule = work

                # Merge rule et user dans la session du thread
                rule = db.session.merge(rule)
                user = db.session.merge(user)

                rule_id = rule.id
                title = rule.title

                message_dict, success, new_rule_content = Check_for_rule_updates(rule_id, repo_dir)
                db_rule = RuleModel.get_rule(rule_id)

                if success and new_rule_content:
                    self.updated += 1
                    self.found += 1

                    result = {
                        "id": rule_id,
                        "title": title,
                        "success": success,
                        "message": message_dict.get("message", "No message"),
                        "new_content": new_rule_content,
                        "old_content": db_rule.to_string if db_rule else "Error loading rule"
                    }

                    history_id = RuleModel.create_rule_history(result)
                    if history_id:
                        result["history_id"] = history_id
                else:
                    if not success:
                        self.bad_rules += 1
                    else:
                        self.not_found += 1

                self.jobs.task_done()
        return True


    # ------------------ SAVE TO DATABASE ------------------

    def save_info(self):
        """Save operation info to DB"""
        s = ImporterResult(
            uuid=self.uuid,
            info=json.dumps(self.info),
            bad_rules=self.bad_rules,
            imported=self.updated,  # reused field
            skipped=self.skipped,
            total=self.total,
            query_date=self.query_date,
            user_id=self.current_user.id
        )
        db.session.add(s)
        db.session.commit()
        return s


# ------------------ GENERIC UPDATE CHECKER ------------------

def Check_for_rule_updates(rule_id: int, repo_dir: str):
    """
    Generic rule update checker.

    Dynamically finds the right RuleType subclass based on the rule format,
    extracts the rule from the repo, validates it, and compares it with the current version.
    """

    rule = RuleModel.get_rule(rule_id)

    if not rule:
        return {"message": f"No rule found with ID {rule_id}", "success": False}, False, None

    # Find the appropriate rule handler dynamically
    rule_format = (rule.format or "").lower()
    rule_class: Optional[RuleType] = None

    for subclass in RuleType.__subclasses__():
        instance = subclass()
        if instance.format.lower() == rule_format:
            rule_class = instance
            break

    if not rule_class:
        return {
            "message": f"No handler found for format: {rule.format}",
            "success": False
        }, False, None

    # Try to locate and extract the updated version in repo
    try:
        found_rule, success = rule_class.find_rule_in_repo(repo_dir, rule_id)
    except Exception as e:
        return {
            "message": f"Error while scanning repository: {e}",
            "success": False
        }, False, None

    if not success:
        return {"message": found_rule, "success": False}, False, None

    # First, validate the found rule
    validation_result = rule_class.validate(found_rule)

    # Then, compare content difference with current rule
    if rule.to_string != validation_result.normalized_content:
        if not validation_result.ok:
            return {
                "message": f"Update found but invalid: {validation_result.errors}",
                "success": True,
                "new_content": validation_result.normalized_content
            }, True, validation_result.normalized_content
        else:
            return {
                "message": "Update found for this rule.",
                "success": True,
                "new_content": validation_result.normalized_content
            }, True, validation_result.normalized_content
    else:
        return {
            "message": "No change detected for this rule.",
            "success": True,
            "new_content": None
        }, True, None




