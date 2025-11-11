import datetime
import json
from queue import Queue
from threading import Thread
from typing import Optional
from uuid import uuid4

from flask import current_app
from flask_login import current_user
from app import ThreadLocalSession
from ... import db
from ...db_class.db import NewRule, RuleStatus, UpdateResult, User
from ...rule import rule_core as RuleModel
from ...rule.rule_core import Rule as RuleDB

from app.rule_format.abstract_rule_type.rule_type_abstract import RuleType, load_all_rule_formats
from app.rule_format.utils_format.utils_import_update import (
    clone_or_access_repo,
    delete_existing_repo_folder,
    git_pull_repo
)

sessions = []


class Update_classs:
    """
    Threaded class to manage large batch rule updates
    across multiple repositories or selected rules.
    """

    def __init__(self, repo_sources, user: User, info: dict, mode: str = "by_rule") -> None:
        self.update_result_id = None
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

        self.db_update = UpdateResult(
            uuid=self.uuid,
            user_id=self.current_user.id,
            mode=self.mode,
            info=json.dumps(self.info),
            repo_sources=json.dumps(self.repo_sources),
            thread_count=self.thread_count,
            query_date=self.query_date,
        )
        db.session.add(self.db_update)
        db.session.commit()
        self.update_result_id = self.db_update.id
        print(f"[INIT] UpdateResult ID = {self.update_result_id}")


    # ------------------ MAIN METHODS ------------------

    def start(self):
        print("[START] Preparing jobs for update...")
        cp = 0

        if self.mode == "by_url":
            print("[MODE] by_url")
            for url in self.repo_sources:
                repo_dir, exists = clone_or_access_repo(url)
                if not exists:
                    continue
                git_pull_repo(repo_dir)
                rule_items = RuleModel.get_all_rule_by_url_github(url)
                self.total += len(rule_items)

                for rule in rule_items:
                    cp += 1
                    self.jobs.put((cp, repo_dir, rule.id))
                load_all_rule_formats()

        else:
            print("[MODE] by_rule")
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

        for _ in range(self.thread_count):
            worker = Thread(target=self.process, args=[current_app._get_current_object(), current_user._get_current_object()])
            worker.daemon = True
            worker.start()
            self.threads.append(worker)

        

    def status(self):
        if self.jobs.empty():
            self.stop()
        remaining = max(self.jobs.qsize(), len(self.threads))
        complete = self.total - remaining
        print("ahhhhh")
        return {
            "id": self.uuid,
            "total": self.total,
            "complete": complete,
            "remaining": remaining,
            "stopped": self.stopped,
            "found": self.found,
            "updated": self.updated,
            "skipped": self.skipped,
            "not_found": self.not_found,
            "bad_rules": self.bad_rules,
            "total": self.total
        }

    def stop(self):
        self.jobs.queue.clear()
        for i, worker in enumerate(self.threads):
            worker.join()  # attendre tous les threads
        self.threads.clear()

        print("############################################################")
        self.save_info()
        print("*******************************************")
        if self in sessions:
            sessions.remove(self)

        delete_existing_repo_folder("Rules_Github")


    # ------------------ WORKER PROCESS ------------------

    def process(self, loc_app, user: User):
        print("[THREAD] Worker started")
        
        with loc_app.app_context():
            from sqlalchemy.orm import scoped_session, sessionmaker
            Session = scoped_session(sessionmaker(bind=db.engine))
            session = Session()

            try:
                while not self.jobs.empty():
                    _, repo_dir, rule_id = self.jobs.get()
                    print(f"[THREAD] Processing Rule ID {rule_id}...")

                    # Récupération de la règle dans cette session
                    rule = session.get(RuleDB, rule_id)
                    if not rule:
                        print(f"[THREAD] ERROR: Rule {rule_id} not found in DB")
                        self.bad_rules += 1
                        self.jobs.task_done()
                        continue

                    message_dict, success, new_rule_content = Check_for_rule_updates(rule_id, repo_dir)

                    if not success:
                        print(f"[THREAD] Rule {rule_id} not found in repo")
                        self.not_found += 1
                    elif new_rule_content:
                        print(f"[THREAD] Rule {rule_id} update found")
                        self.updated += 1
                        self.found += 1
                    else:
                        print(f"[THREAD] Rule {rule_id} no changes detected")
                        self.found += 1

                    # Créer status pour cette mise à jour
                    rule_status = RuleStatus(
                        update_result_id=self.update_result_id,
                        name_rule=rule.title,
                        rule_id=str(rule_id),
                        message=message_dict.get("message", ""),
                        found=success,
                        update_available=bool(new_rule_content),
                        rule_syntax_valid=True,
                        error=not success
                    )
                    session.add(rule_status)

                    if success and new_rule_content:
                        history_id = RuleModel.create_rule_history({
                            "id": rule_id,
                            "title": rule.title,
                            "success": success,
                            "message": message_dict.get("message", ""),
                            "new_content": new_rule_content,
                            "old_content": rule.to_string
                        })
                        rule_status.history_id = history_id

                    try:
                        session.commit()
                    except Exception as e:
                        print(f"[THREAD] DB commit failed for Rule {rule_id}: {e}")
                        session.rollback()

                    self.jobs.task_done()
            finally:
                session.close()
                Session.remove()  # Important pour scoped_session



    # ------------------ SAVE TO DATABASE ------------------

    def save_info(self):
        self.db_update.not_found = self.not_found
        self.db_update.found = self.found
        self.db_update.updated = self.updated
        self.db_update.skipped = self.skipped
        self.db_update.total = self.total
        db.session.commit()
        return self.db_update


# ------------------ GENERIC UPDATE CHECKER ------------------

def Check_for_rule_updates(rule_id: int, repo_dir: str):
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        print(f"[CHECK] Rule ID {rule_id} not found locally")
        return {"message": f"No rule found with ID {rule_id}", "success": False}, False, None

    print(f"[CHECK] Loaded rule '{rule.title}' with format '{rule.format}'")

    rule_format = (rule.format or "").lower()
    rule_class: Optional[RuleType] = None
    for subclass in RuleType.__subclasses__():
        instance = subclass()
        if instance.format.lower() == rule_format:
            rule_class = instance
            break

    if not rule_class:
        print(f"[CHECK] No handler for format '{rule.format}'")
        return {"message": f"No handler for format: {rule.format}", "success": False}, False, None

    try:
        found_rule, success = rule_class.find_rule_in_repo(repo_dir, rule_id)
    except Exception as e:
        print(f"[CHECK] Exception scanning repo: {e}")
        return {"message": f"Error scanning repo: {e}", "success": False}, False, None

    if not success:
        print(f"[CHECK] Rule {rule_id} not found in repo")
        return {"message": f"Rule not found in repo: {found_rule}", "success": False}, False, None

    validation_result = rule_class.validate(found_rule)

    if rule.to_string != validation_result.normalized_content:
        if not validation_result.ok:
            print(f"[CHECK] Rule {rule_id} update invalid: {validation_result.errors}")
            return {
                "message": f"Update found but invalid: {validation_result.errors}",
                "success": True,
                "new_content": validation_result.normalized_content
            }, True, validation_result.normalized_content
        else:
            print(f"[CHECK] Rule {rule_id} update valid")
            return {"message": "Update found for this rule.", "success": True, "new_content": validation_result.normalized_content}, True, validation_result.normalized_content
    else:
        print(f"[CHECK] Rule {rule_id} unchanged")
        return {"message": "No change detected.", "success": True, "new_content": None}, True, None