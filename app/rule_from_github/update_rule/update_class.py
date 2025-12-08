import datetime
import json
import os
from queue import Queue
from threading import Thread, Lock
from typing import Optional
from uuid import uuid4

from flask import current_app
from flask_login import current_user
from ... import db

from ...db_class.db import Rule, RuleStatus, UpdateResult, User, NewRule
from ...rule import rule_core as RuleModel
from ...rule.rule_core import Rule as RuleDB

from app.rule_format.abstract_rule_type.rule_type_abstract import RuleType, load_all_rule_formats
from app.rule_format.utils_format.utils_import_update import (
    clone_or_access_repo,
    delete_existing_repo_folder,
    git_pull_repo,
    github_repo_metadata
)

sessions = []


class Update_class:
    """
    Threaded class to manage batch rule updates with thread-safe DB operations.
    """

    def __init__(self, repo_sources, user: User, info: dict, mode: str = "by_rule") -> None:
        self.uuid = str(uuid4())
        self.thread_count = 4
        self.jobs = Queue()
        self.threads = []
        self.stopped = False
        self.lock = Lock()

        # repo_sources[0] is assumed to be the GitHub URL
        self.repo_sources = repo_sources[0]
        self.mode = mode
        self.current_user = user
        self.info = info
        self.repo_cache = {}
        self.count_per_format = {}
        self.local_repo_path = None  # Added for clarity (see recommendation)

        # Stats
        self.bad_rules = 0
        self.updated = 0
        self.not_found = 0
        self.found = 0
        self.skipped = 0
        self.total = 0

        self.query_date = datetime.datetime.now(tz=datetime.timezone.utc)
        self.rule_status_list = []

        # NEW RULE SYSTEM
        self.new_rules_list = []
        self._import_done_for_repo = set()

    # ------------------ MAIN METHODS ------------------

    def start(self):
        cp = 0
        if self.mode == "by_url":
            cp = 0
            repo_dir, exists = clone_or_access_repo(self.repo_sources)
            # Store the local path of the cloned repo
            self.local_repo_path = repo_dir

            git_pull_repo(repo_dir)
            
            if os.path.exists(repo_dir):
                for root, dirs, files in os.walk(repo_dir):
                    dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
                    for file in files:
                        if not file.startswith('.') or not file.startswith('_'):
                            load_all_rule_formats()
                            subclasses = RuleType.__subclasses__()
                            for RuleClass in subclasses:
                                rule_instance = RuleClass()

                                is_file = rule_instance.get_rule_files(file)

                                if not is_file:
                                    continue

                                if is_file:
                                    cp += 1
                                    self.jobs.put((cp, file, os.path.join(root, file), rule_instance))
                                    break
               
            self.total = cp

    
        else:
            self.total = cp

        for _ in range(self.thread_count):
            worker = Thread(
                target=self.process,
                args=[current_app._get_current_object(), current_user._get_current_object()]
            )
            worker.daemon = True
            worker.start()
            self.threads.append(worker)


    # ------------------ STATUS ------------------

    def status(self):
        if self.jobs.empty():
            self.stop()

        remaining = max(self.jobs.qsize(), len(self.threads))
        complete = self.total - remaining

        rules_json = [
            {
                "id": r.get("rule_id"),
                "name": r.get("name_rule"),
                "found": r.get("found"),
                "update_available": r.get("update_available"),
                "rule_syntax_valid": r.get("rule_syntax_valid"),
                "error": r.get("error"),
                "message": r.get("message"),
                "history_id": r.get("history_id")
            }
            for r in self.rule_status_list
        ]

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
            "rules": rules_json,
            "new_rules": [nr.to_json() for nr in self.new_rules_list]
        }

    # ------------------ STOP ------------------

    def stop(self):
        self.jobs.queue.clear()
        for worker in self.threads:
            worker.join(3.5)
        self.threads.clear()

        with self.lock:
            self.found = sum(1 for r in self.rule_status_list if r["found"])
            self.updated = sum(1 for r in self.rule_status_list if r["update_available"])
            self.not_found = sum(1 for r in self.rule_status_list if r["error"])
            self.skipped = sum(1 for r in self.rule_status_list if not r["found"] and not r["error"])

        self.save_info()
        sessions.remove(self)
        delete_existing_repo_folder("app/rule_from_github/Rules_Github")
        del self

    # ------------------ UPDATE PROCESS ------------------
    def process(self, loc_app, user: User):
        """Threaded function for queue processing."""
        while not self.jobs.empty():
            with loc_app.app_context():
                work = self.jobs.get()

                rule_instance = work[3]

                rules = rule_instance.extract_rules_from_file(work[2])
                for rule_text in rules:    
                    # enrich info with filepath
                    enriched_info = {**self.info, "filepath": work[2]}
                    # Validate
                    validation_result  = rule_instance.validate(rule_text)
                    # Parse metadata
                    metadata = rule_instance.parse_metadata(rule_text , enriched_info , validation_result)

                    result_dict = {
                        "validation": {
                            "ok": validation_result.ok,
                            "errors": validation_result.errors,
                            "warnings": validation_result.warnings
                        },
                        "rule": metadata,
                        "raw_rule": rule_text,
                        "file": work[2]
                    }
                    
                    # --- Determine Rule Name ---
                    name = metadata.get("title") or metadata.get("name")
                    if not name:
                        # Skip if a name/title cannot be extracted for logging
                        continue

                    # verify if the rule is correct or not
                    if validation_result.ok:
                        # Case 1: Rule is VALID (either an update or a completely new rule)
                        
                        existing_rule = RuleModel.get_rule_by_title(name)
                        
                        if existing_rule:
                            # Sub-case 1.1: Rule EXISTS (Attempt Update)
                            
                            # Use self.local_repo_path instead of self.repo_sources
                            message_dict, success, new_rule_content = Check_for_rule_updates(existing_rule.id, self.local_repo_path ) 

                            # --- create history if needed ---
                            history_id = None
                            if success and new_rule_content:
                                history_id = RuleModel.create_rule_history({
                                    "id": existing_rule.id,
                                    "title": existing_rule.title,
                                    "success": success,
                                    "message": message_dict.get("message", ""),
                                    "new_content": new_rule_content,
                                    "old_content": existing_rule.to_string
                                })
                                message_dict["history_id"] = history_id

                            msg = message_dict.get("message", "") or ""
                            syntax_valid = not ("Update found but invalid:" in msg)

                            # --- update status ---
                            with self.lock:
                                self.rule_status_list.append({
                                    "update_result_uuid": self.uuid,
                                    "name_rule": existing_rule.title,
                                    "rule_id": existing_rule.id,
                                    "message": message_dict.get("message", ""),
                                    "found": success,
                                    "update_available": bool(new_rule_content),
                                    "rule_syntax_valid": syntax_valid,
                                    "error": not success,
                                    "history_id": history_id
                                })

                        else:
                            # Sub-case 1.2: Rule does NOT EXIST (Log as New Valid Rule)

                            new_rule_obj = NewRule(
                                uuid=str(uuid4()),
                                update_result_id=None,  # filled later in save_info()
                                date=datetime.datetime.now(tz=datetime.timezone.utc),
                                name_rule=name,
                                rule_content=rule_text,
                                message="", # No error message since it's valid
                                rule_syntax_valid=True,
                                error=False,
                                accept=False,
                                # Ensure 'format' is set if available
                                format=metadata.get("format") 
                            )
                            self.new_rules_list.append(new_rule_obj)

                    else:
                        # Case 2: Rule is INVALID (Log as New Invalid Rule for Correction)

                        # Extract errors and warnings for the message
                        error_details = []
                        if validation_result.errors:
                            error_details.append(f"Errors: {validation_result.errors}")
                        if validation_result.warnings:
                            error_details.append(f"Warnings: {validation_result.warnings}")
                            
                        # Create the NewRule object for the bad rule
                        new_rule_obj = NewRule(
                            uuid=str(uuid4()),
                            update_result_id=None,  # filled later in save_info()
                            date=datetime.datetime.now(tz=datetime.timezone.utc),
                            name_rule=name,
                            rule_content=rule_text,
                            # Use the detailed error message
                            message="Validation Failed. " + " | ".join(error_details),
                            rule_syntax_valid=False, # Key change: Syntax is invalid
                            error=True,             # Key change: There is an error
                            accept=False,
                            # Ensure 'format' is set if available
                            format=metadata.get("format") 
                        )
                        self.new_rules_list.append(new_rule_obj)

            self.jobs.task_done()
        return True



    # ------------------ SAVE TO DATABASE ------------------

    def save_info(self):
        extended_info = dict(self.info)


        if self.mode == 'by_url':
            extended_info["github_metadata"] = [
                {"url": self.repo_sources}
            ]

        s = UpdateResult(
            uuid=self.uuid,
            user_id=self.current_user.id,
            mode=self.mode,
            info=json.dumps(extended_info),
            repo_sources=json.dumps(self.repo_sources),
            thread_count=self.thread_count,
            query_date=self.query_date,
            not_found=self.not_found,
            found=self.found,
            updated=self.updated,
            skipped=self.skipped,
            total=self.total
        )
        db.session.add(s)
        db.session.commit()

        # Save rule statuses
        for rs_dict in self.rule_status_list:
            rule_status = RuleStatus(
                update_result_id=s.id,
                **{k: v for k, v in rs_dict.items() if k != "update_result_uuid"}
            )
            db.session.add(rule_status)

        # Save new rules
        for nr in self.new_rules_list:
            nr.update_result_id = s.id
            db.session.add(nr)

        db.session.commit()


# ------------------ RULE UPDATE CHECKER ------------------

def Check_for_rule_updates(rule_id: int, repo_dir: str):
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return {"message": f"No rule found with ID {rule_id}", "success": False}, False, None

    rule_format = (rule.format or "").lower()
    rule_class: Optional[RuleType] = None

    for subclass in RuleType.__subclasses__():
        instance = subclass()
        if instance.format.lower() == rule_format:
            rule_class = instance
            break

    if not rule_class:
        return {"message": f"No handler for format: {rule.format}", "success": False}, False, None

    try:
        found_rule, success = rule_class.find_rule_in_repo(repo_dir, rule_id)
    except Exception as e:
        return {"message": f"Error scanning repo: {e}", "success": False}, False, None

    if not success:
        return {"message": f"Rule not found in repo: {found_rule}", "success": False}, False, None

    validation = rule_class.validate(found_rule)

    if rule.to_string != validation.normalized_content:
        return (
            {
                "message": "Update found for this rule." if validation.ok
                else f"Update found but invalid: {validation.errors}",
                "success": True,
                "new_content": validation.normalized_content
            },
            True,
            validation.normalized_content
        )

    return {"message": "No change detected.", "success": True, "new_content": None}, True, None