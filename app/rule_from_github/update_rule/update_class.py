import datetime
import json
import os
from queue import Queue
from threading import Thread, Lock
from typing import Optional, List, Dict, Any
from uuid import uuid4

from flask import current_app
from flask_login import current_user

from app.utils.utils import update_or_clone_repo
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

        # repo_sources[0] is assumed to be the GitHub URL for by_url
        if mode == "by_url":
            self.repo_sources = repo_sources[0]
        else:
            # repo_sources is the list of rule IDs for by_rule
            self.repo_sources = repo_sources

        self.mode = mode
        self.current_user = user
        self.info = info
        self.repo_cache = {}
        self.count_per_format = {}
        self.local_repo_path = None

        # Rule Tracking for Ruleset
        self.rules_to_process: List[Dict[str, Any]] = [] # Rules from Rulezet to be checked against repo

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
            
            self.local_repo_path = repo_dir

            # found all the rule in the repo currently in Rulezet
            rules_listes_github = RuleModel.get_all_rule_by_url_github(self.repo_sources , self.current_user)
            
            if not rules_listes_github:
                print("no rules found in Rulezet")
            
            # Initialize the list of rules we need to check
            self.rules_to_process = [
                {"id": r.id, "title": r.title}
                for r in rules_listes_github
            ]

            total_rule_to_update = len(rules_listes_github)
            print(len(rules_listes_github))
            self.total = total_rule_to_update

            success = git_pull_repo(repo_dir)

            if not success:
                print("Error pulling repo")
                return


            
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
               
            # self.total = cp
        elif self.mode == "by_rule":
            
            # get all the rules from Rulezet with the ids
            rules_list: List[Rule] = Rule.query.filter(Rule.id.in_(self.repo_sources) ).all()
            if not rules_list:
                print("no rules found in Rulezet")
            
            # Group rules by source to minimize cloning/pulling
            rules_by_source: Dict[str, List[Rule]] = {}
            for r in rules_list:
                if r.source:
                    source_url = r.source.strip()
                    if source_url not in rules_by_source:
                        rules_by_source[source_url] = []
                    rules_by_source[source_url].append(r)
                else:
                    print(f"Rule ID {r.id} has no source URL, skipping.")
            
            # Initialize the list of rules we need to check
            self.rules_to_process = [
                {"id": r.id, "title": r.title}
                for r in rules_list
            ]

            cp = 0
            for source_url, rule_list in rules_by_source.items():
                
                try:
                    repo_dir, exists = clone_or_access_repo(source_url)
                    git_pull_repo(repo_dir)
                except Exception as e:
                    print(f"Error cloning or pulling repo {source_url}: {e}, skipping rules in this repo.")
                    continue


                # Enqueue a job for each rule using its Rule ID and repo dir
                for rule_obj in rule_list:
                    
                    # Find the corresponding RuleType class
                    rule_type_instance = None
                    load_all_rule_formats()
                    for RuleClass in RuleType.__subclasses__():
                        if RuleClass().format.lower() == (rule_obj.format or "").lower():
                            rule_type_instance = RuleClass()
                            break
                    
                    if not rule_type_instance:
                        print(f"No RuleType handler found for format: {rule_obj.format} of rule ID {rule_obj.id}, skipping.")
                        continue
                    
                    cp += 1
                    # Job tuple for by_rule: (counter, rule_id, local_repo_path, rule_type_instance, rule_title)

                    self.jobs.put((
                        cp, 
                        rule_obj.id, 
                        repo_dir, 
                        rule_type_instance, 
                        rule_obj.title
                    ))
            
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


    # ------------------ RULE TRACKING ------------------

    def remove_processed_rule(self, rule_name: str):
        """Removes a rule from the to-process list if found in the repo."""
        with self.lock:
            # We check the title/name against the rules_to_process list
            # Note: This is an O(N) operation inside a lock, but safe.
            # A dictionary could improve performance if necessary.
            self.rules_to_process = [
                r for r in self.rules_to_process if r["title"] != rule_name
            ]


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

        # Get rules that were in Rulezet but not processed against the repo
        unprocessed_rules = [r["title"] for r in self.rules_to_process]

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
            "new_rules": [nr.to_json() for nr in self.new_rules_list],
            "unprocessed_rules": unprocessed_rules # ADDED: Rules from Rulezet not found in repo
        }

    # ------------------ STOP ------------------

    def stop(self):
        # Only process remaining jobs if the queue is empty (finished naturally)
        if self.jobs.empty():
            for worker in self.threads:
                worker.join(3.5)
            self.threads.clear()

        # Add rules from Rulezet that were not found in the repository to status list
        with self.lock:
            remaining_rules = self.rules_to_process[:]
            for rule in remaining_rules:
                # Log status for the rule not found in the repository
                self.rule_status_list.append({
                    "update_result_uuid": self.uuid,
                    "name_rule": rule["title"],
                    "rule_id": rule["id"],
                    "message": "Rule from Rulezet not found in the repository.",
                    "found": False,
                    "update_available": False,
                    "rule_syntax_valid": False,
                    "error": True, # Flag as error/not_found for summary purposes
                    "history_id": None # No history created for missing rule
                })
                # Remove it now that it has been handled
                self.rules_to_process.remove(rule)

            # Re-calculate final statistics based on the complete rule_status_list
            self.found = sum(1 for r in self.rule_status_list if r["found"])
            self.updated = sum(1 for r in self.rule_status_list if r["update_available"])
            self.not_found = sum(1 for r in self.rule_status_list if r["error"] and not r["found"])
            self.skipped = sum(1 for r in self.rule_status_list if r["found"] and not r["update_available"])

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

                if self.mode == "by_url":

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
                            print("No name or title found in rule:", work[2])
                            continue

                        # verify if the rule is correct or not
                        existing_rule = RuleModel.get_rule_by_title(name)

                        if validation_result.ok:
                            # Case 1: Rule is VALID (either an update or a completely new rule)
                            
                            if existing_rule:
                                # Sub-case 1.1: Rule EXISTS (Attempt Update and History Creation)
                                
                                # Use self.local_repo_path instead of self.repo_sources
                                user = db.session.merge(user)
                                if existing_rule.user_id == user.id or user.is_admin():


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
                                        # message_dict["history_id"] = history_id # Not strictly necessary if history_id is used below

                                    msg = message_dict.get("message", "") or ""
                                    syntax_valid = not ("Update found but invalid:" in msg)

                                    # --- update status ---
                                    with self.lock:
                                        self.rule_status_list.append({
                                            "update_result_uuid": self.uuid,
                                            "name_rule": existing_rule.title,
                                            "rule_id": existing_rule.id,
                                            "message": message_dict.get("message", ""),
                                            # success from Check_for_rule_updates means it was FOUND and processed
                                            "found": success,
                                            "update_available": bool(new_rule_content),
                                            "rule_syntax_valid": syntax_valid,
                                            "error": not success,
                                            "history_id": history_id # history_id is set here
                                        })
                               
                                # Remove rule from the list of rules to process (because it was found in the repo)
                                self.remove_processed_rule(existing_rule.title)

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
                                
                                # Safety: Remove rule from the list of rules to process if it somehow matched a title 
                                self.remove_processed_rule(name)


                        else:
                            # Case 2: Rule is INVALID (Log as Update Status OR New Invalid Rule)

                            # Extract errors and warnings for the message
                            error_details = []
                            if validation_result.errors:
                                error_details.append(f"Errors: {validation_result.errors}")
                            if validation_result.warnings:
                                error_details.append(f"Warnings: {validation_result.warnings}")
                            
                            full_error_message = "Validation Failed. " + " | ".join(error_details)
                                
                            if existing_rule:
                                # Case 2.1: Rule EXISTS but the content in the repo is INVALID (Log as Invalid Update Status AND Create History)
                                user = db.session.merge(user)
                                if existing_rule.user_id == user.id or user.is_admin():



                                    # --- create history for the failed update ---
                                    history_id = RuleModel.create_rule_history({
                                        "id": existing_rule.id,
                                        "title": existing_rule.title,
                                        # Update failed because the new content is invalid
                                        "success": False, 
                                        "message": "rejected",
                                        "new_content": rule_text,
                                        "old_content": existing_rule.to_string
                                    })

                                    # Log status for the failed update
                                    with self.lock:
                                        self.rule_status_list.append({
                                            "update_result_uuid": self.uuid,
                                            "name_rule": existing_rule.title,
                                            "rule_id": existing_rule.id,
                                            "message": f"Update found but invalid: {full_error_message}",
                                            "found": True,
                                            "update_available": True, # Update exists, but we don't apply it
                                            "rule_syntax_valid": False,
                                            "error": True, # Error because the update failed validation
                                            "history_id": history_id # History ID is recorded
                                        })

                        
                                # Remove rule from the list of rules to process (because it was found in the repo)
                                self.remove_processed_rule(existing_rule.title)
                            
                            else:
                                # Case 2.2: Rule does NOT EXIST (Log as New Invalid Rule for Correction)
                                
                                # Create the NewRule object for the bad rule
                                new_rule_obj = NewRule(
                                    uuid=str(uuid4()),
                                    update_result_id=None,  # filled later in save_info()
                                    date=datetime.datetime.now(tz=datetime.timezone.utc),
                                    name_rule=name,
                                    rule_content=rule_text,
                                    # Use the detailed error message
                                    message=full_error_message,
                                    rule_syntax_valid=False, # Key change: Syntax is invalid
                                    error=True,             # Key change: There is an error
                                    accept=False,
                                    # Ensure 'format' is set if available
                                    format=metadata.get("format") 
                                )
                                self.new_rules_list.append(new_rule_obj)
                                
                                # Remove rule from the list of rules to process (as it was found in the repo but is invalid)
                                self.remove_processed_rule(name)
                else:
                    # by rule: work = (cp, rule_id, repo_dir, rule_type_instance, rule_title)
                    
                    rule_id = work[1] 
                    repo_dir = work[2]
                    rule_instance = work[3]
                    rule_title = work[4]

                    # 1. Check for rule updates using the specialized function
                    # Check_for_rule_updates expects rule ID (int) and repo dir (str)
                    message_dict, success, new_rule_content = Check_for_rule_updates(rule_id, repo_dir)
                    
                    # 2. Handle results and update status
                    
                    existing_rule = RuleModel.get_rule(rule_id)
                    if not existing_rule:
                        self.jobs.task_done()
                        continue
                        
                    msg = message_dict.get("message", "") or ""
                    # syntax_valid means the rule was found (success=True) AND the update was not invalid
                    syntax_valid = success and not ("Update found but invalid:" in msg)
                    
                    # Try to retrieve the raw rule content from the repo for history if found
                    rule_text_in_repo = None
                    if success:
                         try:
                            # find_rule_in_repo is a method of the RuleType instance (rule_instance)
                            # it needs the repo_dir and the rule_id to locate the file content
                            found_rule_text, find_success = rule_instance.find_rule_in_repo(repo_dir, existing_rule.id)
                            if find_success:
                                rule_text_in_repo = found_rule_text
                         except Exception as e:
                             print(f"Error retrieving raw rule text for history, ID {rule_id}: {e}")
                    
                    # --- Create History (if an update or failure to find in repo) ---
                    history_id = None
                    if new_rule_content or not syntax_valid or not success:
                        
                        # Use new valid content, or the invalid content if found, or the old content as fallback
                        new_content_for_history = new_rule_content or rule_text_in_repo or existing_rule.to_string

                        history_id = RuleModel.create_rule_history({
                            "id": existing_rule.id,
                            "title": existing_rule.title,
                            # Success only if valid content was found AND applied
                            "success": success and bool(new_rule_content),
                            "message": message_dict.get("message", ""),
                            "new_content": new_content_for_history,
                            "old_content": existing_rule.to_string
                        })

                    # --- Update Status ---
                    with self.lock:
                        self.rule_status_list.append({
                            "update_result_uuid": self.uuid,
                            "name_rule": existing_rule.title,
                            "rule_id": existing_rule.id,
                            "message": message_dict.get("message", ""),
                            # success from Check_for_rule_updates means it was FOUND and processed
                            "found": success,
                            # Update available if we have new valid content OR if the message indicates an invalid update was found
                            "update_available": bool(new_rule_content) or ("Update found but invalid:" in msg),
                            "rule_syntax_valid": syntax_valid,
                            "error": not success or not syntax_valid,
                            "history_id": history_id
                        })

                    self.remove_processed_rule(existing_rule.title)
                        

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
                # Pass history_id to RuleStatus creation
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

    # verify if there is  alredy a history for this rule from a previous update (just the manuel submit not the github one)
    # if there is a history made by a pull request, we don't want to update it again
    #


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
        # NOTE: This finds the rule file in the repo but doesn't do the complex validation/diff yet
        found_rule, success = rule_class.find_rule_in_repo(repo_dir, rule.id)
    except Exception as e:
        return {"message": f"Error scanning repo: {e}", "success": False}, False, None

    if not success:
        return {"message": f"Rule not found in repo: {rule.title}", "success": False}, False, None

    validation = rule_class.validate(found_rule)

    if rule.to_string != validation.normalized_content:

        # There is a change
        if validation.ok:
            # verify if there is already a history for this rule which was made by a pull request (if so, we don't want to update it again)
            # if there is a history made by a pull request, we don't want to update it again
            already_update_by_user = RuleModel.was_last_history_manuel(rule.id)
            if already_update_by_user:
                return {"message": "Already updated by user", "success": True, "new_content": None}, True, None

            # Change is valid, return success
            return (
                {
                    "message": "Update found for this rule.",
                    "success": True,
                    "new_content": validation.normalized_content
                },
                True,
                validation.normalized_content
            )
        else:
            # Change is invalid, return success=True (meaning rule was found) but no content
            # The calling code (Update_class.process) will handle the specific history/status for this failure
            return (
                {
                    "message": f"Update found but invalid: {validation.errors}",
                    "success": True, # Rule was found and diffed
                    "new_content": None # No valid content to apply
                },
                True,
                None # No valid content to return
            )


    return {"message": "No change detected.", "success": True, "new_content": None}, True, None

