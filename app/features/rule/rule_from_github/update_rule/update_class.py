import datetime
import json
import os
from queue import Queue
from threading import Thread, Lock, Event
from typing import Optional, List, Dict, Any
from uuid import uuid4

from flask import current_app

from app import db

from app.core.db_class.db import Rule, RuleStatus, UpdateResult, User, NewRule
from app.features.rule import rule_core as RuleModel


from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import RuleType, load_all_rule_formats
from app.features.rule.rule_format.utils_format.utils_import_update import (
    clone_or_access_repo,
    git_pull_repo,
    github_repo_metadata,
    get_repo_head_sha,
    get_changed_files_between,
    delete_existing_repo_folder,
)

sessions = []


class Update_class:
    """
    Threaded class to manage batch rule updates with thread-safe DB operations.
    """

    def __init__(self, repo_sources, user: User, info: dict, mode: str = "by_rule") -> None:
        self.uuid = str(uuid4())
        self.thread_count = 1
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
        # Unwrap immediately if `user` is a Flask-Login LocalProxy (existing
        # call sites pass `current_user` directly, from inside request
        # context). Storing the proxy itself would be fine here but not once
        # a worker thread (process(), a different thread with no request
        # context) accesses it later — the proxy re-resolves on every
        # attribute access and silently returns None outside a request,
        # crashing that thread. Resolve to the real User object now, while
        # we know we're in a valid context, so it's a plain thread-safe
        # object for the rest of this instance's life.
        self.current_user = user._get_current_object() if hasattr(user, '_get_current_object') else user
        user = self.current_user
        self.user_id      = user.id if user else None
        self.info = info
        self.repo_cache = {}
        self.count_per_format = {}
        self.local_repo_path = None

        # Rule Tracking for Ruleset — keyed by rule id (was a list, O(N) per removal
        # under a global lock; a repo with tens of thousands of rules made every
        # single processed file pay for a full linear scan of every other rule).
        self.rules_to_process: Dict[int, Dict[str, Any]] = {} # {rule_id: {"title":, "github_path":}}

        # Stats
        self.bad_rules = 0
        self.updated = 0
        self.not_found = 0
        self.found = 0
        self.skipped = 0
        self.total = 0
        self.processed = 0

        self.query_date = datetime.datetime.now(tz=datetime.timezone.utc)
        self.rule_status_list = []

        # NEW RULE SYSTEM
        self.new_rules_list = []
        self._import_done_for_repo = set()
        self._finalized    = False
        self._save_done    = Event()
        self._workers_done = 0

    # ------------------ MAIN METHODS ------------------

    def start(self):
        cp = 0
        if self.mode == "by_url":
            cp = 0
            repo_dir, exists = clone_or_access_repo(self.repo_sources)

            self.local_repo_path = repo_dir

            # found all the rule in the repo currently in Rulezet
            rules_listes_github = RuleModel.get_all_rule_by_url_github(self.repo_sources , self.current_user)

            # Only diff against last check if we already had this repo cloned —
            # a brand-new clone has no meaningful "before" state to diff against.
            sha_before = get_repo_head_sha(repo_dir) if exists else None

            success = git_pull_repo(repo_dir)

            if not success:
                # The persistent clone (kept around across runs on purpose —
                # see clone_or_access_repo) can end up in a state `git pull`
                # refuses to fast-forward (diverged history, an interrupted
                # previous run, etc). Recover once by re-cloning fresh instead
                # of just giving up.
                try:
                    delete_existing_repo_folder(repo_dir)
                    repo_dir, _ = clone_or_access_repo(self.repo_sources)
                    self.local_repo_path = repo_dir
                    sha_before = None  # fresh clone — nothing meaningful to diff against
                    success = True
                except Exception as e:
                    self._finalize_with_error(f"Could not access or update the repository: {e}")
                    return

            sha_after = get_repo_head_sha(repo_dir)
            changed_files = None  # None = unknown/first run -> re-check everything
            if sha_before:
                changed_files = get_changed_files_between(repo_dir, sha_before, sha_after)

            # Split rules into "file changed since last check" (re-check) vs
            # "file untouched" (report as unchanged immediately, no re-parse/re-diff
            # needed). A repo with no new commits resolves its whole rule set this
            # way, instantly, instead of re-walking and re-validating every file.
            self.rules_to_process = {}
            unchanged_count = 0
            for r in rules_listes_github:
                if not r.github_path:
                    rel_path = None
                elif os.path.isabs(r.github_path):
                    rel_path = os.path.relpath(r.github_path, repo_dir)
                else:
                    rel_path = r.github_path
                if changed_files is not None and rel_path and rel_path not in changed_files:
                    unchanged_count += 1
                    with self.lock:
                        self.rule_status_list.append({
                            "update_result_uuid": self.uuid,
                            "name_rule": r.title,
                            "rule_id": r.id,
                            "message": "No change detected (file unchanged since last sync).",
                            "found": True,
                            "update_available": False,
                            "rule_syntax_valid": True,
                            "error": False,
                            "history_id": None,
                        })
                else:
                    self.rules_to_process[r.id] = {"title": r.title, "github_path": r.github_path}

            self.processed = unchanged_count

            if os.path.exists(repo_dir):
                load_all_rule_formats()
                subclasses = RuleType.__subclasses__()
                for root, dirs, files in os.walk(repo_dir, followlinks=False):
                    dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')
                               and not os.path.islink(os.path.join(root, d))]
                    for file in files:
                        if file.startswith('.') or file.startswith('_'):
                            continue
                        filepath = os.path.join(root, file)
                        # Reject symlinks — open() in extract_rules_from_file
                        # would otherwise follow one straight to its target
                        # and leak arbitrary filesystem content as a "rule".
                        if os.path.islink(filepath):
                            continue
                        rel_path = os.path.relpath(filepath, repo_dir)
                        if changed_files is not None and rel_path not in changed_files:
                            continue

                        for RuleClass in subclasses:
                            rule_instance = RuleClass()
                            if not rule_instance.get_rule_files(file):
                                continue

                            # Read + split into individual rules now (once) so each
                            # queue item is one rule, not one file — see session_class.py
                            # for the same fix on the import side.
                            try:
                                rules_text = rule_instance.extract_rules_from_file(filepath)
                            except Exception:
                                rules_text = []
                            for rule_text in rules_text:
                                cp += 1
                                self.jobs.put((cp, filepath, rule_instance, rule_text))
                            break

            self.total = cp + unchanged_count
        elif self.mode == "by_rule":

            # get all the rules from Rulezet with the ids
            rules_list: List[Rule] = Rule.query.filter(Rule.id.in_(self.repo_sources) ).all()

            # Group rules by source to minimize cloning/pulling
            rules_by_source: Dict[str, List[Rule]] = {}
            for r in rules_list:
                if r.source:
                    source_url = r.source.strip()
                    if source_url not in rules_by_source:
                        rules_by_source[source_url] = []
                    rules_by_source[source_url].append(r)

            # Initialize the rules we need to check
            self.rules_to_process = {r.id: {"title": r.title} for r in rules_list}

            cp = 0
            for source_url, rule_list in rules_by_source.items():
                
                try:
                    repo_dir, exists = clone_or_access_repo(source_url)
                    git_pull_repo(repo_dir)
                except Exception as e:
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
                # self.current_user (set in __init__ from the constructor's `user`
                # param), never Flask-Login's current_user proxy — that proxy
                # resolves via has_request_context() and silently returns None
                # once we're outside a Flask request (e.g. triggered from a
                # BackgroundJob worker thread, as the Sync Schedule feature does).
                # A None here crashes process() the first time it touches
                # user.id/user.is_admin() (db.session.merge(user) etc.), which
                # kills the worker thread mid-loop with no error surfaced —
                # exactly the "progress stuck at 1/N forever" symptom.
                args=[current_app._get_current_object(), self.current_user]
            )
            worker.daemon = True
            worker.start()
            self.threads.append(worker)


    # ------------------ RULE TRACKING ------------------

    def remove_processed_rule(self, rule_id: int):
        """Removes a rule from the to-process dict if found in the repo — O(1)."""
        with self.lock:
            self.rules_to_process.pop(rule_id, None)


    # ------------------ STATUS ------------------

    def status(self):
        if self.jobs.empty():
            self.stop()

        remaining = max(self.jobs.qsize(), len(self.threads))
        complete = self.processed

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
        unprocessed_rules = [r["title"] for r in self.rules_to_process.values()]

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
            "new_rules": [
                {
                    "id": None,  # not yet persisted — assigned in save_info()
                    "uuid": nr["uuid"],
                    "update_result_id": nr["update_result_id"],
                    "date": nr["date"].strftime('%Y-%m-%d %H:%M') if nr["date"] else None,
                    "name_rule": nr["name_rule"],
                    "rule_content": nr["rule_content"],
                    "message": nr["message"],
                    "format": nr["format"],
                    "rule_syntax_valid": nr["rule_syntax_valid"],
                    "error": nr["error"],
                    "accept": nr["accept"],
                    "github_path": nr["github_path"],
                }
                for nr in self.new_rules_list
            ],
            "unprocessed_rules": unprocessed_rules # ADDED: Rules from Rulezet not found in repo
        }

    # ------------------ FAIL FAST, DON'T HANG FOREVER ------------------

    def _finalize_with_error(self, message):
        """Used when start() bails out before ever enqueueing a job or
        spawning a worker (e.g. git pull failed even after a re-clone retry).
        Without this, self.total stays 0 and _save_done is never set — every
        future status() poll calls stop(), which then blocks for its full
        30s _save_done.wait() over and over, forever, since nothing ever
        completes process() to set it. The user sees an update-check page
        that spins indefinitely with no error and no way out."""
        self.total = max(self.total, 1)
        self.rule_status_list.append({
            "update_result_uuid": self.uuid,
            "name_rule": "—",
            "rule_id": None,
            "message": message,
            "found": False,
            "update_available": False,
            "rule_syntax_valid": False,
            "error": True,
            "history_id": None,
        })
        self.not_found = 1
        try:
            self.save_info()
        except Exception:
            pass
        finally:
            self._save_done.set()

    # ------------------ STOP ------------------

    def stop(self):
        if self.jobs.empty():
            for worker in self.threads:
                worker.join(3.5)
        self._save_done.wait(timeout=30)
        self.threads.clear()

    # ------------------ UPDATE PROCESS ------------------
    def process(self, loc_app, user: User):
        """Threaded function for queue processing."""
        while not self.jobs.empty():
            with loc_app.app_context():
                work = self.jobs.get()
                with self.lock:
                    self.processed += 1

                if self.mode == "by_url":

                    # work = (cp, filepath, rule_instance, rule_text) — one queue
                    # item is one rule (extracted up front in start()), not one file.
                    filepath = work[1]
                    rule_instance = work[2]
                    rule_text = work[3]

                    enriched_info = {**self.info, "filepath": filepath}
                    # Validate
                    validation_result  = rule_instance.validate(rule_text)
                    # Parse metadata
                    metadata = rule_instance.parse_metadata(rule_text , enriched_info , validation_result)

                    # --- Determine Rule Name ---
                    name = metadata.get("title") or metadata.get("name")
                    if not name:
                        # Skip if a name/title cannot be extracted for logging
                        self.jobs.task_done()
                        continue

                    metadata["github_path"] = os.path.relpath(filepath, self.local_repo_path)

                    # verify if the rule is correct or not
                    if metadata.get("original_uuid"):
                        _original_uuid = metadata.get("original_uuid")
                    else:
                        _original_uuid = None

                    # we have parse a rule and we want to found if it is already in Rulezet
                    existing_rule , message = RuleModel.get_rule_from_a_github(
                        name, filepath, self.repo_sources, _original_uuid,
                        content=metadata.get("to_string"),
                    )

                    if validation_result.ok:
                        # Case 1: Rule is VALID (either an update or a completely new rule)

                        if existing_rule:
                            # Sub-case 1.1: Rule EXISTS (Attempt Update and History Creation)

                            # Use self.local_repo_path instead of self.repo_sources
                            user = db.session.merge(user)
                            if existing_rule.user_id == user.id or user.is_admin():

                                # Check for rule updates
                                message_dict, success, new_rule_content = Check_for_rule_updates(existing_rule.to_string, rule_text, existing_rule.id)

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
                            self.remove_processed_rule(existing_rule.id)

                        else:
                            if message == "[new rule]":

                                # Sub-case 1.2: Rule does NOT EXIST (Log as New Valid Rule)
                                # Stored as a plain dict, not a NewRule ORM instance — this list
                                # lives in memory across the whole run, read from many different
                                # app-context/session scopes (status() polls, other worker
                                # iterations); an unattached ORM object read outside the context
                                # it was built in can raise DetachedInstanceError. Actual NewRule
                                # rows are only constructed once, at insert time, in save_info().
                                self.new_rules_list.append({
                                    "uuid": str(uuid4()),
                                    "update_result_id": None,  # filled in save_info()
                                    "date": datetime.datetime.now(tz=datetime.timezone.utc),
                                    "name_rule": name,
                                    "rule_content": rule_text,
                                    "message": "", # No error message since it's valid
                                    "rule_syntax_valid": True,
                                    "error": False,
                                    "accept": False,
                                    "format": metadata.get("format"),
                                    "github_path": os.path.relpath(filepath, self.local_repo_path),
                                })

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
                            self.remove_processed_rule(existing_rule.id)

                        else:
                            # Case 2.2: Rule does NOT EXIST (Log as New Invalid Rule for Correction)
                            if message == "[new rule]":

                # Same rationale as the valid-new-rule case above: plain dict, not
                                # a live ORM instance, since this list outlives the app-context
                                # it was built in.
                                self.new_rules_list.append({
                                    "uuid": str(uuid4()),
                                    "update_result_id": None,  # filled in save_info()
                                    "date": datetime.datetime.now(tz=datetime.timezone.utc),
                                    "name_rule": name,
                                    "rule_content": rule_text,
                                    "message": full_error_message,
                                    "rule_syntax_valid": False,
                                    "error": True,
                                    "accept": False,
                                    "format": metadata.get("format"),
                                    "github_path": metadata.get("github_path"),
                                })

                else:
                    # by rule: work = (cp, rule_id, repo_dir, rule_type_instance, rule_title)

                    rule_id = work[1]
                    repo_dir = work[2]
                    rule_instance = work[3]

                    existing_rule = RuleModel.get_rule(rule_id)
                    if not existing_rule:
                        self.jobs.task_done()
                        continue

                    # 1. Retrieve the rule content from the local repo clone
                    try:
                        found_rule_text, find_success = rule_instance.find_rule_in_repo(repo_dir, existing_rule.id)
                    except Exception:
                        self.jobs.task_done()
                        continue

                    if not find_success:
                        with self.lock:
                            self.rule_status_list.append({
                                "update_result_uuid": self.uuid,
                                "name_rule": existing_rule.title,
                                "rule_id": existing_rule.id,
                                "message": found_rule_text or "Rule not found in repository.",
                                "found": False,
                                "update_available": False,
                                "rule_syntax_valid": False,
                                "error": True,
                                "history_id": None
                            })
                        self.remove_processed_rule(existing_rule.id)
                        self.jobs.task_done()
                        continue

                    # 2. Compare existing content against repo content
                    message_dict, success, new_rule_content = Check_for_rule_updates(
                        existing_rule.to_string, found_rule_text, existing_rule.id
                    )

                    msg = message_dict.get("message", "") or ""
                    syntax_valid = success and ("Update found but invalid:" not in msg)

                    # 3. Create history if there is a change or an invalid update
                    history_id = None
                    if new_rule_content or not syntax_valid:
                        new_content_for_history = new_rule_content or found_rule_text
                        history_id = RuleModel.create_rule_history({
                            "id": existing_rule.id,
                            "title": existing_rule.title,
                            "success": success and bool(new_rule_content),
                            "message": msg,
                            "new_content": new_content_for_history,
                            "old_content": existing_rule.to_string
                        })

                    # 4. Record status
                    with self.lock:
                        self.rule_status_list.append({
                            "update_result_uuid": self.uuid,
                            "name_rule": existing_rule.title,
                            "rule_id": existing_rule.id,
                            "message": msg,
                            "found": success,
                            "update_available": bool(new_rule_content) or ("Update found but invalid:" in msg),
                            "rule_syntax_valid": syntax_valid,
                            "error": not success or not syntax_valid,
                            "history_id": history_id
                        })

                    self.remove_processed_rule(existing_rule.id)


            self.jobs.task_done()

        # Detect last worker — finalize exactly once regardless of whether the user
        # stays on the page (same pattern as session_class.py)
        with self.lock:
            self._workers_done += 1
            is_last = (self._workers_done >= self.thread_count and not self._finalized)
            if is_last:
                self._finalized = True

        if is_last:
            with self.lock:
                for rule_id, rule in list(self.rules_to_process.items()):
                    self.rule_status_list.append({
                        "update_result_uuid": self.uuid,
                        "name_rule": rule["title"],
                        "rule_id": rule_id,
                        "message": "Rule from Rulezet not found in the repository.",
                        "found": False,
                        "update_available": False,
                        "rule_syntax_valid": False,
                        "error": True,
                        "history_id": None
                    })
                self.rules_to_process.clear()

                self.found     = sum(1 for r in self.rule_status_list if r["found"])
                self.updated   = sum(1 for r in self.rule_status_list if r["update_available"])
                self.not_found = sum(1 for r in self.rule_status_list if r["error"] and not r["found"])
                self.skipped   = sum(1 for r in self.rule_status_list if r["found"] and not r["update_available"])

            with loc_app.app_context():
                try:
                    self.save_info()
                except Exception:
                    pass
                finally:
                    self._save_done.set()

            if self in sessions:
                sessions.remove(self)

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
            user_id=self.user_id,
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

        # Save new rules — built here, at insert time, from the plain dicts
        # accumulated during the run (see the "by_url" branch of process()).
        for nr in self.new_rules_list:
            db.session.add(NewRule(
                uuid=nr["uuid"],
                update_result_id=s.id,
                date=nr["date"],
                name_rule=nr["name_rule"],
                rule_content=nr["rule_content"],
                message=nr["message"],
                rule_syntax_valid=nr["rule_syntax_valid"],
                error=nr["error"],
                accept=nr["accept"],
                format=nr["format"],
                github_path=nr["github_path"],
            ))

        db.session.commit()

        try:
            from app.features.notification.notification_core import notify_github_update_done
            notify_github_update_done(
                user_id     = self.user_id,
                updated     = self.updated,
                found       = self.found,
                result_uuid = self.uuid,
            )
        except Exception:
            pass


# ------------------ RULE UPDATE CHECKER ------------------



def Check_for_rule_updates(rule_content, new_rule_content, rule_id):
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

    validation = rule_class.validate(new_rule_content)

    if rule.to_string.strip() != validation.normalized_content.strip():

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


