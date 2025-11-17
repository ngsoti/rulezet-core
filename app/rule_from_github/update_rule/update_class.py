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
        self.rule_status_list = []

        # NEW RULE SYSTEM
        self.new_rules_list = []
        self._import_done_for_repo = set()

    # ------------------ MAIN METHODS ------------------

    def start(self):
        cp = 0
        if self.mode == "by_url":

            for url in self.repo_sources:
                repo_dir, exists = clone_or_access_repo(url)
                if not repo_dir:
                    continue

                git_pull_repo(repo_dir)

                # -------- IMPORT NEW RULES (ONLY ONCE PER REPO) --------
                # self.import_new_rules_from_repo(repo_dir)
                # self._import_done_for_repo.add(repo_dir)

                rule_items = RuleModel.get_all_rule_by_url_github(url)
                self.total += len(rule_items)
                load_all_rule_formats()

                for rule in rule_items:
                    cp += 1
                    self.jobs.put((cp, repo_dir, rule.id))

        else:
            sources = RuleModel.get_sources_from_ids(self.repo_sources)
            load_all_rule_formats()

            for src in sources:
                repo_dir, exists = clone_or_access_repo(src)
                if exists and repo_dir:
                    git_pull_repo(repo_dir)
                    # assure-toi d'utiliser une clé qui correspondra à rule.source (str)
                    self.repo_cache[src] = repo_dir
                else:
                    # on veut quand même garder la clé mais avec None pour debug (optionnel)
                    self.repo_cache[src] = None

            for rule_id in self.repo_sources:
                rule = RuleModel.get_rule(rule_id)
                if not rule:
                    continue

                # essaye de récupérer repo_dir depuis le cache en utilisant rule.source
                repo_dir = self.repo_cache.get(rule.source)

                # si absent, essaye de cloner / accéder au repo en utilisant rule.source
                if not repo_dir and isinstance(rule.source, str):
                    repo_dir, exists = clone_or_access_repo(rule.source)
                    if exists and repo_dir:
                        git_pull_repo(repo_dir)
                        self.repo_cache[rule.source] = repo_dir
                    else:
                        # log + skip le job si on n'a pas de repo valide
                        with self.lock:
                            self.skipped += 1
                        continue

                cp += 1
                self.jobs.put((cp, repo_dir, rule.id))


                
            self.total = cp

        for _ in range(self.thread_count):
            worker = Thread(
                target=self.process,
                args=[current_app._get_current_object(), current_user._get_current_object()]
            )
            worker.daemon = True
            worker.start()
            self.threads.append(worker)

    # ------------------ IMPORT NEW RULES FROM REPO ------------------

    def import_new_rules_from_repo(self, repo_dir):
        """Extracts rules from repo that are NOT present in DB and stores them as NewRule objects."""
        if repo_dir in self._import_done_for_repo:
            return

        load_all_rule_formats()

        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]

            for file in files:
                if file.startswith('.') or file.startswith('_'):
                    continue

                for RuleClass in RuleType.__subclasses__():
                    rule_instance = RuleClass()

                    if not rule_instance.get_rule_files(file):
                        continue

                    filepath = os.path.join(root, file)
                    rules = rule_instance.extract_rules_from_file(filepath)
                    info = {
                        "license": None,
                        "author": getattr(current_user, "first_name", "Unknown"),
                        "repo_url": repo_dir
                    }
                    for rule_text in rules:
                        validation = rule_instance.validate(rule_text)
                        metadata = rule_instance.parse_metadata(rule_text, info, validation)

                        name = metadata.get("title") or metadata.get("name")
                        if not name:
                            continue

                        # skip if already exists in DB
                        if RuleModel.get_rule_by_title(name):
                            continue

                        # Add new rule object
                        new_rule_obj = NewRule(
                            uuid=str(uuid4()),
                            update_result_id=None,  # filled later in save_info()
                            date=datetime.datetime.now(tz=datetime.timezone.utc),
                            name_rule=name,
                            rule_content=rule_text,
                            message=str(validation.errors) if not validation.ok else "",
                            rule_syntax_valid=validation.ok,
                            error=not validation.ok,
                            accept=False
                        )

                        self.new_rules_list.append(new_rule_obj)

                    break  # Rule type matched → break inner loop

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
        while not self.jobs.empty():
            _, repo_dir, rule_id = self.jobs.get()

            with loc_app.app_context():
                # --- sécurité : repo_dir manquant ---
                if not repo_dir:
                    with self.lock:
                        self.skipped += 1
                        self.rule_status_list.append({
                            "update_result_uuid": self.uuid,
                            "name_rule": f"Rule {rule_id}",
                            "rule_id": str(rule_id),
                            "message": "Repo path not available (NoneType)",
                            "found": False,
                            "update_available": False,
                            "rule_syntax_valid": False,
                            "error": True,
                            "history_id": None
                        })
                    self.jobs.task_done()
                    continue

                # --- récupérer la règle ---
                rule = RuleModel.get_rule(rule_id)
                if not rule:
                    with self.lock:
                        self.skipped += 1
                        self.rule_status_list.append({
                            "update_result_uuid": self.uuid,
                            "name_rule": f"Rule {rule_id}",
                            "rule_id": str(rule_id),
                            "message": "Rule not found in database",
                            "found": False,
                            "update_available": False,
                            "rule_syntax_valid": False,
                            "error": True,
                            "history_id": None
                        })
                    self.jobs.task_done()
                    continue

                # --- vérifier les mises à jour ---
                message_dict, success, new_rule_content = Check_for_rule_updates(rule_id, repo_dir)

                # --- créer un historique si besoin ---
                history_id = None
                if success and new_rule_content:
                    history_id = RuleModel.create_rule_history({
                        "id": rule_id,
                        "title": rule.title,
                        "success": success,
                        "message": message_dict.get("message", ""),
                        "new_content": new_rule_content,
                        "old_content": rule.to_string
                    })
                    message_dict["history_id"] = history_id

                msg = message_dict.get("message", "") or ""
                syntax_valid = not ("Update found but invalid:" in msg)

                # --- mise à jour du statut ---
                with self.lock:
                    self.rule_status_list.append({
                        "update_result_uuid": self.uuid,
                        "name_rule": rule.title,
                        "rule_id": str(rule_id),
                        "message": message_dict.get("message", ""),
                        "found": success,
                        "update_available": bool(new_rule_content),
                        "rule_syntax_valid": syntax_valid,
                        "error": not success,
                        "history_id": history_id
                    })

            # signaler que le job est terminé
            self.jobs.task_done()


    # ------------------ SAVE TO DATABASE ------------------

    def save_info(self):
        extended_info = dict(self.info)


        if self.mode == 'by_url':
            extended_info["github_metadata"] = [
                {"url": repo_url, **github_repo_metadata(repo_url, None)}
                for repo_url in self.repo_sources
                if github_repo_metadata(repo_url, None)
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
