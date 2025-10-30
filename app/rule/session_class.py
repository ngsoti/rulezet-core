import datetime
import json
import os
from queue import Queue
from threading import Thread
from uuid import uuid4

from app.rule_type.abstract_rule_type.rule_type_abstract import RuleType
from app.rule_type.main_format import Process_rules_by_format
from .. import db
from ..db_class.db import ImporterResult, User
from . import rule_core as RuleModel
from app.import_github_project.cron_check_updates import APP
from flask import current_app
from flask_login import current_user

sessions = list()

class Session_class:
    def __init__(self, repo_dir, user: User, info) -> None:
        self.uuid = str(uuid4())
        self.thread_count = 4
        self.jobs = Queue(maxsize=0)
        self.threads = []
        self.stopped = False
        self.repo_dir = repo_dir
        self.bad_rules = 0
        self.imported = 0
        self.skipped = 0
        self.query_date = datetime.datetime.now(tz=datetime.timezone.utc)
        self.current_user = user
        self.info = info
        self.total = 0
        self.count_per_format = {}

    def start(self):
        """Start all worker"""
        cp = 0
        for root, dirs, files in os.walk(self.repo_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
            for file in files:
                subclasses = RuleType.__subclasses__()

                for RuleClass in subclasses:
                    rule_instance = RuleClass()

                    format_name = rule_instance.format
                    if not format_name in self.count_per_format:
                        self.count_per_format[format_name] = {"bad_rule":0, "skipped":0, "imported":0}


                    is_file = rule_instance.get_rule_files(file)

                    if not is_file:
                        continue

                    if is_file:
                        cp += 1
                        self.jobs.put((cp, file, os.path.join(root, file), rule_instance))
        self.total = cp

        #need the index and the url in each queue item.
        for _ in range(self.thread_count):
            worker = Thread(target=self.process, args=[current_app._get_current_object(), current_user._get_current_object()])
            worker.daemon = True
            worker.start()
            self.threads.append(worker)

    def status(self):
        """Status of the current queue"""
        if self.jobs.empty():
            self.stop()

        total = self.total
        remaining = max(self.jobs.qsize(), len(self.threads))
        complete = total - remaining

        return {
            'id': self.uuid,
            'total': total,
            'complete': complete,
            'remaining': remaining,
            'stopped' : self.stopped,
            "bad_rules": self.bad_rules,
            "imported": self.imported,
            "skipped": self.skipped
            }

    def status_for_test(self):
        return {
            'id': self.uuid,
            'total': 10,
            'complete': 5,
            'remaining': 5,
            "nb_errors": 0
            }

    def stop(self):
        """Stop the current queue and worker"""
        self.jobs.queue.clear()

        for worker in self.threads:
            worker.join(3.5)

        self.threads.clear()
        self.save_info()
        sessions.remove(self)
        del self

    def process(self, loc_app, user: User):
        """Threaded function for queue processing."""
        while not self.jobs.empty():
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
                # Attempt to create rule if validation is OK
                if validation_result.ok:
                    with loc_app.app_context():
                        user = db.session.merge(user)
                        success = RuleModel.add_rule_core(result_dict["rule"], user)
                    # success = True
                    if success:
                        self.imported += 1
                        self.count_per_format[rule_instance.format]["imported"] += 1
                    else:
                        self.skipped += 1
                        self.count_per_format[rule_instance.format]["skipped"] += 1
                else:
                    
                    with loc_app.app_context():
                        user = db.session.merge(user)
                        RuleModel.save_invalid_rule(
                            form_dict=metadata,
                            to_string=rule_text,
                            rule_type=rule_instance.format,
                            error=validation_result.errors,
                            user=user
                        )

                        self.bad_rules += 1
                        self.count_per_format[rule_instance.format]["bad_rule"] += 1

                    # break
            self.jobs.task_done()
        return True
    
    def save_info(self):
        """Save info in the db"""
        s = ImporterResult(
            uuid=str(self.uuid),
            info=json.dumps(self.info),
            bad_rules=self.bad_rules,
            imported=self.imported,
            skipped=self.skipped,
            total=self.total,
            count_per_format=json.dumps(self.count_per_format),
            query_date=self.query_date,
            user_id=self.current_user.id
        )
        db.session.add(s)
        db.session.commit()
        return