import datetime
import json
import os
from queue import Queue
from threading import Thread
from uuid import uuid4

from app.rule_format.abstract_rule_type.rule_type_abstract import RuleType, load_all_rule_formats
from app.rule_format.utils_format.utils_import_update import delete_existing_repo_folder

from ... import db
from ...db_class.db import ImporterResult, User
from ...rule import rule_core as RuleModel
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
        job_index = 0
        load_all_rule_formats()
        rule_subclasses = RuleType.__subclasses__()
        rule_instances = [RuleClass() for RuleClass in rule_subclasses]

        if os.path.exists(self.repo_dir):
            for root, dirs, files in os.walk(self.repo_dir):
                dirs[:] = [d for d in dirs if not d.startswith(('.', '_'))]
                for file in files:
                    if file.startswith(('.', '_')):
                        continue
                    
                    filepath = os.path.join(root, file)
                    for rule_instance in rule_instances:
                        if rule_instance.get_rule_files(file):
                            format_name = rule_instance.format
                            if format_name not in self.count_per_format:
                                self.count_per_format[format_name] = {
                                    "bad_rule": 0, 
                                    "skipped": 0, 
                                    "imported": 0
                                }

                            job_index += 1
                            self.jobs.put((job_index, file, filepath, rule_instance))
                            break

        self.total = job_index
        app_obj = current_app._get_current_object()
        user_obj = current_user._get_current_object()

        for _ in range(self.thread_count):
            worker = Thread(target=self.process, args=[app_obj, user_obj])
            worker.daemon = True
            worker.start()
            self.threads.append(worker)

    def status(self):
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
            "skipped": self.skipped,
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
        self.jobs.queue.clear()
        for worker in self.threads:
            worker.join(3.5)
        self.threads.clear()
        self.save_info()
        if self in sessions:
            sessions.remove(self)
        delete_existing_repo_folder("app/rule_from_github/Rules_Github")

    def process(self, loc_app, user: User):
        while not self.jobs.empty():
            try:
                work = self.jobs.get(timeout=1)
                filepath = work[2]
                rule_instance = work[3]

                extracted_rules = rule_instance.extract_rules_from_file(filepath)
                
                for raw_text in extracted_rules:
                    clean_text = raw_text.strip()
                    if not clean_text or clean_text.startswith('#'):
                        continue

                    enriched_info = {**self.info, "filepath": filepath}
                    validation = rule_instance.validate(clean_text)
                    metadata = rule_instance.parse_metadata(clean_text, enriched_info, validation)

                    with loc_app.app_context():
                        local_user = db.session.merge(user)
                        
                        if validation.ok:
                            success = RuleModel.add_rule_core(metadata, local_user)
                            if success:
                                self.imported += 1
                                self.count_per_format[rule_instance.format]["imported"] += 1
                            else:
                                self.skipped += 1
                                self.count_per_format[rule_instance.format]["skipped"] += 1
                        else:
                            RuleModel.save_invalid_rule(
                                form_dict=metadata,
                                to_string=clean_text,
                                rule_type=rule_instance.format,
                                error=validation.errors,
                                user=local_user
                            )
                            self.bad_rules += 1
                            self.count_per_format[rule_instance.format]["bad_rule"] += 1
                
                self.jobs.task_done()
            except Exception:
                if not self.jobs.empty():
                    self.jobs.task_done()
        return True
    
    def save_info(self):
        result_entry = ImporterResult(
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
        db.session.add(result_entry)
        db.session.commit()
        return result_entry