import datetime
import json
import os
from queue import Queue
from threading import Event, Lock, Thread
from uuid import uuid4

from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import RuleType, load_all_rule_formats
from app.features.rule.rule_format.utils_format.utils_import_update import delete_existing_repo_folder

from ..... import db
from .....core.db_class.db import ImporterResult, User
from app.features.rule import rule_core as RuleModel
from app.features.rule.rules_core import bad_rule_core as BadRuleModel
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
        self.user_id      = user.id if user else None
        self.info = info
        self.total = 0
        self.count_per_format = {}
        self._stop_lock    = Lock()
        self._finalized    = False
        self._save_done    = Event()  # set once save_info() has completed
        self._workers_done = 0        # how many worker threads have exited

    def start(self):
        job_index = 0
        load_all_rule_formats()
        rule_subclasses = RuleType.__subclasses__()
        rule_instances = [RuleClass() for RuleClass in rule_subclasses]

        if os.path.exists(self.repo_dir):
            repo_real = os.path.realpath(self.repo_dir)
            for root, dirs, files in os.walk(self.repo_dir, followlinks=False):
                # Skip hidden directories and symlinked directories (a symlinked
                # directory could otherwise be walked into via its resolved target)
                dirs[:] = [
                    d for d in dirs
                    if not d.startswith(('.', '_'))
                    and not os.path.islink(os.path.join(root, d))
                ]
                for file in files:
                    if file.startswith(('.', '_')):
                        continue

                    filepath = os.path.join(root, file)

                    # Reject symlinks outright: a cloned repo can contain a symlink
                    # (e.g. rule.yar -> /etc/passwd) whose target open() would follow
                    # transparently, leaking arbitrary filesystem content as a "rule".
                    if os.path.islink(filepath):
                        continue

                    # Defense in depth: also reject any path that, once resolved,
                    # escapes the cloned repo directory (covers symlinked ancestors).
                    real_filepath = os.path.realpath(filepath)
                    if real_filepath != repo_real and not real_filepath.startswith(repo_real + os.sep):
                        continue

                    # Collect every format that claims this file by extension
                    candidates = [ri for ri in rule_instances if ri.get_rule_files(file)]
                    if not candidates:
                        continue

                    # When multiple formats share an extension (e.g. ATR + Sigma on .yml),
                    # use each format's detect() method on the file content to pick the
                    # right one.  Falls back to the first candidate if none self-identify.
                    if len(candidates) > 1:
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='replace') as _fh:
                                _sample = _fh.read(8192)
                            detected = [ri for ri in candidates
                                        if hasattr(ri, 'detect') and ri.detect(_sample)]
                            rule_instance = detected[0] if detected else candidates[0]
                        except Exception:
                            rule_instance = candidates[0]
                    else:
                        rule_instance = candidates[0]

                    format_name = rule_instance.format
                    if format_name not in self.count_per_format:
                        self.count_per_format[format_name] = {
                            "bad_rule": 0,
                            "skipped": 0,
                            "imported": 0
                        }

                    job_index += 1
                    self.jobs.put((job_index, file, filepath, rule_instance))

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

    def _ensure_finalized(self, app_obj=None):
        """Save import results and send notifications exactly once, thread-safe.
        Called by _bg_watchdog (background, needs app_obj) or stop() (request context).
        Sets _save_done once the DB commit and notifications are complete so that
        stop() never clears threads before the result is persisted."""
        with self._stop_lock:
            if self._finalized:
                return
            self._finalized = True
        try:
            if app_obj:
                with app_obj.app_context():
                    self.save_info()
            else:
                self.save_info()
            if self in sessions:
                sessions.remove(self)
            delete_existing_repo_folder("app/rule_from_github/Rules_Github")
        except Exception:
            pass
        finally:
            self._save_done.set()   # always unblock stop(), even on error

    def stop(self):
        self.jobs.queue.clear()
        for worker in self.threads:
            worker.join(3.5)
        self._ensure_finalized()        # save + notify (no-op if watchdog already did it)
        self._save_done.wait(timeout=30)  # wait until save is committed before clearing
        self.threads.clear()            # only now is remaining=0 safe to return

    def process(self, loc_app, user: User):
        while not self.jobs.empty():
            try:
                work = self.jobs.get(timeout=1)
                filepath = work[2] # Absolute path to the file
                rule_instance = work[3]



                extracted_rules = rule_instance.extract_rules_from_file(filepath)
                
                for raw_text in extracted_rules:
                    clean_text = raw_text.strip()
                    if not clean_text or clean_text.startswith('#'):
                        continue

                    # ENRICHMENT: Adding the filepath to the info dictionary
                    # This allows the metadata parser to see the 'github_path'
                    enriched_info = {**self.info, "github_path": filepath}
                    
                    validation = rule_instance.validate(clean_text)
                    metadata = rule_instance.parse_metadata(clean_text, enriched_info, validation)
                    # add to metadata the enriched info (github_path)
                    metadata["github_path"] = filepath # os.path.relpath(filepath, self.repo_dir)
                    with loc_app.app_context():
                        local_user = db.session.merge(user)
                        
                        if validation.ok:
                            # metadata now contains 'github_path' for RuleModel.add_rule_core
                            success, msg = RuleModel.add_rule_core(metadata, local_user)
                            if success:
                                self.imported += 1
                                self.count_per_format[rule_instance.format]["imported"] += 1
                            else:
                                self.skipped += 1
                                self.count_per_format[rule_instance.format]["skipped"] += 1
                        else:
                            BadRuleModel.save_invalid_rule(
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
                self.jobs.task_done()

        # Detect whether this is the last worker to exit.
        # If so, finalize the session right here — we already have an app context
        # available via loc_app, so no extra thread or Queue.join() is needed.
        with self._stop_lock:
            self._workers_done += 1
            is_last = (self._workers_done >= self.thread_count and not self._finalized)
            if is_last:
                self._finalized = True

        if is_last:
            with loc_app.app_context():
                try:
                    self.save_info()
                except Exception:
                    pass
                finally:
                    self._save_done.set()
            if self in sessions:
                sessions.remove(self)
            try:
                delete_existing_repo_folder("app/rule_from_github/Rules_Github")
            except Exception:
                pass

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
            user_id=self.user_id
        )
        db.session.add(result_entry)
        db.session.commit()

        try:
            from app.features.notification.notification_core import notify_github_import_done
            notify_github_import_done(
                user_id    = self.user_id,
                imported   = self.imported,
                skipped    = self.skipped,
                bad_rules  = self.bad_rules,
                result_uuid = self.uuid,
            )
        except Exception:
            pass

        return result_entry