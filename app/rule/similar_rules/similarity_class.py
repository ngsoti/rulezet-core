import datetime
import json
import numpy as np
import faiss
import time
from uuid import uuid4
from queue import Queue
from threading import Thread
from concurrent.futures import ProcessPoolExecutor
from sklearn.feature_extraction.text import TfidfVectorizer
from sqlalchemy import delete, or_

from ... import db
from ...db_class.db import Rule, SimilarResult, RuleSimilarity, User
from flask import current_app

sessions = list()

def _parallel_fuzzy_worker(batch_data):
    from rapidfuzz import fuzz
    source_id, source_text, candidates, min_score, uuid = batch_data
    results = []
    source_id = int(source_id)

    for sim_id, target_text in candidates:
        sim_id = int(sim_id)
        if source_id == sim_id:
            continue

        if source_text == target_text:
            final_score = 1.0
        else:
            # Rapidfuzz is used for the final precise verification
            score_ratio = fuzz.ratio(source_text, target_text)
            final_score = score_ratio / 100.0

        if final_score >= min_score:
            results.append({
                "rule_id": source_id,
                "similar_rule_id": sim_id,
                "score": round(final_score, 4),
                "result_uuid": uuid
            })
    return results

class Similarity_class:
    def __init__(self, user: User, info, mode="global", target_rule_id=None, params=None) -> None:
        self.uuid = str(uuid4())
        self.thread_count = 6
        self.jobs = Queue(maxsize=0)
        self.threads = []
        self.stopped = False

        self.current_user = user
        self.user_id = user.id
        self.info = info
        self.mode = mode
        self.target_rule_id = target_rule_id
        self.params = params

        self.top_k = 10
        self.min_score = 0.50
        self.total = 0
        self.similar_pairs_found = 0
        
        # Percentage management
        self.indexing_progress = 0  
        self.is_indexing = True
        
        self.status_message = "Initializing environment..."
        self.start_time = datetime.datetime.now(tz=datetime.timezone.utc)
        self.name = user.last_name + " " + user.first_name
        self.title = "Calculating Similar Rules for " + user.last_name + " " + user.first_name

    def start(self):
        app_obj = current_app._get_current_object()
        with app_obj.app_context():
            new_res = SimilarResult(
                uuid=self.uuid,
                info=json.dumps(self.info) if isinstance(self.info, dict) else str(self.info),
                mode=self.mode,
                user_id=self.user_id
            )
            db.session.add(new_res)
            db.session.commit()

        manager = Thread(target=self._run_session, args=[app_obj])
        manager.daemon = True
        manager.start()

    def _run_session(self, app_obj):
        try:
            with app_obj.app_context():
                # --- STEP 1: INDEXING (1% to 30%) ---
                self.status_message = "Fetching rules from database..."
                self.indexing_progress = 5 
                
                rules_data = db.session.query(Rule.id, Rule.to_string).filter(Rule.to_string.isnot(None)).all()
                
                if not rules_data:
                    self.status_message = "No rules found."
                    self.stopped = True
                    return

                rule_ids = np.array([r[0] for r in rules_data])
                content_list = [(r[1] or "").strip() for r in rules_data]
                content_map = {r[0]: content_list[i] for i, r in enumerate(rules_data)}
                
                self.status_message = "Vectorizing rules (TF-IDF Sparse)..."
                self.indexing_progress = 15

                # Optimization: We keep the matrix sparse to save RAM
                vectorizer = TfidfVectorizer(
                    max_features=2500, 
                    min_df=3,
                    dtype=np.float32, 
                )
                tfidf_sparse = vectorizer.fit_transform(content_list)
                
                self.status_message = "Building FAISS HNSW Index..."
                self.indexing_progress = 20

                # Initialize HNSW index (Efficient for 180k+ items)
                d = tfidf_sparse.shape[1]
                index = faiss.IndexHNSWFlat(d, 32)
                
                # Add to index in chunks to avoid memory spikes
                chunk_size = 10000
                for i in range(0, tfidf_sparse.shape[0], chunk_size):
                    chunk = tfidf_sparse[i : i + chunk_size].toarray().astype('float32')
                    faiss.normalize_L2(chunk)
                    index.add(chunk)
                
                # Logic for target selection
                target_indices = []
                if self.mode == "global":
                    db.session.execute(delete(RuleSimilarity))
                    db.session.commit()
                    target_indices = list(range(len(rules_data)))
                elif self.mode == "filter" and self.params:
                    p_mode = self.params.get('mode')
                    sel, exc = self.params.get('selected_ids', []), self.params.get('excluded_ids', [])
                    target_indices = [i for i, rid in enumerate(rule_ids) if (rid in sel if p_mode == 'partial' else rid not in exc)]
                elif self.target_rule_id:
                    target_indices = [i for i, rid in enumerate(rule_ids) if rid == self.target_rule_id]

                self.total = len(target_indices)
                self.status_message = "Indexing complete. Starting match..."
                self.indexing_progress = 30
                
                # --- STEP 2: PROCESSING (31% to 100%) ---
                batch_size = 200 # Increased batch size for FAISS efficiency
                job_count = 0
                for i in range(0, len(target_indices), batch_size):
                    self.jobs.put((job_count, target_indices[i : i + batch_size]))
                    job_count += 1
                
                self.total_jobs = job_count
                self.is_indexing = False 
                
            for _ in range(self.thread_count):
                # We pass the sparse matrix to the worker
                worker = Thread(target=self.process, args=[app_obj, tfidf_sparse, index, rule_ids, content_map])
                worker.daemon = True
                worker.start()
                self.threads.append(worker)

        except Exception as e:
            self.status_message = f"Error: {str(e)}"
            self.stopped = True

    def process(self, loc_app, tfidf_sparse, index, rule_ids, content_map):
        with ProcessPoolExecutor(max_workers=2) as executor:
            while not self.jobs.empty() and not self.stopped:
                try:
                    _, batch_indices = self.jobs.get(timeout=1)
                    

                    vectors_dense = tfidf_sparse[batch_indices].toarray().astype('float32')
                    faiss.normalize_L2(vectors_dense)
                    

                    _, neighbors = index.search(vectors_dense, self.top_k + 1)

                    tasks = []
                    for k, idx_in_matrix in enumerate(batch_indices):
                        source_id = rule_ids[idx_in_matrix]
                        
                        candidates = []
                        for sid in neighbors[k]:
                            if sid != -1:
                                target_id = rule_ids[sid]
                                if target_id != source_id:
                                    candidates.append((target_id, content_map[target_id]))
                        
                        if candidates:
                            tasks.append((source_id, content_map[source_id], candidates, self.min_score, self.uuid))

                    # Fuzzy matching via ProcessPool
                    if tasks:
                        chunk_results = list(executor.map(_parallel_fuzzy_worker, tasks))
                        flat_entries = [item for sublist in chunk_results for item in sublist]

                        with loc_app.app_context():
                            if flat_entries and not self.stopped:
                                db.session.bulk_insert_mappings(RuleSimilarity, flat_entries)
                                db.session.commit()
                                self.similar_pairs_found += len(flat_entries)

                    self.jobs.task_done()
                except Exception as e:
                    print(f"Process Error: {e}")
                    if not self.jobs.empty(): self.jobs.task_done()
        return True

    def status(self):
        if self.total > 0 and self.jobs.empty() and not self.is_indexing:
            self.stop()
        
        remaining = self.jobs.qsize()
        # Progress based on total jobs created in _run_session
        complete_jobs = getattr(self, 'total_jobs', 1) - remaining

        if self.is_indexing:
            display_percent = self.indexing_progress
        else:
            processing_ratio = (complete_jobs / self.total_jobs) if self.total_jobs > 0 else 0
            display_percent = int(30 + (processing_ratio * 70))

        return {
            'id': self.uuid,
            'total': self.total,
            'complete': complete_jobs,
            'remaining': remaining,
            'stopped': self.stopped,
            'percentage': min(display_percent, 100),
            'status_message': self.status_message,
            'similar_pairs_found': self.similar_pairs_found,
            'step': "Indexing" if self.is_indexing else "Fuzzy Matching",
            'mode': self.mode,
            'name': self.name,
            'title': self.title,
            'uuid': self.uuid,
            'time_begin': self.start_time.isoformat()
        }

    def stop(self):
        self.stopped = True
        with self.jobs.mutex:
            self.jobs.queue.clear()
        for worker in self.threads:
            worker.join(timeout=0.5)
        self.save_final_stats()
        if self in sessions:
            sessions.remove(self)

    def save_final_stats(self):
        duration = int((datetime.datetime.now(tz=datetime.timezone.utc) - self.start_time).total_seconds())
        try:
            res = SimilarResult.query.filter_by(uuid=self.uuid).first()
            if res:
                res.time_taken = duration
                res.similar_pairs_found = self.similar_pairs_found
                res.total_rules_processed = self.total
                db.session.commit()
        except Exception:
            db.session.rollback()
