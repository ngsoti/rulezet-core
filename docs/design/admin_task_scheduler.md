# Admin Task Scheduler — Design Plan

> Status: design only, nothing is implemented. This document is the map for
> a future implementation — it must stay readable and actionable months from
> now. Based on a full inspection of the existing "Sync Schedule" system
> (`/rule/github/manage`, "Sync Schedules" tab), which this generalizes
> rather than reinvents.

## Context

The existing **Sync Schedule** system (GitHub recurrence, `GithubSyncSchedule`
+ `scheduler_engine.py`) already works well: APScheduler for the "when",
`BackgroundJob`/`job_worker.py` for the "what" (no new concurrency code to
write), the DB as the single source of truth (a restart never loses a
schedule). That is exactly the mechanism to reproduce — but **generalized**:
today it can only schedule one kind of task (GitHub sync). The goal is a
single admin panel where N kinds of tasks can be scheduled (Similarity,
GitHub Import, Field Parser, Quality Score, MISP taxonomy/galaxy updates,
Connector pulls, and any future job), plus several things that don't exist
yet:

1. Choose **"run now" OR "schedule for later / recurring"** at creation
   time — not just "always recurring".
2. A notion of **dependency between tasks**: "task B only runs after task A
   has finished" (chaining), on top of classic time-based triggering —
   pushed all the way to **multiple dependencies (AND/OR)** and
   **success/failure branching** (§4bis), not just a single linear chain.
3. Pushed toward **maximum autonomy** (§9bis): retries, cooperative
   timeouts, a concurrency guard, an auto-disable circuit breaker after
   repeated failures, and **opt-in email alerts** per schedule so an admin
   genuinely doesn't have to watch it — the system tells you when it needs
   attention instead of you having to check.

The whole thing must stay a clean system where adding a new schedulable task
type later is a small, localized change (a registry entry), never an
explosion of `if/else` in the engine — and simple enough that someone
self-hosting Rulezet can add their own task type without touching the
engine (§2ter).

## 0. What's reused as-is (do not reinvent)

These building blocks of the existing Sync Schedule are already generic by
construction and get reused **unchanged**:

- `scheduler_engine.py`: `BackgroundScheduler` (APScheduler) on a daemon
  thread, `build_trigger()`, `register_schedule()`/`unregister_schedule()`,
  `start_scheduler()` called from `app/__init__.py` (`if start_worker: ...`).
  The core principle — "APScheduler only ever creates a `BackgroundJob` row
  and lets `job_worker.py` do the actual work" — is central: never run heavy
  work on the APScheduler thread itself.
- `ScheduleRecurrencePicker` (`app/static/js/rule/scheduleRecurrencePicker.js`):
  already 100% generic, has no GitHub-specific notion — emits
  `{frequency, days_of_week, day_of_month, hour, minute, cron_expr, timezone}`.
  Reused as-is, with one small addition (§3).
- The admin-only blueprint pattern (`before_request` + `abort(403)`), already
  used by `sync_schedule_routes.py`.
- `PaginationComponent`, `UserChip`.
- The "toggleable table/card view + multi-select + bulk actions" pattern
  (`dt-*` classes) already used in `manage_github.html` for the schedule
  list — same visual style for the new task list.

## 1. Generalized data model

Three new tables replace (or coexist with, see §8) the `GithubSyncSchedule*`
tables. Naming: `AdminTask*` (the word "Schedule" alone no longer covers it
since a task can be one-shot).

### `AdminTaskType` — not a table, a Python registry (§2)

The list of task types is **not** stored in the DB — it's a code registry
(like `@register_handler`), so that adding a task type is a file/a few
lines, never a migration.

### `AdminTaskSchedule` (replaces `GithubSyncSchedule`)

```python
class AdminTaskSchedule(db.Model):
    __tablename__ = "admin_task_schedule"

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid        = db.Column(db.String(36), index=True, unique=True)
    title       = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    editor_id   = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # Key into the AdminTaskType registry (§2) — e.g. 'github_sync', 'quality_score'.
    task_type   = db.Column(db.String(50), nullable=False, index=True)

    # Free-form payload, shape defined by task_type (§2) — replaces the
    # dedicated GithubSyncScheduleRepo table: a Quality Score task has no
    # "repo", a GitHub Sync task has no "rule_ids". Always the shape
    # {mode, filters, selected_ids/urls, excluded_ids/urls, ...type-specific
    # options} — the exact shape RuleList already emits via its 'send' event
    # (see rule_quality_score.html's submitQualityAnalysis for a working example).
    target_payload = db.Column(db.JSON, nullable=False, default=dict)

    is_active   = db.Column(db.Boolean, default=True, index=True)

    # ── Triggering: either time-based, or "after another task" ──
    # Never both at once for the same row — see §4.
    trigger_mode = db.Column(db.String(20), nullable=False, default='cron')
    # 'once' | 'daily' | 'weekly' | 'monthly' | 'cron' | 'after_task'

    # Recurrence — identical to GithubSyncSchedule, plus 'once'.
    run_once_at  = db.Column(db.DateTime, nullable=True)      # trigger_mode == 'once'
    days_of_week = db.Column(db.String(20), nullable=True)    # 'weekly' only
    day_of_month = db.Column(db.Integer, nullable=True)       # 'monthly' only
    hour         = db.Column(db.Integer, nullable=False, default=3)
    minute       = db.Column(db.Integer, nullable=False, default=0)
    cron_expr    = db.Column(db.String(120), nullable=True)   # 'cron' only
    timezone     = db.Column(db.String(60), nullable=False, default="UTC")

    # Chaining — 'after_task' only. The actual edges live in
    # AdminTaskDependency below (a task can depend on MULTIPLE parents —
    # see §4bis); dependency_logic says how to combine them.
    # 'all' = every parent must satisfy its condition (AND);
    # 'any' = one is enough (OR).
    dependency_logic = db.Column(db.String(10), nullable=False, default='all')

    # ── Robustness / autonomy (§9bis) ──
    retry_count          = db.Column(db.Integer, nullable=False, default=0)   # attempts IN ADDITION to the 1st
    retry_delay_minutes  = db.Column(db.Integer, nullable=False, default=5)
    timeout_minutes      = db.Column(db.Integer, nullable=True)               # NULL = no timeout
    concurrency_policy   = db.Column(db.String(10), nullable=False, default='skip')  # 'skip' | 'queue'
    max_consecutive_failures = db.Column(db.Integer, nullable=True, default=5)  # NULL/0 = never auto-disable
    consecutive_failures = db.Column(db.Integer, nullable=False, default=0)     # reset to 0 on any success
    auto_disabled_reason = db.Column(db.Text, nullable=True)  # set when the circuit breaker flips is_active off

    # ── Email notifications (§9bis) ──
    notify_on_failure = db.Column(db.Boolean, nullable=False, default=True)
    notify_on_success = db.Column(db.Boolean, nullable=False, default=False)
    notify_emails      = db.Column(db.JSON, nullable=True)  # extra recipients ON TOP OF editor.email

    # ── Resilience across restarts (§9bis, "missed run") ──
    on_missed_run = db.Column(db.String(20), nullable=False, default='skip_to_next')
    # 'run_immediately' | 'skip_to_next' — maps directly onto the existing
    # APScheduler misfire_grace_time / coalesce kwargs, no need to reinvent
    # this logic (see §9bis).

    next_run_at = db.Column(db.DateTime, index=True, nullable=True)
    last_run_at = db.Column(db.DateTime, nullable=True)

    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow,
                             onupdate=datetime.datetime.utcnow)

    editor        = db.relationship("User")
    runs          = db.relationship("AdminTaskRun", backref="schedule",
                                     cascade="all, delete-orphan", lazy=True,
                                     order_by="desc(AdminTaskRun.started_at)")
```

Why `trigger_mode` is exclusive rather than "a cron AND a dependency on
top": simpler to reason about and to render in the UI ("this task runs: ⚪
on a fixed schedule ⚪ after another task" — one radio group, not a matrix
of cases). Nothing stops a v2 from loosening this — but starting strict
avoids a first double-trigger bug.

### `AdminTaskDependency` (new — replaces the plain FK from the first draft of this plan)

```python
class AdminTaskDependency(db.Model):
    __tablename__ = "admin_task_dependency"

    id                     = db.Column(db.Integer, primary_key=True, autoincrement=True)
    schedule_id            = db.Column(db.Integer,
        db.ForeignKey("admin_task_schedule.id", ondelete="CASCADE"), nullable=False)
    depends_on_schedule_id = db.Column(db.Integer,
        db.ForeignKey("admin_task_schedule.id", ondelete="CASCADE"), nullable=False)
    # 'success' | 'failure' | 'always' — condition ON THIS SPECIFIC parent;
    # two parents of the same task can have different conditions
    # (e.g. "after A if it succeeds AND after B no matter what").
    condition              = db.Column(db.String(20), nullable=False, default='success')

    __table_args__ = (db.UniqueConstraint('schedule_id', 'depends_on_schedule_id'),)

    schedule    = db.relationship("AdminTaskSchedule", foreign_keys=[schedule_id], backref="dependencies")
    depends_on  = db.relationship("AdminTaskSchedule", foreign_keys=[depends_on_schedule_id])
```

One row per edge of the dependency graph — see §4bis for why a separate
table (rather than a plain FK) is required as soon as "wait for A AND B" is
a requirement.

### `AdminTaskRun` (replaces `GithubSyncRun`)

```python
class AdminTaskRun(db.Model):
    __tablename__ = "admin_task_run"

    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid          = db.Column(db.String(36), index=True, unique=True)
    schedule_id   = db.Column(db.Integer, db.ForeignKey("admin_task_schedule.id", ondelete="CASCADE"), nullable=False)
    job_uuid      = db.Column(db.String(36), nullable=True)   # -> BackgroundJob.uuid

    status        = db.Column(db.String(20), default="pending")  # pending | running | done | failed | skipped | timed_out
    retry_attempt = db.Column(db.Integer, nullable=False, default=0)  # 0 = initial attempt, 1+ = a retry
    started_at    = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    finished_at   = db.Column(db.DateTime, nullable=True)
```

No `GithubSyncRunRepo`-style sub-table: every `task_type` already has its
own rich history (an `UpdateResult` for GitHub sync, a detailed
`BackgroundJobLog` for everything else) — `AdminTaskRun` is just a thin
wrapper pointing at the real `BackgroundJob`, not a duplication. Plan for a
periodic purge of this table (the same need as `delete_activity_logs`,
§2bis) — otherwise it grows forever; expose it as a schedulable task in the
registry itself once the system is in place (a bit meta, but consistent).

## 2. Task type registry — the central point for "adding a job easily"

New file `app/features/admin/task_scheduler/task_types.py`:

```python
"""
task_types.py — registry of schedulable task types. Adding a task type =
adding an entry here, never touching the generic engine (scheduler_engine)
or the list UI. The job_type must already exist in job_handlers.py
(@register_handler) — this registry only describes how the scheduling form
should build its payload. See §2ter for the full step-by-step guide.
"""

TASK_TYPES = {
    'quality_score': {
        'label': 'Rule Quality Score — (re)analyze',
        'icon': 'fa-solid fa-gauge-high',
        'job_type': 'compute_rule_quality_score',      # already registered, reused as-is
        'target_picker': 'rule_list_select',            # see §3 — which widget the form shows
        'build_label': lambda payload: 'Analyze quality — ' + _target_summary(payload),
    },
    'field_parser': {
        'label': 'Bulk Field Parser',
        'icon': 'fa-solid fa-wand-magic-sparkles',
        'job_type': 'bulk_parse_fields',                # already registered
        'target_picker': 'rule_list_select',
    },
    'attack_parser': {
        'label': 'ATT&CK Auto-parse',
        'icon': 'fa-solid fa-crosshairs',
        'job_type': 'bulk_parse_attack_rules',          # already registered
        'target_picker': 'format_filter_only',          # this job only takes a format filter, no rule_ids
    },
    'github_sync': {
        'label': 'GitHub Sync (update existing rules)',
        'icon': 'fa-brands fa-github',
        'job_type': 'github_sync_schedule_run',         # already registered — the existing handler, reused
        'target_picker': 'repo_selection_table',
        'extra_options': ['auto_accept_update', 'auto_add_new_rule'],  # per-repo, see the existing RepoSelectionTable
    },
    'github_import': {
        'label': 'GitHub Import (new repos)',
        'icon': 'fa-brands fa-github',
        'job_type': 'github_import_run',                # ⚠ DOES NOT EXIST YET — see §9, prerequisite work
        'target_picker': 'repo_url_list',
    },
    'similarity_scan': {
        'label': 'Similarity Scan',
        'icon': 'fa-solid fa-code-compare',
        'job_type': 'similarity_scan_run',               # ⚠ DOES NOT EXIST YET — see §9, prerequisite work
        'target_picker': 'rule_list_select',
    },

    # ── Candidates found by the full audit of the 30 existing
    #    @register_handler entries (§2bis) — all ready (job_type already
    #    exists), no prerequisite work unlike the two above.
    'misp_update_data': {
        'label': 'MISP — Update taxonomies & galaxies (imported only)',
        'icon': 'fa-solid fa-rotate',
        'job_type': 'update_misp_data',                  # already registered — job_handlers.py:767
        'target_picker': 'none',                          # payload {} — nothing to target
    },
    'misp_import_all_taxonomies': {
        'label': 'MISP — Import all new taxonomies',
        'icon': 'fa-solid fa-tags',
        'job_type': 'import_all_taxonomies',              # job_handlers.py:872
        'target_picker': 'none',
    },
    'misp_import_all_galaxies': {
        'label': 'MISP — Import all new galaxies',
        'icon': 'fa-solid fa-tags',
        'job_type': 'import_all_galaxies',                # job_handlers.py:918
        'target_picker': 'none',
    },
    'attack_update_data': {
        'label': 'ATT&CK — Update MITRE data',
        'icon': 'fa-brands fa-github',
        'job_type': 'update_attack_data',                 # job_handlers.py:2447
        'target_picker': 'none',
    },
    'db_backup': {
        'label': 'Database Backup',
        'icon': 'fa-solid fa-database',
        'job_type': 'db_backup',                          # job_handlers.py:3945
        'target_picker': 'none',
    },
    'rule_validation_run': {
        'label': 'Rule Validation (false-positive gate)',
        'icon': 'fa-solid fa-shield-check',
        'job_type': 'rule_validation_run',                # job_handlers.py:4002
        'target_picker': 'none',
        'extra_options': ['full'],                        # bool: full scan vs incremental (payload {full, limit})
    },
    'bulk_tag_platforms': {
        'label': 'Bulk Platform Tagging (regex config)',
        'icon': 'fa-solid fa-tags',
        'job_type': 'bulk_tag_platforms',                 # job_handlers.py:2701
        'target_picker': 'rule_list_select',
        'extra_options': ['config_id'],                   # which FieldParserConfig to apply
    },
    'activity_log_purge': {
        'label': 'Activity Log — Purge old entries',
        'icon': 'fa-solid fa-broom',
        'job_type': 'delete_activity_logs',               # job_handlers.py:652 — orphaned, NO UI calls it today
        'target_picker': 'none',
        'extra_options': ['action_filter', 'older_than_days'],  # payload {log_ids|delete_all, action_filter}
    },
    'connector_pull': {
        'label': 'Connector — Pull one federation source',
        'icon': 'fa-solid fa-plug',
        'job_type': 'connector_pull',                     # job_handlers.py:1095
        'target_picker': 'connector_select',              # new picker — a <select> of Connector rows, not rules
    },
}
```

**Official vs. custom instance pulls**: `connector_pull` covers this
directly — `Connector.instance_url` (`db.py:2619`) is just a URL, and
`Connector.is_system` (`db.py:2634`, "System connectors (e.g. official
Rulezet) are read-only and visible to all users") is the exact flag that
distinguishes an official-instance connector from a self-hosted/custom one.
No new field is needed: the `connector_select` picker (§3) should badge
`is_system` connectors as "Official" so the admin can tell them apart at a
glance, and scheduling a recurring `connector_pull` against either kind
works identically — it's just a different `connector_id` in the payload.

Every generic route/component (list, creation form, engine) reads this
dict — never a scattered `if task_type == 'quality_score': ... elif ...`
across multiple files. Adding a job later = one entry here + (if needed) a
new `@register_handler` in `job_handlers.py`, nothing else to touch in the
scheduler.

`target_picker` = which Vue component the generic form instantiates
dynamically to choose the target (§3). `extra_options` = which extra
checkboxes/fields to render (e.g. the two per-repo booleans the current
GitHub Sync already has).

### 2bis. Full catalog — the 30 existing `@register_handler` entries, classified

A one-time exhaustive audit of `job_handlers.py` (for reference — should
not need to be redone by hand later). Three categories:

- **(a) Already manually triggerable, good registry candidate** — the "Added
  above?" column says whether it's already done.
- **(b) Already runs on a schedule** — this is `github_sync_schedule_run`,
  the exact system being generalized here; nothing more to do.
- **(c) Not worth scheduling** — depends on a one-off, precise context (a
  specific blog post, a specific GitHub session, a specific ownership
  request, a specific MISP/Velociraptor server + a specific rule) or is too
  risky to run without direct human supervision (packages/submodules — can
  break the app).

| job_type | Line | Category | Added to the registry above? |
|---|---|---|---|
| `bulk_add_tag_to_rules` | 239 | (a) | No — already has its own dedicated UI (`/rule/bulk_tag`), not a priority |
| `bulk_remove_tag_from_rules` | 413 | (a) | No — same |
| `compute_rule_quality_score` | 505 | (a) | ✅ `quality_score` |
| `delete_github_rules` | 600 | (a) | No — a one-off destructive action, not recurring by nature |
| `delete_activity_logs` | 652 | (a, orphaned) | ✅ `activity_log_purge` — **no UI exists today**, this will be its first interface |
| `update_misp_data` | 767 | (a) | ✅ `misp_update_data` |
| `import_all_taxonomies` | 872 | (a) | ✅ `misp_import_all_taxonomies` |
| `import_all_galaxies` | 918 | (a) | ✅ `misp_import_all_galaxies` |
| `trash_restore_bulk` | 968 | (a) | No — a one-off action tied to a specific deletion batch |
| `trash_permanent_delete_bulk` | 1034 | (a) | Not yet — would become relevant with an actual retention policy (§9 note) |
| `connector_pull` | 1095 | (a) | ✅ `connector_pull` |
| `update_package` | 1701 | (c) | — risk of breaking the app without supervision |
| `uninstall_package` | 1747 | (c) | — same |
| `update_submodule_bg` | 1793 | (c) | — same |
| `remove_submodule` | 1838 | (c) | — same |
| `bulk_update_decision` | 1905 | (c) | — tied to a specific GitHub-update session |
| `bulk_new_rules_decision` | 1979 | (c) | — same |
| `ownership_transfer_bulk` | 2052 | (c) | — tied to a specific ownership request |
| `bulk_transfer_ownership` | 2150 | (a) | No — needs a human pick of a target user every time |
| `github_proposal_bulk_import` | 2326 | (c) | — tied to already-accepted proposals |
| `update_attack_data` | 2447 | (a) | ✅ `attack_update_data` |
| `bulk_parse_attack_rules` | 2467 | (a) | ✅ `attack_parser` |
| `bulk_parse_fields` | 2575 | (a) | ✅ `field_parser` |
| `bulk_tag_platforms` | 2701 | (a) | ✅ `bulk_tag_platforms` |
| `blog_from_cve` | 3221 | (c) | — an editorial action tied to one specific post |
| `rule_test_bulk` | 3425 | (c) | — tied to one specific test |
| `github_sync_schedule_run` | 3612 | (b) | already the existing system being generalized |
| `velociraptor_push` | 3766 | (c) | — pushes ONE rule to ONE server, not a sweep |
| `misp_push` | 3848 | (c) | — same |
| `db_backup` | 3945 | (a) | ✅ `db_backup` |
| `rule_validation_run` | 4002 | (a) | ✅ `rule_validation_run` |

**Mechanisms outside `BackgroundJob` — not candidates**:
- **Phone-home telemetry** (`app/__init__.py:277-326`, daemon thread, pings
  every 24h) — fixed infra behavior, no point making it "admin-schedulable".
- **Automatic trash purge** — doesn't exist today, no age-based retention
  notion on `trash_permanent_delete_bulk`. This new system makes it possible
  for the first time (`activity_log_purge` shows the same need for logs —
  same pattern could be duplicated for trash in a v2 if wanted).
- **Connectors**: the `Connector` model has **no `sync_interval` field** —
  per-connector scheduling is 100% manual today. This new system removes
  the need to add that field: scheduling a recurring `connector_pull` is
  done directly via `AdminTaskSchedule`, without touching the `Connector`
  model.

### 2ter. Developer guide — adding a new task type

The whole point of the registry is that someone self-hosting Rulezet can add
their own scheduled task on their own rules without touching the engine,
the UI list, or the dependency logic. Concrete steps:

1. **Check whether the job already exists.** `grep "@register_handler" app/features/jobs/job_handlers.py`
   — if the behavior you want is already a `job_type` (see the catalog in
   §2bis), skip straight to step 3.
2. **If it doesn't exist, write a new handler** in `job_handlers.py`,
   copying the shape of an existing one (`bulk_add_tag_to_rules` at
   `job_handlers.py:221` is the best template: batch loop, `_is_cancelled`/
   `_should_pause` checks between batches, `_save_offset` for resumability,
   `log_job` for progress). Register it with `@register_handler('my_new_job_type')`.
   This is the exact same step you'd take to add any regular background
   job — nothing scheduler-specific about it.
3. **Add one entry to `TASK_TYPES`** in `task_types.py`:
   ```python
   'my_new_task': {
       'label': 'My New Task',
       'icon': 'fa-solid fa-star',
       'job_type': 'my_new_job_type',
       'target_picker': 'rule_list_select',   # pick the closest existing picker (§3)
   },
   ```
   Pick `target_picker` from what already exists (`rule_list_select`,
   `repo_selection_table`, `repo_url_list`, `format_filter_only`,
   `connector_select`, `none`). Only write a brand new Vue picker component
   if none of these fit your job's payload shape — register it in the
   `targetPickerComponent` map in `task_scheduler.html` (§3).
4. **Add `extra_options`** (a list of field names) if the job needs
   parameters beyond its target (e.g. a boolean, a config id) — render them
   as plain form fields keyed off that list; no schema language, just a
   small `{field_name: {type, label, default}}` lookup next to `TASK_TYPES`.
5. **No migration needed.** `TASK_TYPES` is pure Python — restarting the app
   (or the debug auto-reloader) is enough to see the new type in the
   dropdown.
6. **Test with "Run now" first** (§3.2) — simplest path, skips recurrence
   entirely; confirm the job appears correctly in `/jobs/list` with the
   right payload before wiring up an actual recurring schedule.

Steps 3-6 are the ONLY ones a self-hoster adding, say, their own custom
bulk-tagging job needs to do — nothing in `scheduler_engine.py`,
`task_scheduler.html`'s generic list/table, or the dependency engine (§4,
§4bis) ever needs to change for a new task type.

## 3. Creation/edit form — generalizing the existing modal

Reuses the `syncScheduleModal` from `manage_github.html` as-is in structure,
with 3 changes:

1. **New: task type selector**, at the top of the form (before everything
   else):
   ```html
   <select class="rl-fp-select" v-model="taskForm.task_type" @change="onTaskTypeChange">
       <option v-for="(t, key) in taskTypes" :key="key" :value="key">[[ t.label ]]</option>
   </select>
   ```
   `taskTypes` comes from a new route `GET /admin/tasks/types` that
   serializes the §2 registry (label/icon/target_picker only — not the
   Python lambdas).

2. **Extended `ScheduleRecurrencePicker`** with one more radio mode at the
   top of its template: ⚪ Now ⚪ Once, at a specific date ⚪ Recurring ⚪
   After another task. New optional props `:allow-once="true"` and
   `:allow-after-task="true"` (the component stays usable elsewhere without
   these two modes if not needed):
   - "Now" → not a schedule at all, calls `POST /jobs/create` directly, the
     same way `bulk_tag.html`/`rule_quality_score.html` already do — no
     `AdminTaskSchedule` row is created.
   - "Once, at a date" → `trigger_mode='once'`, a new
     `<input type="datetime-local">` in the picker, emits `run_once_at`.
   - "Recurring" → daily/weekly/monthly/cron, strictly identical to what
     exists today.
   - "After another task" → a multi-select listing active
     `AdminTaskSchedule` rows (new route `GET /admin/tasks/list?picker=true`,
     a lightweight id+title response), one row per chosen parent, each with
     its own "if it succeeds" / "if it fails" / "no matter what" choice
     (`condition`: `success` / `failure` / `always`) — this 3-way choice,
     not just 2, is what enables the branching described in §4. Plus a
     radio "ALL of these conditions must hold" / "ANY ONE is enough" for
     `dependency_logic` (§4bis). `trigger_mode='after_task'`.

3. **Dynamic `target_picker`**: replaces the fixed "Repositories" area of
   the current modal with a `<component :is="targetPickerComponent">` where
   `targetPickerComponent` maps `target_picker` → the real component:
   - `'rule_list_select'` → `<rule-list mode="select" fetch-url="/rule/data_table" :show-export="false" @send="onTargetChange">`
     (exactly the pattern already written in `rule_quality_score.html` —
     copy the `submitQualityAnalysis`/`<rule-list mode="select">` block).
   - `'repo_selection_table'` → `<repo-selection-table>` (already exists, reused as-is).
   - `'repo_url_list'` → a plain multi-line textarea (one URL per line), for
     imports (no need for a complex picker, these are repos we don't have yet).
   - `'format_filter_only'` → a plain `<select>` of formats.
   - `'connector_select'` (new, §2bis) → a plain `<select>` listing existing
     `Connector` rows (label + active status + an "Official" badge for
     `is_system` connectors), single selection — `connector_pull` only
     takes one `connector_id`, not a batch.
   - `'none'` (new, §2bis) → nothing to render, the job takes no target at
     all (`update_misp_data`, `db_backup`, `update_attack_data`, etc. all
     run on payload `{}`). The form skips straight to the scheduling part (§3.2).

## 4. Engine — dependencies between tasks (the real new part)

The generalized `scheduler_engine.py` keeps `build_trigger()`/
`register_schedule()`/`unregister_schedule()`/`start_scheduler()`
**unchanged in principle**, only adapted to read `AdminTaskSchedule` and
handle the new `trigger_mode`:

```python
def build_trigger(schedule):
    tz = schedule.timezone or "UTC"
    if schedule.trigger_mode == 'once':
        from apscheduler.triggers.date import DateTrigger
        return DateTrigger(run_date=schedule.run_once_at, timezone=tz)
    if schedule.trigger_mode == 'after_task':
        return None   # no APScheduler trigger — fired by chaining, see below
    # 'daily' / 'weekly' / 'monthly' / 'cron': identical to the existing code
    ...

def register_schedule(app, schedule):
    if schedule.trigger_mode == 'after_task':
        return   # nothing to register in APScheduler — no next_run_at either
    ...  # identical to the existing code for the other modes
```

**Chained triggering** — when an `AdminTaskRun` finishes, other schedules
that depend on it need to be checked and fired. Two options considered:

- **(a) Periodic polling** (one more thread, like APScheduler) that checks
  recently finished runs. Easy to isolate, but adds a delay (the poll
  interval) and one more thread to maintain.
- **(b) A direct hook in `job_worker.py`**, right after a job flips to
  `done`/`failed` (`job_worker.py` already sets the status in exactly one
  central place). Recommended: immediate, no extra thread, and
  `job_worker.py` is already THE mandatory choke point for every job
  regardless of its `job_type`.

  ```python
  # in job_worker.py, right after marking job.status = 'done'/'failed'
  try:
      from app.features.admin.task_scheduler.scheduler_engine import on_job_finished
      on_job_finished(job)
  except Exception as e:
      print(f"[task_scheduler] on_job_finished error: {e}")
  ```

  `on_job_finished(job)`: looks up the `AdminTaskRun` for this `job_uuid`,
  updates its `status`/`finished_at`, then checks every candidate dependent
  schedule via `_dependencies_satisfied()` (the real implementation,
  supporting multiple parents and AND/OR, lives in §4bis — this is the only
  function `on_job_finished` needs to call):
  ```python
  def on_job_finished(job):
      run = AdminTaskRun.query.filter_by(job_uuid=job.uuid).first()
      if not run:
          return  # this job wasn't launched via an AdminTaskSchedule (e.g. a manual bulk_tag) — nothing to do
      run.status = 'done' if job.status == 'done' else 'failed'
      run.finished_at = datetime.datetime.utcnow()
      _handle_retry_and_circuit_breaker(run)   # §9bis — may turn this into a retry instead of a final failure
      run.schedule.last_run_at = run.finished_at
      db.session.commit()

      candidates = AdminTaskSchedule.query.filter_by(trigger_mode='after_task', is_active=True).all()
      for candidate in candidates:
          if run.schedule_id not in [d.depends_on_schedule_id for d in candidate.dependencies]:
              continue  # not affected by this particular run
          if _dependencies_satisfied(candidate):   # §4bis
              _fire_schedule(current_app._get_current_object(), candidate.uuid)
  ```

  **Success/failure branching pipeline** — since several `AdminTaskSchedule`
  rows can point at the same parent task with different `condition` values
  in their `AdminTaskDependency` edge, real branching falls out for free:
  e.g. "GitHub Sync" (A) → on success, fires "Quality Score" (B, edge
  `condition='success'`) → on failure, fires a "notify admins" task (C,
  edge `condition='failure'`, see §9 for the `notify_admins` job_type to
  write if none exists yet — though §9bis's built-in email alerts already
  cover the common case without needing a dedicated task). This is exactly
  the "wait for this job to finish… if it goes well I do X, otherwise I do
  Y" behavior asked for — modeled on how `update_loading.html` already
  chains its own steps (update → new rules) but generalized to ANY pair of
  tasks in the registry, not just GitHub sync.

  **Mandatory cycle guard**: when creating/editing a schedule in
  `after_task` mode, validate server-side that no cycle is introduced (A
  depends on B which depends on A) — walk the dependency graph before
  `commit()`, reject with a clear error otherwise (same spirit as the
  existing `_validate_recurrence()`).

  This function lives in its own module (not inside `job_worker.py` itself)
  so `job_worker.py` stays a thin call site — keeps the central jobs file
  lean and not coupled to the "task scheduler" domain.

`_fire_schedule` generalized (replaces the one in `scheduler_engine.py`):

```python
def _fire_schedule(app, schedule_uuid):
    with app.app_context():
        schedule = AdminTaskSchedule.query.filter_by(uuid=schedule_uuid, is_active=True).first()
        if not schedule:
            return
        task_def = TASK_TYPES.get(schedule.task_type)
        if not task_def:
            return

        if _is_already_running(schedule):     # §9bis — concurrency guard
            _record_skipped_run(schedule)
            return

        run = AdminTaskRun(uuid=str(uuid.uuid4()), schedule_id=schedule.id, status='pending')
        db.session.add(run)
        db.session.flush()

        job = create_job(
            job_type=task_def['job_type'],
            payload=schedule.target_payload,          # already in the shape the handler expects
            label=f"{schedule.title} — {task_def['label']}",
            created_by=schedule.editor_id,
        )
        run.job_uuid = job.uuid
        db.session.commit()
```

Key point: **the `BackgroundJob` payload is directly `schedule.target_payload`**
— no per-type translation in the generic engine. That's why `target_payload`
must be stored in exactly the shape the corresponding `job_type` already
expects (e.g. for `compute_rule_quality_score`, `{filters: {...}}` — that
shape already exists, see `rule_quality_score.html`).

## 4bis. Multiple dependencies (AND / OR) — the genuinely tricky part

A real pipeline often needs "wait for both A AND B to finish", not just a
linear chain A→B→C. Hence `AdminTaskDependency` (§1, one row per edge)
rather than a plain FK, and `AdminTaskSchedule.dependency_logic`
(`'all'` = AND, `'any'` = OR).

**The trap to avoid at all costs**: if the check is simply "do ALL parents
have a last run that satisfies their condition?" every time A SINGLE parent
finishes, a 3-week-old run of A can "satisfy" its condition forever and
make B fire repeatedly every time B's other parent (C) finishes — even
though A hasn't run in 3 weeks. A **freshness** check is required: a
parent's run only counts if it's more recent than this dependent task's own
last firing.

```python
def _dependencies_satisfied(schedule: AdminTaskSchedule) -> bool:
    """Called from on_job_finished() for EACH candidate dependent schedule."""
    results = []
    for dep in schedule.dependencies:  # AdminTaskDependency rows
        last_run = (AdminTaskRun.query
            .filter_by(schedule_id=dep.depends_on_schedule_id)
            .filter(AdminTaskRun.status.in_(('done', 'failed')))
            .order_by(AdminTaskRun.finished_at.desc())
            .first())
        if not last_run:
            results.append(False)
            continue
        # Freshness: this parent run must be newer than this task's own
        # last firing — otherwise a stale run would satisfy the condition
        # forever (the bug described above).
        is_fresh = schedule.last_run_at is None or last_run.finished_at > schedule.last_run_at
        condition_met = (
            dep.condition == 'always' or
            (dep.condition == 'success' and last_run.status == 'done') or
            (dep.condition == 'failure' and last_run.status == 'failed')
        )
        results.append(is_fresh and condition_met)

    return all(results) if schedule.dependency_logic == 'all' else any(results)
```

**UI**: in the modal (§3.2, "After another task" mode), the parent selector
becomes multi-select (one row per chosen parent, each with its own
success/failure/always choice), plus a radio "ALL of these conditions must
hold" / "ANY ONE is enough" for `dependency_logic`.

## 5. Routes (new blueprint `admin_task_scheduler_blueprint`, `/admin/tasks`)

Same pattern as `sync_schedule_routes.py`, generalized:

- `GET /admin/tasks/types` — serializes the §2 registry.
- `GET /admin/tasks/list` — pagination/search/sort (identical to
  `schedule_list`, additionally filterable by `task_type`).
- `GET /admin/tasks/picker` — lightweight `{id, uuid, title}` list to fill
  the "after which task(s)" multi-select in the form.
- `POST /admin/tasks/create`, `POST /admin/tasks/<uuid>/update`,
  `POST /admin/tasks/<uuid>/delete` — identical, plus cycle-guard validation
  (§4) when `trigger_mode == 'after_task'`.
- `POST /admin/tasks/bulk_delete`, `POST /admin/tasks/bulk_set_active` —
  identical.
- `POST /admin/tasks/<uuid>/run_now` — identical, reuses `_fire_schedule`.
- `GET /admin/tasks/run/<uuid>` — a run detail page, reuses `<job-tracker>`
  (§7) instead of the dedicated multi-repo report page (that one stays
  specific to GitHub sync via `sync_run_detail`, kept for that exact case —
  every other task type has only ONE `BackgroundJob` per run, not a
  multi-repo group, so `JobTracker` alone is enough).

## 6. UI — a full standalone admin section

New template `app/templates/admin/task_scheduler.html`, **not** a tab inside
`manage_github.html` (a standalone section was explicitly requested).
Structure identical to the CLAUDE.md style guide:

- Breadcrumb + `.explorer-banner` (icon `fa-solid fa-diagram-project` or
  `fa-solid fa-clock-rotate-left`).
- `dr-nav` row with `{{ anav.admin_nav_toggle() }}` — new "Task Scheduler"
  entry in `admin_nav.html` (the "System" section, next to "Jobs").
- KPI cards: active tasks, paused tasks, next scheduled run, recent
  failures, **tasks needing attention** (auto-disabled or currently in a
  failing streak — §9bis, so an admin sees it at a glance even without
  reading email).
- Task list — **near-verbatim copy** of the table/card block from
  `manage_github.html`'s "Sync Schedules" section (lines 508-658), with:
  - an extra "Type" column (registry icon + label) before "Frequency".
  - a "Depends on" column showing the parent task title(s) when
    `trigger_mode == 'after_task'`, otherwise "Frequency" as before.
  - a visual flag on rows where `auto_disabled_reason` is set.
  - the same per-row "Run now" button.
- Creation/edit modal — §3.
- **Dependency graph view**, using PivoTick — see §7bis (explicitly
  requested, part of v1, not deferred).

## 7. Execution tracking — reuse `JobTracker`, don't reinvent

A generic `AdminTaskSchedule` run has only one `BackgroundJob` (unlike
GitHub sync, which groups N repos): `<job-tracker :job-uuid="run.job_uuid">`
(already with AnsiTerminal, a slim progress bar, the "My Jobs" button — see
the work already done on `JobTracker.js`) is enough directly, no dedicated
report page needed. A task's run history (its list of `AdminTaskRun` rows)
shows in an expandable panel per row of the task list — the same
`<job-tracker>` component reused for the most recent run if still active.

## 7bis. Graph visualization — PivoTick

Verified by inspecting the real code (not an assumption): **PivoTick is not
a Vue component** — it's an independent force-directed graph engine, a real
standalone TypeScript submodule (`app/modules/pivotick/`, built into
`/static/js/pivotick.iife.js`, exposed as the global `window.Pivotick`). The
`/admin/pivotick` page (`pivotick.py`, `pivotick_core.py`) is NOT the
visualization itself — it's a **style editor** (colors/shapes/icons per
node/edge type), stored in `PivotickGraphStyle` (one row per `graph_type`,
columns `id`, `graph_type` (String(20), unique), `config` (JSON, NULL =
default style), `updated_at`, `updated_by`).

Today only 2-3 `graph_type` values exist, hardcoded server-side
(`GRAPH_TYPES` in `pivotick_core.py`): `'rule'`, `'bundle'`, `'attack'`.
`save_style_config`/`get_style_config` **reject** any `graph_type` not on
that list — `'task_schedule'` will need to be added to it.

The engine itself knows nothing about MISP or rules — it just takes:
```js
{
  nodes: [{ id, data: { label, sublabel, type, raw } }],
  edges: [{ from, to, data: { label, type } }],
}
```
where `type` (on both nodes and edges) is the key that maps into the
current `graph_type`'s style config (e.g. for `'rule'`: node types
`bundle`, `metadata`, `rule`, `tag`, `attack`, `vulnerability`; edge types
`contains`, `related-to`, `tagged`). The current wrapper `initBundleGraph()`
(`app/static/js/bundle/bundleMispGraph.js`) is **tightly coupled to MISP
JSON** (`parseMispBundle`) — not reusable as-is, but that's not a problem:
our case is simpler (no MISP to parse), we build `{nodes, edges}` directly
from `AdminTaskSchedule` rows.

**Integration plan**:

1. `pivotick_core.py`: add `'task_schedule'` to `GRAPH_TYPES`, with a simple
   default style — one node type per `task_type` in the registry (§2), a
   single `depends_on` edge type (neutral color, arrow pointing in the
   trigger direction: parent → dependent).
2. New small JS wrapper `app/static/js/admin/taskScheduleGraph.js`
   (parallel to `initBundleGraph`, but with no MISP parsing):
   ```js
   export function initTaskScheduleGraph(containerId, schedules, opts) {
       const nodes = schedules.map(s => ({
           id: s.uuid,
           data: { label: s.title, sublabel: TASK_TYPES[s.task_type]?.label, type: s.task_type, raw: s },
       }));
       const edges = schedules.flatMap(s =>
           (s.dependencies || []).map(dep => ({
               from: dep.depends_on_schedule_uuid,
               to:   s.uuid,
               data: { label: dep.condition, type: 'depends_on' },
           }))
       );
       // reuses fetchPivotickStyle/buildNodeStyleMap/edgeStyleFor/isDarkMode
       // from app/static/js/pivotick/pivotickStyle.js as-is — same logic as
       // bundleMispGraph.js, just without the MISP-parsing step.
       return new window.Pivotick(document.getElementById(containerId), { nodes, edges }, opts);
   }
   ```
3. In `task_scheduler.html`: a "Graph view" panel (toggled against the table
   view, the same pattern as the existing table/card switch in
   `manage_github.html`) calling `initTaskScheduleGraph('task-graph',
   allSchedules, { graphType: 'task_schedule' })` — `allSchedules` comes
   straight from the already-loaded `GET /admin/tasks/list` response (add
   `dependencies` — schedule_id/uuid + condition — to its serialization), no
   new route needed.
4. Clicking a node in the graph opens that task's edit modal (the same
   `onclick` as clicking its table row) — keeps both views consistent.

Since the engine is already loaded elsewhere in the app (rule/bundle detail
pages), no new third-party script needs to be added to the bundle — just
`<script src="/static/js/pivotick.iife.js">` in `task_scheduler.html`'s
`{% block head %}` if it isn't already global via `base.html` (to verify at
implementation time).

## 8. Migrating the existing Sync Schedule

Two options, to be decided at implementation time (out of scope for this
document, which only maps things out):

- **(a) Coexistence**: `GithubSyncSchedule` stays as-is (specific, with its
  rich multi-repo report page), the new generic system handles all OTHER
  task types. GitHub sync keeps its own tab in `manage_github.html`. Zero
  migration, zero risk, but two scheduling systems running in parallel.
- **(b) Absorption**: `github_sync` becomes a registry entry like the
  others (§2), `GithubSyncSchedule*` is migrated into `AdminTaskSchedule`
  (a data migration script), the multi-repo report page becomes a special
  case of `/admin/tasks/run/<uuid>` (the only `task_type` that genuinely
  needs a custom detail view rather than `<job-tracker>` alone).

Recommendation: start with (a) — ship the generic system for NEW task types
first, migrate GitHub sync later once the new system has proven itself in
production.

## 9. Prerequisite work per task type (before adding it to the registry)

The §2 registry can only reference a `job_type` that already exists in
`job_handlers.py`. Current state:

| Task type | `job_type` exists? | Prerequisite work |
|---|---|---|
| Quality Score | ✅ `compute_rule_quality_score` | None — ready to integrate as-is. |
| Field Parser | ✅ `bulk_parse_fields` | None. |
| ATT&CK Auto-parse | ✅ `bulk_parse_attack_rules` | None. |
| GitHub Sync | ✅ `github_sync_schedule_run` | None (already the existing system). |
| MISP — Update data | ✅ `update_misp_data` | None. |
| MISP — Import taxonomies | ✅ `import_all_taxonomies` | None. |
| MISP — Import galaxies | ✅ `import_all_galaxies` | None. |
| ATT&CK — Update MITRE data | ✅ `update_attack_data` | None. |
| Database Backup | ✅ `db_backup` | None. |
| Rule Validation | ✅ `rule_validation_run` | None. |
| Bulk Platform Tagging | ✅ `bulk_tag_platforms` | None. |
| Activity Log Purge | ✅ `delete_activity_logs` | None on the job side — but this handler is **orphaned** today (no UI calls it): this will be its very first interface, so test the `{log_ids/delete_all, action_filter}` payload manually before exposing it to an unsupervised cron. |
| Connector Pull | ✅ `connector_pull` | None. |
| **Similarity** | ❌ | `Similarity_class` (`app/features/rule/utils/similar_rules/similarity_class.py`) runs on its **own home-grown thread** (`.start()`), not through the `BackgroundJob` system. A new handler `@register_handler('similarity_scan_run')` needs to call `Similarity_class`'s logic synchronously inside the `job_worker.py` thread (the same refactor already done for `Session_class.run_sync()`, next row) — **before** it can be scheduled. |
| **GitHub Import** | ❌ (partially) | `Session_class` already has a `run_sync()` method documented "for use inside a BackgroundJob" (`session_class.py:221`) — but no `@register_handler` calls it today. This handler (`github_import_run`) needs to be written before imports can be scheduled. |
| **Notify Admins** (failure branch, §4) | ❌ | Doesn't exist as a job yet — only needed for an explicit "on failure → notify" pipeline task. Not blocking: write it only when that specific use case is wanted (would reuse `notification_core.py`, already used everywhere else in the app to notify admins). The built-in email alerts (§9bis) already cover the common case without needing a dedicated task for it. |

This table should be updated every time a task type is added to the registry.

**Deliberately excluded from the registry** (see §2bis for the full detail):
anything that depends on a precise one-off context rather than a
re-selectable target on every run (`bulk_update_decision`,
`github_proposal_bulk_import`, `blog_from_cve`, `rule_test_bulk`,
`velociraptor_push`, `misp_push`, `ownership_transfer_bulk`...), and
anything touching the app's own infrastructure without direct human
supervision (`update_package`, `uninstall_package`, `update_submodule_bg`,
`remove_submodule`). Adding one of these to the registry later is still
possible but requires re-checking, case by case, that "reschedulable without
human context" actually makes sense for it.

## 9bis. Robustness & maximum autonomy

The point of this section: an admin should get told when something needs
attention, instead of having to go check. Everything here is designed to be
optional per schedule (sane defaults, nothing forces the admin to configure
it) but available when the goal is "set it and forget it".

### Retry policy

`retry_count` (extra attempts beyond the first) / `retry_delay_minutes` on
`AdminTaskSchedule`. In `on_job_finished`, before treating a failure as
final:

```python
def _handle_retry_and_circuit_breaker(run):
    schedule = run.schedule
    if run.status == 'failed' and run.retry_attempt < schedule.retry_count:
        # Not a final failure yet — schedule a one-off retry and stop here;
        # this attempt does NOT count toward consecutive_failures, does NOT
        # fire dependents, and does NOT send a failure email.
        retry_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=schedule.retry_delay_minutes)
        _schedule_one_off_retry(schedule, run.retry_attempt + 1, retry_at)
        run.status = 'retry_scheduled'
        return

    if run.status == 'failed':
        schedule.consecutive_failures += 1
        if schedule.max_consecutive_failures and schedule.consecutive_failures >= schedule.max_consecutive_failures:
            schedule.is_active = False
            schedule.auto_disabled_reason = (
                f"Auto-disabled after {schedule.consecutive_failures} consecutive failures "
                f"(last: {datetime.datetime.utcnow():%Y-%m-%d %H:%M} UTC)"
            )
            send_task_alert_email(schedule, run, kind='auto_disabled')   # always sent, ignores notify_on_failure
        elif schedule.notify_on_failure:
            send_task_alert_email(schedule, run, kind='failure')
    else:
        schedule.consecutive_failures = 0
        schedule.auto_disabled_reason = None
        if schedule.notify_on_success:
            send_task_alert_email(schedule, run, kind='success')
```

### Cooperative timeout (be honest about the limitation)

`timeout_minutes` (NULL = disabled). **True preemptive killing of a Python
thread is not safely possible** — handlers can only be interrupted at
points where they already check for cancellation. The existing
`_is_cancelled(job)`/`_should_pause(job)` pattern (already used by every
batch-loop handler for pause/cancel) is exactly that cooperative checkpoint,
so a timeout watchdog reuses it rather than inventing a new mechanism:

- A lightweight recurring check (piggybacks on the existing APScheduler
  thread, e.g. every 60s — no new thread) scans `BackgroundJob` rows with
  `status='running'` whose `started_at` is older than their schedule's
  `timeout_minutes`, and marks them `status='cancelled'`, `error='Timed out
  after N minutes'`.
- This only actually stops a handler that periodically checks
  `_is_cancelled()` in a loop — which is true for every batch/bulk handler
  in `job_handlers.py` today. A handler doing one single long blocking call
  (e.g. a `subprocess` inside `db_backup`) can't be interrupted this way and
  will keep running until that call returns; document this explicitly in
  the UI tooltip on the timeout field so it isn't assumed to be a hard kill.

### Concurrency guard

`concurrency_policy` = `'skip'` (v1) | `'queue'` (documented, not
implemented in v1 — true queuing needs either APScheduler's own misfire
handling or a small poll loop; defer until a real use case shows up).
`'skip'`: before `_fire_schedule` creates a `BackgroundJob`, check for an
existing `AdminTaskRun` on this `schedule_id` with `status in ('pending',
'running')`; if found, create an `AdminTaskRun` with `status='skipped'`
instead (visible in the run history, so a schedule that keeps
self-overlapping is easy to notice) and return without creating a job.

### Circuit breaker (auto-disable)

Covered above inside `_handle_retry_and_circuit_breaker` — `is_active` is
flipped to `False` and `auto_disabled_reason` is filled in once
`consecutive_failures` reaches `max_consecutive_failures` (default 5, NULL/0
= never auto-disable). The reason string is shown directly in the task list
(§6) so re-enabling it is an informed decision, not a guess. The
auto-disabled alert **always** sends regardless of `notify_on_failure` —
going silent forever is strictly worse than one extra email.

### Email alerts — per-schedule opt-in

New fields already in the model (§1): `notify_on_failure` (default `True`),
`notify_on_success` (default `False`), `notify_emails` (extra recipients on
top of `schedule.editor.email` — the admin who created the schedule always
gets it unless they explicitly remove themselves from `notify_emails`, but
there is no separate "off" switch for the editor's own address beyond
turning off `notify_on_failure` itself).

Reuses the app's real, already-working mail pattern rather than inventing a
new one — confirmed in `app/features/account/account_core.py:100-144`
(`Message(subject, sender=..., recipients=[...])`, inline HTML body,
`mail.send(msg)`, using the existing `mail` object from `app/__init__.py`
and the `MAIL_SERVER`/`MAIL_PORT` config already in `.env`):

```python
# new file: app/features/admin/task_scheduler/notifications.py
from flask_mail import Message
from app import mail

def send_task_alert_email(schedule, run, kind):
    # kind: 'failure' | 'success' | 'auto_disabled'
    recipients = [schedule.editor.email] + (schedule.notify_emails or [])
    subject = {
        'failure':       f"[Rulezet] Task '{schedule.title}' failed",
        'success':       f"[Rulezet] Task '{schedule.title}' completed",
        'auto_disabled': f"🔴 [Rulezet] Task '{schedule.title}' auto-disabled",
    }[kind]
    msg = Message(subject, recipients=recipients)
    msg.html = f"""...same inline-HTML card style as account_core.py's
        verification email, summarizing: task type, when it ran, the run's
        error message if any, a link to /admin/tasks..."""
    mail.send(msg)
```

**UI**: a new "Notifications" subsection in the creation/edit modal (§3),
two checkboxes ("Email me on failure" / "Email me on success") plus a
simple comma-separated input for extra recipient addresses.

### Missed-run / catch-up policy

`on_missed_run` maps directly onto APScheduler's own existing
`misfire_grace_time`/`coalesce` job kwargs — no custom logic to invent:
- `'skip_to_next'` (default): small `misfire_grace_time` + `coalesce=True`
  — if the server was down when a run was due, skip it and wait for the
  next normally-scheduled occurrence.
- `'run_immediately'`: a very large (or `None`, unlimited) `misfire_grace_time`
  — a run that was due while the server was down still fires as soon as it
  comes back up. Appropriate for things like `db_backup` where missing a
  night entirely is worse than running late; inappropriate for something
  like `rule_validation_run` where a late run overlapping the next
  regularly-scheduled one could be confusing (hence `skip_to_next` as the
  safer default).

## 9ter. End-user documentation

The user asked for this feature to have write-up documentation "like for
Connectors and everything" — Rulezet's docs are **not** per-feature pages;
they live as numbered chapters inside a single page,
`app/templates/docs/full_documentation.html` (sidebar link + TOC entry +
`<h2 class="section-title" id="chXX-title">` + a short feature-card blurb —
Connectors is chapter 22, confirmed at `full_documentation.html:82,201,1115,1596`).
The file currently runs through chapter 31 ("Conventions to Respect", a
wrap-up/meta chapter — `full_documentation.html:99`).

At implementation time, add a new chapter following that exact same
structure, covering: what the Task Scheduler is, how to create a scheduled
task (with a screenshot-style walkthrough matching the doc's existing
tone), the "run now vs. schedule" choice, how dependencies/branching work
with a concrete example, and what the notification settings do. Two
placement options:
- **Safer**: append it as a new chapter 32, right before "Conventions to
  Respect" stays last — no existing chapter numbers/anchors need to change.
- **More logical ordering**: insert it right after chapter 28 ("Background
  Job Engine", since Task Scheduler builds directly on it), renumbering 29→30,
  30→31, 31→32 — more editing, only worth it if chapter ordering genuinely
  matters to readers browsing sequentially.

## 10. Verification (once implemented)

1. Create a "Quality Score" task in "Recurring → Weekly → Monday 03:00"
   mode; verify it shows up with the right `next_run_at`, and that `flask
   db upgrade` + a server restart doesn't lose it (the principle is already
   guaranteed by `start_scheduler()` — same test as for the existing Sync
   Schedule).
2. Create a "Field Parser" task in "After another task" mode pointing at
   the task above; run the first one manually (`run_now`); verify the
   second fires automatically when the first finishes (check that the
   second `AdminTaskRun.started_at` ≈ right after the first's
   `finished_at`).
3. Try to create a cycle (A depends on B, B depends on A); verify the
   server-side validation rejects it with a clear error.
4. Create a task in "Once, at a date" mode 2 minutes out; verify it fires
   at the right time and then no longer shows as "active"
   (`trigger_mode='once'` must not re-fire).
5. Verify that "Run now" (no schedule at all) creates a `BackgroundJob`
   visible in `/jobs/list` without creating a stray `AdminTaskSchedule` row.
6. Full `FLASKENV=testing pytest` run — confirm no existing GitHub Sync
   Schedule test breaks if option (a) coexistence is chosen.
7. Success/failure branching (§4): create task A, task B (dependency edge
   `condition='success'`) and task C (`condition='failure'`), both pointing
   at A. Run A against a target that fails on purpose; verify C fires and B
   does not. Re-run A against a valid target; verify the reverse.
8. Multiple dependencies AND/OR (§4bis): create task D depending on BOTH B
   and C with `dependency_logic='all'`; verify D only fires once both have
   a fresh matching run, not after just one of them. Switch to `'any'`;
   verify D fires after either one alone.
9. Graph view (§7bis): with the pipeline from points 7-8 in place, open the
   graph view and verify all schedules appear with correctly labeled edges;
   clicking node B opens its edit modal.
10. Retry + circuit breaker (§9bis): set `retry_count=2` on a task, point it
    at a target that always fails; verify two retries happen (spaced by
    `retry_delay_minutes`) before it's counted as a final failure. Set
    `max_consecutive_failures=2` and let it fail twice more (across
    separate scheduled runs, not retries); verify `is_active` flips to
    `False` with a readable `auto_disabled_reason`, and that an email fires
    even if `notify_on_failure` was turned off for that schedule.
11. Concurrency guard (§9bis): manually trigger the same schedule twice in
    quick succession (before the first run finishes); verify the second
    creates an `AdminTaskRun` with `status='skipped'` rather than a second
    overlapping `BackgroundJob`.
12. Email alerts (§9bis): with `notify_on_success=True` and a valid mail
    config, run a task successfully; verify an email actually lands in the
    editor's inbox (and any `notify_emails` addresses), with a working link
    back to `/admin/tasks`.

## 11. Recommended implementation roadmap (phasing)

Everything above is the full target design. Building all of it in one pass
is not recommended: the robustness features (§9bis) and the multi-parent
dependency graph (§4bis) are exactly the kind of code whose bugs only show
up once real schedules interact with each other in production — writing
them before that feedback exists means testing against guesses instead of
real failure modes. Ship in three phases instead, each one a usable,
mergeable increment on its own.

### Phase 1 — MVP: generalized scheduling, single linear dependency

This phase alone already unlocks the concrete, immediate value: Quality
Score, Field Parser, Similarity, MISP updates, ATT&CK updates, DB backup,
Activity Log purge, and Connector pulls all become schedulable.

- §1: `AdminTaskSchedule` and `AdminTaskRun` **only** — skip
  `AdminTaskDependency` for now (a single nullable
  `depends_on_schedule_id` + `depends_on_condition` column directly on
  `AdminTaskSchedule` is enough for a *linear* chain, exactly like the
  original single-parent design this doc started from). Skip every §9bis
  column too (`retry_count`, `timeout_minutes`, `concurrency_policy`,
  `max_consecutive_failures`, `consecutive_failures`, `auto_disabled_reason`,
  `notify_on_failure`, `notify_on_success`, `notify_emails`,
  `on_missed_run`) — add them in Phase 2 as a follow-up migration, not now.
- §2 + §2bis + §2ter: build the full registry as designed — this costs
  nothing extra and is the whole point of the architecture.
- §3: the form, but the "After another task" mode only offers **one**
  parent (single `<select>`, not the multi-select + AND/OR radio) and only
  the `success` / `failure` / `always` condition on that one parent.
- §4: `on_job_finished` checks the single `depends_on_schedule_id` directly
  (no `_dependencies_satisfied()` yet, no freshness guard needed since
  there's only ever one parent). Still add the cycle guard — trivial with
  one parent (walk up until `None` or a repeat) and cheap insurance.
- §5, §6, §7: routes, list/table UI, `<job-tracker>` reuse — as designed,
  no reduction (this is where most of the day-to-day value is visible).
- Skip §7bis (PivoTick graph) entirely for Phase 1 — a graph of straight
  chains with no branching is barely more readable than the table.
- §8: coexistence (option a) — do not touch `GithubSyncSchedule` yet.
- §10: run verification steps 1-6 only.

### Phase 2 — Robustness (§9bis), once Phase 1 has run for a while

Only start this once Phase 1 has been live long enough to have actually
observed a few real failures/timeouts — tune defaults
(`max_consecutive_failures`, `retry_delay_minutes`) against what really
happened, not guesses.

- Migration adding all the §9bis columns to `AdminTaskSchedule`.
- Implement retry, circuit breaker, concurrency guard, cooperative timeout,
  email alerts (`notifications.py`), missed-run policy — exactly as
  designed in §9bis.
- Add the "Notifications" subsection to the form (§3) and the
  "auto-disabled" visual flag to the task list (§6).
- §10: run verification steps 10-12.

### Phase 3 — Multi-parent AND/OR + PivoTick graph view

Only worth building once there are enough real chained schedules in use
that a linear-only chain is visibly limiting (e.g. someone actually asks
for "wait for both A and B").

- Migration: introduce `AdminTaskDependency`, migrate any existing
  `depends_on_schedule_id`/`depends_on_condition` rows into it as
  single-edge rows, then drop the two old columns.
- Implement `_dependencies_satisfied()` with the freshness guard (§4bis)
  and wire it into `on_job_finished` (§4), replacing the Phase 1 single-
  parent check.
- Extend the form's "After another task" mode to the full multi-select +
  AND/OR radio (§3).
- Build §7bis (PivoTick graph view) — this is the phase where a graph
  genuinely earns its place over a table, once branching exists.
- §9ter (docs chapter 32): write this once the feature is stable enough
  that the walkthrough won't need rewriting a week later — realistically
  end of Phase 2 or during Phase 3, not Phase 1.
- §10: run verification steps 7-9.

Each phase should land as its own PR/migration, and each is fully usable
and testable on its own — nothing in Phase 1 needs to be reworked to add
Phase 2 or 3, only extended (the single-parent columns are the one
exception, deliberately migrated away in Phase 3 rather than kept
alongside `AdminTaskDependency` forever).
