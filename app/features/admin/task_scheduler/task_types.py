"""
task_types.py — registry of schedulable task types for the Admin Task
Scheduler (see docs/design/admin_task_scheduler.md). Adding a task type is
a matter of adding an entry here — never touch the generic engine
(scheduler_engine.py) or the admin UI's list/table. The job_type must
already exist as a @register_handler in job_handlers.py; this registry only
describes how the scheduling form should build its target_payload.

Phase 1 subset: only task types whose job handler already exists AND whose
payload shape is simple enough for a generic picker (§9 of the design doc
lists what's excluded and why — e.g. Similarity/GitHub Import need a new
handler first, Field Parser/Bulk Platform Tagging need a richer config
picker than any target_picker below covers yet). Extending this dict is the
whole point of the registry — see it as a starting set, not a ceiling.

target_picker values understood by task_scheduler.html:
    'rule_list_select'   — <rule-list mode="select"> picks target_payload.filters/rule_ids
    'format_filter_only' — a plain <select> of rule formats, payload {format}
    'connector_select'   — a plain <select> of Connector rows, payload {connector_id}
    'none'               — nothing to target, payload {}
"""

TASK_TYPES = {
    'quality_score': {
        'label': 'Rule Quality Score — (re)analyze',
        'icon': 'fa-solid fa-gauge-high',
        'job_type': 'compute_rule_quality_score',
        'target_picker': 'rule_list_select',
    },
    'attack_parser': {
        'label': 'ATT&CK Auto-parse',
        'icon': 'fa-solid fa-crosshairs',
        'job_type': 'bulk_parse_attack_rules',
        'target_picker': 'format_filter_only',
    },
    'misp_update_data': {
        'label': 'MISP — Update taxonomies & galaxies (imported only)',
        'icon': 'fa-solid fa-rotate',
        'job_type': 'update_misp_data',
        'target_picker': 'none',
    },
    'misp_import_all_taxonomies': {
        'label': 'MISP — Import all new taxonomies',
        'icon': 'fa-solid fa-tags',
        'job_type': 'import_all_taxonomies',
        'target_picker': 'none',
    },
    'misp_import_all_galaxies': {
        'label': 'MISP — Import all new galaxies',
        'icon': 'fa-solid fa-tags',
        'job_type': 'import_all_galaxies',
        'target_picker': 'none',
    },
    'attack_update_data': {
        'label': 'ATT&CK — Update MITRE data',
        'icon': 'fa-brands fa-github',
        'job_type': 'update_attack_data',
        'target_picker': 'none',
    },
    'db_backup': {
        'label': 'Database Backup',
        'icon': 'fa-solid fa-database',
        'job_type': 'db_backup',
        'target_picker': 'none',
    },
    'rule_validation_run': {
        'label': 'Rule Validation (false-positive gate)',
        'icon': 'fa-solid fa-shield-check',
        'job_type': 'rule_validation_run',
        'target_picker': 'none',
        'extra_options': [
            {'key': 'full', 'type': 'bool', 'label': 'Full scan (ignore last-sync date)', 'default': False},
        ],
    },
    'activity_log_purge': {
        'label': 'Activity Log — Purge old entries',
        'icon': 'fa-solid fa-broom',
        'job_type': 'delete_activity_logs',
        'target_picker': 'none',
        'extra_options': [
            {'key': 'action_filter', 'type': 'text', 'label': 'Only actions starting with (optional)', 'default': ''},
        ],
        # A scheduled purge always targets every matching entry — there is no
        # per-run manual log_ids selection like the ad-hoc admin action has.
        'fixed_payload': {'delete_all': True},
    },
    'connector_pull': {
        'label': 'Connector — Pull one federation source',
        'icon': 'fa-solid fa-plug',
        'job_type': 'connector_pull',
        'target_picker': 'connector_select',
    },
    'ai_rule_analysis': {
        'label': 'AI Rule Analysis — generate reports',
        'icon': 'fa-solid fa-robot',
        'job_type': 'ai_generate',
        'target_picker': 'rule_list_select',
        # This job runs in job_worker.py's background lane (see AI_00
        # FOUNDATION.md §8) and is deliberately bounded per invocation
        # (batch_size/max_seconds below) — scheduling it to recur (e.g.
        # nightly) is the intended way to run it, not a one-shot "ALL" pick.
        'fixed_payload': {'agent_key': 'rule_analysis'},
        'extra_options': [
            {'key': 'model', 'type': 'text', 'label': 'Ollama model (e.g. qwen2.5:7b) — blank uses the agent default', 'default': ''},
            {'key': 'batch_size', 'type': 'text', 'label': 'Rules per run', 'default': '50'},
            {'key': 'max_seconds', 'type': 'text', 'label': 'Max seconds per run', 'default': '900'},
            {'key': 'regenerate_existing', 'type': 'bool', 'label': 'Regenerate rules that already have an analysis', 'default': False},
            {'key': 'default_public', 'type': 'bool', 'label': 'Publish new reports immediately', 'default': True},
        ],
    },
}


def serialize_task_types():
    """JSON-safe view of the registry for GET /admin/tasks/types — drops
    nothing sensitive (there isn't any), just here so the route doesn't
    reach into TASK_TYPES' internals directly."""
    return {
        key: {
            'label': t['label'],
            'icon': t['icon'],
            'target_picker': t['target_picker'],
            'extra_options': t.get('extra_options', []),
        }
        for key, t in TASK_TYPES.items()
    }
