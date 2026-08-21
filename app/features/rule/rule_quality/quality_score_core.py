"""
quality_score_core.py — objective per-rule quality scoring.

Deliberately separate from votes/favorites/comments ("engagement"): a rule's
quality_score answers "is this well documented, traceable and valid?"
regardless of how popular it is. Engagement is folded in only as a capped
bonus on top, never mixed into the base score, so filtering/sorting by
quality_score alone finds "well-formed but unpopular" and "popular but
undocumented" rules correctly.

quality_score is NULL until a rule has actually been analyzed (either via a
write-time hook or the 'compute_rule_quality_score' background job) — distinct
from a real low score of 0.
"""
import datetime
import math
from typing import Any, Dict, Tuple

from app import db
from app.core.db_class.db import RuleAttackAssociation, RuleUpdateHistory, RuleTagAssociation, Tag
from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import RuleType, load_all_rule_formats

_PLACEHOLDER_VALUES = {"", "unknown", "n/a", "none", "null", "no description provided"}
_DEFAULT_TAG_PREFIXES = ("tlp:", "pap:")

# ATT&CK mapping is idiomatic for these formats on this platform; scoring it
# as a missing criterion for e.g. YARA would unfairly penalize a format that
# was never expected to carry ATT&CK tags in the first place.
_ATTACK_APPLICABLE_FORMATS = {"sigma", "suricata", "zeek", "wazuh"}

# A rule edited well after its own creation has had at least one real review
# pass. The two timestamps can differ by a few seconds/ms even on a rule
# that was never touched again (two separate now() calls at creation time),
# so a small threshold avoids counting that as "reviewed".
_FRESHNESS_THRESHOLD = datetime.timedelta(hours=1)


def _is_meaningful(value: Any) -> bool:
    if not value:
        return False
    return str(value).strip().lower() not in _PLACEHOLDER_VALUES


# Format string -> RuleType instance (or None for an unknown format). Building
# this involves load_all_rule_formats() (a pkgutil scan) plus instantiating
# every RuleType subclass just to read its .format — cheap once, but scoring
# thousands of rules called it fresh per rule, which measurably added up.
# Module-level so it also stays warm across job runs in the worker process.
_rule_type_instances: Dict[str, Any] = {}
_formats_loaded = False


def _get_rule_type_instance(rule_format: str):
    global _formats_loaded
    fmt = (rule_format or "").lower()
    if fmt in _rule_type_instances:
        return _rule_type_instances[fmt]
    if not _formats_loaded:
        load_all_rule_formats()
        _formats_loaded = True
    instance = None
    for subclass in RuleType.__subclasses__():
        candidate = subclass()
        if candidate.format.lower() == fmt:
            instance = candidate
            break
    _rule_type_instances[fmt] = instance
    return instance


def _weighted(checks: Dict[str, bool], weights: Dict[str, float]) -> Tuple[float, float]:
    earned = sum(weights[k] for k, v in checks.items() if v and k in weights)
    total = sum(weights.values())
    return earned, total


def _score_traceability(rule) -> Tuple[float, float, Dict[str, bool]]:
    checks = {
        "has_original_uuid": _is_meaningful(rule.original_uuid),
        "has_github_path": _is_meaningful(rule.github_path),
        "has_source": _is_meaningful(rule.source),
    }
    weights = {"has_original_uuid": 10, "has_github_path": 5, "has_source": 5}
    earned, total = _weighted(checks, weights)
    return earned, total, checks


def _meaningful_tag_count(rule_id: int) -> int:
    """Tags beyond the auto-attached tlp:/pap: defaults — a context-free query
    (no current_user dependency) so this is safe from background-job threads
    that have no request/session context, unlike get_tags_for_rule()."""
    names = [
        name for (name,) in db.session.query(Tag.name)
        .join(RuleTagAssociation, RuleTagAssociation.tag_id == Tag.id)
        .filter(RuleTagAssociation.rule_id == rule_id)
        .all()
    ]
    return sum(1 for n in names if not str(n).lower().startswith(_DEFAULT_TAG_PREFIXES))


def _score_documentation(rule) -> Tuple[float, float, Dict[str, bool]]:
    """Basic human-readable authorship info — separate from _score_metadata's
    structured triage fields (references, falsepositives, level, tags, ATT&CK)."""
    checks = {
        "has_description": _is_meaningful(rule.description) and len(str(rule.description).strip()) >= 30,
        "has_author": _is_meaningful(rule.author),
        "has_license": _is_meaningful(rule.license),
    }
    weights = {"has_description": 10, "has_author": 5, "has_license": 5}
    earned, total = _weighted(checks, weights)
    return earned, total, checks


def _score_metadata(rule, rule_type, batch_context=None) -> Tuple[float, float, Dict[str, bool]]:
    """Structured triage metadata — the fields a SOC analyst actually leans on
    at alert time (references, known false-positive scenarios, severity
    level, taxonomy tags, ATT&CK mapping), as opposed to _score_documentation's
    free-text authorship fields."""
    if batch_context is not None:
        has_tags = rule.id in batch_context["meaningful_tags"]
    else:
        has_tags = _meaningful_tag_count(rule.id) > 0

    checks: Dict[str, bool] = {"has_meaningful_tags": has_tags}
    weights: Dict[str, float] = {"has_meaningful_tags": 5}

    if (rule.format or "").lower() in _ATTACK_APPLICABLE_FORMATS:
        if batch_context is not None:
            has_attack = rule.id in batch_context["has_attack"]
        else:
            has_attack = db.session.query(RuleAttackAssociation.id).filter_by(rule_id=rule.id).first() is not None
        checks["has_attack_mapping"] = has_attack
        weights["has_attack_mapping"] = 5

    earned, total = _weighted(checks, weights)

    # Per-format metadata checklist (references, falsepositives, level, meta
    # block richness, ...) — averaged into a single 10pt bucket so a format
    # with 4 signals and one with 2 both max out at 10, not 40/20.
    format_signals: Dict[str, bool] = {}
    if rule_type is not None and rule.to_string:
        try:
            format_signals = rule_type.documentation_signals(rule.to_string) or {}
        except Exception:
            format_signals = {}
    if format_signals:
        signal_ratio = sum(1 for v in format_signals.values() if v) / len(format_signals)
        earned += signal_ratio * 10
        total += 10
        checks.update({f"format:{k}": v for k, v in format_signals.items()})

    return earned, total, checks


def _score_validity(rule, rule_type, batch_context=None) -> Tuple[float, float, Dict[str, bool]]:
    is_valid = False
    if rule_type is not None and rule.to_string:
        try:
            is_valid = bool(rule_type.validate(rule.to_string).ok)
        except Exception:
            is_valid = False

    if batch_context is not None:
        no_pending_failure = rule.id not in batch_context["last_history_failed"]
    else:
        last_history = (
            RuleUpdateHistory.query
            .filter_by(rule_id=rule.id)
            .order_by(RuleUpdateHistory.analyzed_at.desc())
            .first()
        )
        no_pending_failure = not (last_history is not None and last_history.success is False)

    checks = {
        "passes_validation": is_valid,
        "no_pending_failed_update": no_pending_failure,
    }
    weights = {"passes_validation": 15, "no_pending_failed_update": 10}
    earned, total = _weighted(checks, weights)
    return earned, total, checks


def _score_freshness(rule) -> Tuple[float, float, Dict[str, bool]]:
    reviewed = bool(
        rule.creation_date and rule.last_modif
        and (rule.last_modif - rule.creation_date) > _FRESHNESS_THRESHOLD
    )
    checks = {"reviewed_since_creation": reviewed}
    earned = 15.0 if reviewed else 0.0
    return earned, 15.0, checks


def compute_engagement_boost(rule, batch_context=None) -> float:
    """Popularity signal, log-scaled and capped — a bonus on top of the base
    score, never a substitute for it (see module docstring)."""
    if batch_context is not None:
        favorites = batch_context["favorites"].get(rule.id, 0)
        comments = batch_context["comments"].get(rule.id, 0)
    else:
        favorites = rule.favorited_by_users_assocs.count()
        comments = rule.comments_rule.count()
    net_votes = max((rule.vote_up or 0) - (rule.vote_down or 0), 0)
    raw = math.log1p(favorites) * 3 + math.log1p(net_votes) * 2 + math.log1p(comments) * 1.5
    return round(min(raw, 10.0), 2)


def compute_quality_score(rule, batch_context=None) -> Tuple[float, Dict[str, Any]]:
    """Returns (base_score 0-100, breakdown dict). base_score is the objective
    documentation/traceability/validity signal — engagement is reported
    separately inside breakdown, never folded into base_score itself.

    batch_context (see build_batch_context()) replaces this rule's per-row
    tag/ATT&CK/history/favorite/comment queries with dict lookups — pass it
    when scoring many rules in one job run; leave it None for a single rule
    (the interactive write-time hooks), where a handful of queries is fine."""
    rule_type = _get_rule_type_instance(rule.format)

    trace_earned, trace_total, trace_checks = _score_traceability(rule)
    doc_earned, doc_total, doc_checks = _score_documentation(rule)
    meta_earned, meta_total, meta_checks = _score_metadata(rule, rule_type, batch_context)
    valid_earned, valid_total, valid_checks = _score_validity(rule, rule_type, batch_context)
    fresh_earned, fresh_total, fresh_checks = _score_freshness(rule)

    total_earned = trace_earned + doc_earned + meta_earned + valid_earned + fresh_earned
    total_possible = trace_total + doc_total + meta_total + valid_total + fresh_total
    base_score = round((total_earned / total_possible) * 100, 2) if total_possible else 0.0

    engagement_boost = compute_engagement_boost(rule, batch_context)

    breakdown = {
        "base_score": base_score,
        "engagement_boost": engagement_boost,
        "display_score": round(min(100.0, base_score + engagement_boost), 2),
        "categories": {
            "traceability":  {"earned": trace_earned, "total": trace_total, "checks": trace_checks},
            "authorship":    {"earned": doc_earned,   "total": doc_total,   "checks": doc_checks},
            "metadata":      {"earned": meta_earned,  "total": meta_total,  "checks": meta_checks},
            "validity":      {"earned": valid_earned, "total": valid_total, "checks": valid_checks},
            "freshness":     {"earned": fresh_earned, "total": fresh_total, "checks": fresh_checks},
        },
    }
    return base_score, breakdown


def recompute_rule_quality_score(rule, commit: bool = True, batch_context=None) -> float:
    """Call after any write that can change a rule's score (content edit,
    tag/ATT&CK/favorite/vote change, GitHub update acceptance, or in bulk from
    the 'compute_rule_quality_score' job). Isolated commit — never interferes
    with the caller's own transaction, same pattern as the github_path
    backfill in update_class.py."""
    score, breakdown = compute_quality_score(rule, batch_context=batch_context)
    rule.quality_score = score
    rule.quality_score_breakdown = breakdown
    rule.quality_score_computed_at = datetime.datetime.now(tz=datetime.timezone.utc)
    if commit:
        db.session.commit()
    return score


def build_batch_context(rule_ids) -> Dict[str, Dict[int, Any]]:
    """One query per signal for a whole batch of rule ids, instead of the
    ~5 queries per rule that compute_quality_score()/compute_engagement_boost()
    fall back to without a batch_context — that's what made the
    'compute_rule_quality_score' job slow (thousands of rules x 5 round trips
    each). Absence of a rule_id from a dict IS the correct "no tags / no
    ATT&CK / no history / no favorites / no comments" answer, not a
    not-yet-computed marker, so callers can use plain `in`/`.get(id, 0)`."""
    rule_ids = list(rule_ids)
    if not rule_ids:
        return {"meaningful_tags": {}, "has_attack": {}, "last_history_failed": {}, "favorites": {}, "comments": {}}

    from sqlalchemy import func
    from app.core.db_class.db import Comment, RuleFavoriteUser

    tag_rows = (
        db.session.query(RuleTagAssociation.rule_id, Tag.name)
        .join(Tag, RuleTagAssociation.tag_id == Tag.id)
        .filter(RuleTagAssociation.rule_id.in_(rule_ids))
        .all()
    )
    meaningful_tags = {}
    for rule_id, name in tag_rows:
        if not str(name).lower().startswith(_DEFAULT_TAG_PREFIXES):
            meaningful_tags[rule_id] = True

    attack_rows = (
        db.session.query(RuleAttackAssociation.rule_id)
        .filter(RuleAttackAssociation.rule_id.in_(rule_ids))
        .distinct()
        .all()
    )
    has_attack = {rid: True for (rid,) in attack_rows}

    # Ordered by (rule_id, analyzed_at desc): within each rule_id's run of
    # rows, the first one seen is its most recent — same result as the
    # per-rule "order by analyzed_at desc, take first" query, in one pass.
    history_rows = (
        db.session.query(RuleUpdateHistory.rule_id, RuleUpdateHistory.success)
        .filter(RuleUpdateHistory.rule_id.in_(rule_ids))
        .order_by(RuleUpdateHistory.rule_id, RuleUpdateHistory.analyzed_at.desc())
        .all()
    )
    last_history_failed = {}
    for rule_id, success in history_rows:
        if rule_id not in last_history_failed:
            last_history_failed[rule_id] = (success is False)
    last_history_failed = {rid: v for rid, v in last_history_failed.items() if v}

    favorites = dict(
        db.session.query(RuleFavoriteUser.rule_id, func.count(RuleFavoriteUser.id))
        .filter(RuleFavoriteUser.rule_id.in_(rule_ids))
        .group_by(RuleFavoriteUser.rule_id)
        .all()
    )

    comments = dict(
        db.session.query(Comment.rule_id, func.count(Comment.id))
        .filter(Comment.rule_id.in_(rule_ids))
        .group_by(Comment.rule_id)
        .all()
    )

    return {
        "meaningful_tags": meaningful_tags,
        "has_attack": has_attack,
        "last_history_failed": last_history_failed,
        "favorites": favorites,
        "comments": comments,
    }


def refresh_engagement_boost(rule, commit: bool = True) -> None:
    """Cheap counterpart to recompute_rule_quality_score() for high-frequency,
    engagement-only writes (vote up/down) that can never move the base score
    (votes aren't a scoring criterion, only a boost — see module docstring).
    Updates just the boost/display_score inside the existing breakdown
    without re-running validate()/documentation checks on every click.
    Falls back to a full recompute if the rule has never been analyzed yet
    (no breakdown to patch)."""
    if not rule.quality_score_breakdown or rule.quality_score is None:
        recompute_rule_quality_score(rule, commit=commit)
        return

    breakdown = dict(rule.quality_score_breakdown)
    breakdown["engagement_boost"] = compute_engagement_boost(rule)
    breakdown["display_score"] = round(min(100.0, rule.quality_score + breakdown["engagement_boost"]), 2)
    rule.quality_score_breakdown = breakdown
    rule.quality_score_computed_at = datetime.datetime.now(tz=datetime.timezone.utc)
    if commit:
        db.session.commit()
