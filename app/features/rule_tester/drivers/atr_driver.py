"""
ATR (Agent Threat Rules) driver for the Rulezet rule tester.

ATR is an MIT-licensed YAML detection-rule standard for AI-agent threats
(prompt injection, tool poisoning, skill compromise, ...). Each rule has a
stable identifier ``ATR-YYYY-NNNNN`` and a ``detection.conditions`` block.

This driver mirrors the self-contained style of ``sigma_driver.py``:

* ``validate_syntax`` does its own lightweight structural/schema validation
  and never requires the engine to be installed, so authoring feedback works
  everywhere.
* ``run_test`` executes the rule against a single agent event using the
  upstream ``pyatr`` engine -- the same engine downstream ATR integrations
  use -- loaded lazily so the rest of the tester keeps working even when the
  optional dependency is absent.

Standard: https://github.com/Agent-Threat-Rule/agent-threat-rules
Engine:   https://pypi.org/project/pyatr/  (MIT)
"""
import json
import re
import time

from .base import BaseTesterDriver, ValidationResult, MatchDetail
from .registry import register_driver


# Canonical ATR rule-ID shape, e.g. ATR-2026-00001.
_ATR_ID_RE = re.compile(r"^ATR-\d{4}-\d{5}$")

# Required top-level fields per the ATR schema (spec/atr-schema.yaml). These
# mirror what the pyatr engine enforces, plus ``detection`` -- without which a
# rule cannot be executed.
_ATR_REQUIRED_FIELDS = (
    "id", "title", "description", "status", "author",
    "date", "severity", "tags", "agent_source", "detection", "response",
)

# Severity enum from the ATR schema.
_ATR_SEVERITIES = frozenset({"critical", "high", "medium", "low", "informational"})

# Operators the ATR engine understands. Unknown operators are a warning, not
# an error: the schema is additive and the engine is the final authority.
_ATR_KNOWN_OPERATORS = frozenset(
    {"regex", "contains", "equals", "startswith", "endswith",
     "gt", "lt", "gte", "lte", "in", "not_contains", "not_equals"}
)

# ATR matches carry a categorical confidence rather than a numeric score;
# map it onto the driver's 0.0-1.0 scale.
_CONFIDENCE_SCORE = {"high": 1.0, "medium": 0.66, "low": 0.33, "informational": 0.2}


@register_driver('atr')
class AtrDriver(BaseTesterDriver):
    format_name  = 'atr'
    display_name = 'ATR'
    input_types  = ['text', 'json']
    can_execute  = True

    def get_capabilities(self) -> dict:
        caps = super().get_capabilities()
        # Execution needs the optional pyatr engine; report honestly.
        caps['can_execute'] = _engine_available()
        return caps

    # ── syntax validation ────────────────────────────────────────────────
    def validate_syntax(self, rule_content: str) -> ValidationResult:
        if not rule_content.strip():
            return ValidationResult(valid=False, errors=['Empty rule content'])

        try:
            import yaml
            doc = yaml.safe_load(rule_content)
        except Exception as e:
            return ValidationResult(valid=False, errors=[f'YAML parse error: {e}'])

        if not isinstance(doc, dict):
            return ValidationResult(valid=False, errors=['ATR rule must be a YAML mapping'])

        errors: list = []
        warnings: list = []
        self._check_required_fields(doc, errors)
        self._check_identifiers(doc, errors)
        self._check_detection(doc, errors, warnings)
        self._check_agent_source(doc, warnings)
        self._engine_check(rule_content, errors, warnings)

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    def _check_required_fields(self, doc: dict, errors: list) -> None:
        for field_name in _ATR_REQUIRED_FIELDS:
            if field_name not in doc or doc[field_name] in (None, "", []):
                errors.append(f"Missing required field: '{field_name}'")

    def _check_identifiers(self, doc: dict, errors: list) -> None:
        rule_id = doc.get('id')
        if isinstance(rule_id, str) and not _ATR_ID_RE.match(rule_id):
            errors.append(
                f"Rule id '{rule_id}' does not match the ATR pattern ATR-YYYY-NNNNN"
            )
        severity = doc.get('severity')
        if severity is not None and severity not in _ATR_SEVERITIES:
            errors.append(f"severity '{severity}' is not one of {sorted(_ATR_SEVERITIES)}")

    def _check_detection(self, doc: dict, errors: list, warnings: list) -> None:
        detection = doc.get('detection')
        if not isinstance(detection, dict):
            return  # absence already reported by the required-field check
        conditions = detection.get('conditions')
        if not isinstance(conditions, list) or not conditions:
            errors.append("detection.conditions must be a non-empty list")
            return
        logic = detection.get('condition')
        if logic is not None and logic not in ('any', 'all', 'or', 'and'):
            warnings.append(f"detection.condition '{logic}' is unusual (expected any|all)")
        for idx, cond in enumerate(conditions):
            if not isinstance(cond, dict):
                errors.append(f"detection.conditions[{idx}] must be a mapping")
                continue
            for key in ('field', 'operator', 'value'):
                if key not in cond:
                    errors.append(f"detection.conditions[{idx}] missing '{key}'")
            operator = cond.get('operator')
            if operator is not None and operator not in _ATR_KNOWN_OPERATORS:
                warnings.append(
                    f"detection.conditions[{idx}] operator '{operator}' is not a known "
                    "ATR operator -- the engine may not support it"
                )
            if operator == 'regex':
                self._check_regex(cond.get('value'), idx, errors)

    def _check_regex(self, value, idx: int, errors: list) -> None:
        if not isinstance(value, str):
            return
        try:
            re.compile(value)
        except re.error as e:
            errors.append(f"detection.conditions[{idx}] has an invalid regex: {e}")

    def _check_agent_source(self, doc: dict, warnings: list) -> None:
        agent_source = doc.get('agent_source')
        if isinstance(agent_source, dict) and 'type' not in agent_source:
            warnings.append("agent_source.type is missing")

    def _engine_check(self, rule_content: str, errors: list, warnings: list) -> None:
        """Best-effort engine signal: warn if pyatr is absent, or if a rule
        that passed structural checks still will not load into the engine."""
        if not _engine_available():
            warnings.append(
                'pyatr not installed -- rule execution unavailable '
                '(pip install pyatr for full ATR testing).'
            )
            return
        if errors:
            return  # already invalid; no point probing the engine
        engine, load_errors = _build_engine(rule_content)
        if engine is None:
            reason = load_errors[0] if load_errors else 'unknown reason'
            warnings.append(f'ATR engine could not load this rule; it may not execute: {reason}')

    # ── execution ────────────────────────────────────────────────────────
    def run_test(self, rule_content: str, input_data: dict, log_fn) -> MatchDetail:
        if not _engine_available():
            log_fn('error', 'ATR engine (pyatr) is not installed -- cannot execute rule.')
            return MatchDetail(
                matched=False, score=0.0,
                details={'mode': 'engine_unavailable'},
                quality_hints=['Install the ATR engine: pip install pyatr'],
                error='pyatr not installed',
            )

        engine, load_errors = _build_engine(rule_content)
        if engine is None:
            msg = load_errors[0] if load_errors else 'rule failed to load into the ATR engine'
            log_fn('error', f'ATR rule did not load: {msg}')
            return MatchDetail(matched=False, score=0.0, details={'mode': 'load_error'},
                               quality_hints=[], error=msg)

        event = _build_event(input_data)
        log_fn('info', f'Evaluating ATR rule against a "{event.event_type}" agent event...')
        t0 = time.monotonic()
        try:
            matches = engine.evaluate(event)
        except Exception as e:
            elapsed = int((time.monotonic() - t0) * 1000)
            log_fn('error', f'ATR engine error: {e}')
            return MatchDetail(matched=False, score=0.0, details={'mode': 'engine_error'},
                               quality_hints=[], execution_time_ms=elapsed, error=str(e))
        elapsed = int((time.monotonic() - t0) * 1000)

        matched = len(matches) > 0
        top = matches[0] if matched else None
        confidence = (top.confidence or '').lower() if top else ''
        score = _CONFIDENCE_SCORE.get(confidence, 0.5) if matched else 0.0
        fired = list(top.matched_patterns) if top else []

        log_fn('success' if matched else 'info',
               ('MATCHED ' + top.rule_id + ' (' + top.severity + ')' if top else 'NO MATCH')
               + f' in {elapsed}ms')

        return MatchDetail(
            matched=matched,
            score=round(score, 3),
            details={
                'rule_id':          top.rule_id if top else None,
                'severity':         top.severity if top else None,
                'confidence':       top.confidence if top else None,
                'matched_patterns': fired,
                'matched_count':    len(matches),
                'event_type':       event.event_type,
                'mode':             'engine',
            },
            quality_hints=_quality_hints(matched, top, fired),
            execution_time_ms=elapsed,
        )


# ── module-level helpers (kept off the driver instance so they are easy to
#    monkeypatch in tests and reuse across validate/execute) ───────────────

def _engine_available() -> bool:
    try:
        import pyatr  # noqa: F401
        return True
    except Exception:
        return False


def _build_engine(rule_content: str):
    """Return ``(ATREngine, [])`` on success or ``(None, [error, ...])``.

    The rule is written into an isolated temp directory and loaded through
    pyatr's own file loader, so the driver never depends on pyatr's internal
    YAML-to-rule parsing details. Loaded rules live in memory on the engine,
    so the temp directory is safe to remove before evaluation.
    """
    try:
        from pyatr import ATREngine
    except Exception as e:
        return None, [f'pyatr import failed: {e}']

    import os
    import tempfile
    try:
        with tempfile.TemporaryDirectory(prefix='atr_rule_') as tmp:
            path = os.path.join(tmp, 'rule.yaml')
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(rule_content)
            engine = ATREngine()
            count = engine.load_rules_from_directory(tmp)
    except Exception as e:
        return None, [str(e)]

    if count and count > 0:
        return engine, []
    return None, ['no valid ATR rule found in content']


def _build_event(input_data: dict):
    """Build a pyatr ``AgentEvent`` from the tester's ``{type, value}`` input.

    ``content`` is always set (ATR conditions fall back to it for named
    fields), and structured JSON objects are additionally exposed via
    ``fields`` so field-specific conditions can match.
    """
    from pyatr import AgentEvent

    input_data = input_data or {}
    value = input_data.get('value', '')
    input_type = str(input_data.get('type') or 'text').lower()
    event_type = input_data.get('event_type') or 'llm_input'

    fields: dict = {}
    if isinstance(value, dict):
        fields = {k: _stringify(v) for k, v in value.items()}
        content = json.dumps(value, ensure_ascii=False)
    elif isinstance(value, str) and (input_type == 'json' or value.strip()[:1] in '{['):
        content = value
        try:
            parsed = json.loads(value)
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            fields = {k: _stringify(v) for k, v in parsed.items()}
    else:
        content = '' if value is None else str(value)

    return AgentEvent(content=content, event_type=event_type, fields=fields)


def _stringify(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _quality_hints(matched: bool, top, fired: list) -> list:
    if not matched:
        return ['No ATR detection conditions matched this input -- if this input '
                'represents the attack, the rule may under-detect (false negative).']
    hints = [f'{len(fired)} detection pattern(s) fired.']
    if top and (top.confidence or '').lower() == 'low':
        hints.append('Match confidence is low -- consider tightening the rule or '
                     'reviewing for false positives.')
    return hints
