import ast
import json
import re
import time

from .base import BaseTesterDriver, ValidationResult, MatchDetail
from .registry import register_driver

# After group-name substitution, `expr` must contain nothing but
# True/False/and/or/not/parentheses. Anything else (names, calls,
# attributes, subscripts, ...) means the substitution missed a token —
# reject it rather than ever handing it to eval()/exec().
_ALLOWED_BOOL_NODES = (
    ast.Expression, ast.BoolOp, ast.And, ast.Or,
    ast.UnaryOp, ast.Not, ast.Constant,
)


def _safe_bool_eval(expr: str) -> bool:
    """Evaluate a boolean expression made only of True/False/and/or/not/parens.

    Raises ValueError/SyntaxError for anything else so the caller can fall
    back safely — this function never calls eval() or exec().
    """
    tree = ast.parse(expr, mode='eval')

    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_BOOL_NODES):
            raise ValueError(f'disallowed expression node: {type(node).__name__}')
        if isinstance(node, ast.Constant) and not isinstance(node.value, bool):
            raise ValueError('only boolean constants are allowed')

    return bool(_eval_bool_node(tree.body))


def _eval_bool_node(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_bool_node(node.operand)
    if isinstance(node, ast.BoolOp):
        values = [_eval_bool_node(v) for v in node.values]
        return all(values) if isinstance(node.op, ast.And) else any(values)
    raise ValueError(f'unhandled node: {type(node).__name__}')


@register_driver('sigma')
class SigmaDriver(BaseTesterDriver):
    format_name  = 'sigma'
    display_name = 'Sigma'
    input_types  = ['json']
    can_execute  = True

    def validate_syntax(self, rule_content: str) -> ValidationResult:
        try:
            import yaml
            doc = yaml.safe_load(rule_content)
        except Exception as e:
            return ValidationResult(valid=False, errors=[f'YAML parse error: {e}'])

        if not isinstance(doc, dict):
            return ValidationResult(valid=False, errors=['Rule must be a YAML mapping'])

        errors, warnings = [], []
        for required in ('title', 'logsource', 'detection'):
            if required not in doc:
                errors.append(f"Missing required field: '{required}'")
        if 'logsource' in doc and not isinstance(doc['logsource'], dict):
            errors.append("'logsource' must be a mapping")
        if 'detection' in doc:
            det = doc['detection']
            if not isinstance(det, dict):
                errors.append("'detection' must be a mapping")
            elif 'condition' not in det:
                errors.append("'detection' must contain a 'condition' key")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    def run_test(self, rule_content: str, input_data: dict, log_fn) -> MatchDetail:
        import yaml

        input_type  = input_data.get('type', 'json')
        input_value = input_data.get('value', '')

        # parse log event
        try:
            if isinstance(input_value, dict):
                event = input_value
            else:
                event = json.loads(input_value)
        except Exception as e:
            return MatchDetail(matched=False, score=0.0, details={},
                               quality_hints=[], error=f'Invalid JSON event: {e}')

        # parse rule
        try:
            doc = yaml.safe_load(rule_content)
        except Exception as e:
            return MatchDetail(matched=False, score=0.0, details={},
                               quality_hints=[], error=f'YAML parse error: {e}')

        log_fn('info', f'Evaluating Sigma rule "{doc.get("title", "untitled")}" against log event…')
        t0 = time.monotonic()

        detection = doc.get('detection', {})
        logsource  = doc.get('logsource', {})
        condition  = str(detection.get('condition', '')).strip()

        # build named selection groups
        selections = {k: v for k, v in detection.items() if k != 'condition'}

        # evaluate each selection group
        group_results: dict[str, bool] = {}
        conditions_evaluated = []

        for sel_name, sel_def in selections.items():
            group_matched, group_conds = self._eval_selection(sel_def, event)
            group_results[sel_name] = group_matched
            conditions_evaluated.extend(group_conds)

        # evaluate condition expression
        matched = self._eval_condition(condition, group_results)

        elapsed_ms = int((time.monotonic() - t0) * 1000)

        total = len(conditions_evaluated)
        matched_count = sum(1 for c in conditions_evaluated if c.get('matched'))
        coverage = round(matched_count / total, 3) if total > 0 else (1.0 if matched else 0.0)
        score = coverage if matched else 0.0

        missing_fields = [c['field'] for c in conditions_evaluated
                          if not c.get('present_in_log')]

        hints = []
        if missing_fields:
            hints.append(
                f"Fields not found in log event: {', '.join(set(missing_fields))} — "
                'rule may miss detections in this log source'
            )
        if matched and total > 0 and coverage < 1.0:
            hints.append('Some condition fields are missing — partial match only')
        if matched and not missing_fields:
            hints.append('All condition fields present — rule is well-suited for this log format')

        log_fn('success' if matched else 'info',
               f'{"MATCHED" if matched else "NO MATCH"} — {matched_count}/{total} conditions met '
               f'in {elapsed_ms}ms')

        return MatchDetail(
            matched=matched,
            score=round(score, 3),
            details={
                'logsource':             logsource,
                'condition_expression':  condition,
                'conditions_evaluated':  conditions_evaluated,
                'missing_fields':        list(set(missing_fields)),
                'coverage_pct':          round(coverage * 100),
                'mode':                  'field_matching',
            },
            quality_hints=hints,
            execution_time_ms=elapsed_ms,
        )

    # ── helpers ──────────────────────────────────────────────────────────────

    def _eval_selection(self, sel_def, event: dict) -> tuple:
        """Return (group_matched, list_of_condition_dicts)."""
        if isinstance(sel_def, dict):
            return self._eval_field_mapping(sel_def, event)
        if isinstance(sel_def, list):
            # OR list of sub-selectors
            all_conds = []
            any_match = False
            for item in sel_def:
                gm, conds = self._eval_selection(item, event)
                all_conds.extend(conds)
                if gm:
                    any_match = True
            return any_match, all_conds
        return False, []

    def _eval_field_mapping(self, mapping: dict, event: dict) -> tuple:
        """Evaluate a {field: value} or {field|modifier: value} mapping."""
        conds = []
        all_match = True

        for key, expected in mapping.items():
            field, *modifiers = key.split('|')
            modifier = modifiers[0] if modifiers else None

            # search event case-insensitively
            event_val = self._get_event_field(event, field)
            present   = event_val is not None

            if expected is None:
                matched = True
            elif isinstance(expected, list):
                matched = any(self._apply_modifier(modifier, event_val, str(v)) for v in expected)
            else:
                matched = self._apply_modifier(modifier, event_val, str(expected))

            if not present:
                matched = False
                all_match = False
            elif not matched:
                all_match = False

            conds.append({
                'field':          field,
                'modifier':       modifier,
                'expected':       expected,
                'event_value':    str(event_val)[:120] if event_val is not None else None,
                'present_in_log': present,
                'matched':        matched,
            })

        return all_match, conds

    def _get_event_field(self, event: dict, field: str):
        """Case-insensitive field lookup."""
        if field in event:
            return event[field]
        lower = field.lower()
        for k, v in event.items():
            if k.lower() == lower:
                return v
        return None

    def _apply_modifier(self, modifier, event_val, expected: str) -> bool:
        if event_val is None:
            return False
        ev = str(event_val)
        if modifier in (None, 'equals'):
            return ev.lower() == expected.lower()
        if modifier == 'contains':
            return expected.lower() in ev.lower()
        if modifier == 'startswith':
            return ev.lower().startswith(expected.lower())
        if modifier == 'endswith':
            return ev.lower().endswith(expected.lower())
        if modifier == 're':
            try:
                return bool(re.search(expected, ev, re.IGNORECASE))
            except Exception:
                return False
        if modifier == 'cidr':
            return self._cidr_match(ev, expected)
        # unknown modifier — fall back to contains
        return expected.lower() in ev.lower()

    def _cidr_match(self, ip: str, cidr: str) -> bool:
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return False

    def _eval_condition(self, condition: str, groups: dict) -> bool:
        """Evaluate a simple Sigma condition expression."""
        if not condition:
            return all(groups.values())

        # replace 'all of them' / 'any of them' / '1 of selection_*'
        cond = condition.strip()

        if cond == 'all of them':
            return all(groups.values())
        if cond == 'any of them':
            return any(groups.values())

        # '1 of <pattern>' or 'N of <pattern>'
        m = re.match(r'^(\d+|all|any)\s+of\s+(.+)$', cond, re.IGNORECASE)
        if m:
            quant, pattern = m.group(1), m.group(2).strip()
            pat = re.compile(pattern.replace('*', '.*'), re.IGNORECASE)
            matched_groups = [v for k, v in groups.items() if pat.match(k)]
            if quant.lower() == 'all':
                return all(matched_groups)
            if quant.lower() == 'any':
                return any(matched_groups)
            n = int(quant)
            return sum(matched_groups) >= n

        # simple substitution: replace group names with True/False
        expr = cond
        for name, val in sorted(groups.items(), key=lambda x: -len(x[0])):
            expr = re.sub(rf'\b{re.escape(name)}\b', str(val), expr)

        expr = re.sub(r'\bnot\b', 'not ', expr, flags=re.IGNORECASE)
        expr = re.sub(r'\band\b', ' and ', expr, flags=re.IGNORECASE)
        expr = re.sub(r'\bor\b',  ' or ',  expr, flags=re.IGNORECASE)

        try:
            return _safe_bool_eval(expr)
        except (SyntaxError, ValueError):
            # fallback: any group matches
            return any(groups.values())
