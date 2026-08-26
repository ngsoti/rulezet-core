"""
rule_fixer_agent.py — RuleFixerAgent(AIAgent)

Proposes a targeted fix for a rule that failed validation, given its exact
content and validator error message. Deliberately a *surgical edit*, not a
regeneration — the prompt explicitly forbids rewriting unrelated parts of
the rule. This class only proposes one candidate; re-validating it and
retrying on failure is the caller's job (bad_rule_core.py::run_ai_fix), so
this stays a pure "propose one edit" unit like every other agent.

See ~/Documents/Rulezet/IA-Integration-plan/AI_04_RULE_FIXER.md.
"""

import json
import re

from app.features.ai.ai_core import (
    AgentResult,
    AIAgent,
    UNTRUSTED_DATA_PREAMBLE,
    extract_json_string_field,
    strip_control_chars,
)

# Same reasoning as rule_analysis_agent.py — keep the rule content well
# inside the model's context window alongside the system prompt and error.
MAX_CONTENT_CHARS = 10000

# Lines of context shown on either side of the flagged line in the
# highlighted excerpt (see _line_context below).
_LINE_CONTEXT = 2


def _line_context(content, line_no):
    """Renders a numbered excerpt of `content` centered on `line_no`, with
    that exact line marked — confirmed necessary in practice: both a small
    YARA-specific model and a general 7B coding model missed an identical
    single-character bug (a string identifier missing its leading '$') when
    only given the raw error message and the full rule text to scan
    themselves. Pointing directly at the flagged line removes the need for
    the model to first locate it correctly before it can even attempt a fix.
    Returns None if line_no is out of range or content has only one line."""
    lines = content.splitlines()
    if not lines or not (1 <= line_no <= len(lines)):
        return None
    start = max(1, line_no - _LINE_CONTEXT)
    end = min(len(lines), line_no + _LINE_CONTEXT)
    width = len(str(end))
    out = []
    for i in range(start, end + 1):
        marker = '>>> ' if i == line_no else '    '
        out.append(f"{marker}{str(i).rjust(width)}: {lines[i - 1]}")
    return '\n'.join(out)

_SYSTEM_PROMPT = """You are a detection-rule repair assistant. You will be given a \
detection rule that fails to compile or validate, and the exact validator error \
message for it. Make the SMALLEST possible edit that fixes this specific error — but \
"smallest edit" describes how much you CHANGE, never how much you RETURN.

"fixed_content" MUST be the complete rule file, from its very first character to its \
very last, in full — the same length and structure as the input, with only the \
necessary correction applied inline. It is NEVER acceptable to return only the changed \
line, a snippet, an excerpt, or "the section with the fix" — that output is unusable and \
will be rejected. If you are not changing a part of the rule, copy it into your answer \
byte-for-byte exactly as given.

Rules you must follow:
- Return the ENTIRE rule content, unabridged — never a fragment, snippet, or diff.
- Do not rewrite unrelated parts of the rule.
- Do not change the detection logic's intent.
- Do not add new strings, conditions, or fields that were not already implied by the \
existing rule.
- Preserve the rule's original formatting and style wherever the fix doesn't require \
changing it.
- If you cannot determine a targeted fix for this exact error, set "could_not_fix" to \
true rather than guessing destructively — a wrong guess that hides the real problem is \
worse than admitting you can't fix it.

Respond with ONLY a JSON object of this exact shape, nothing else:
{"fixed_content": "<the COMPLETE corrected rule content in full, or the original content \
unchanged if could_not_fix is true>", "explanation": "<one short paragraph explaining \
what was wrong and what you changed>", "could_not_fix": <true or false>}"""


class RuleFixerAgent(AIAgent):
    @property
    def key(self):
        return 'rule_fixer'

    @property
    def display_name(self):
        return 'Rule Fixer'

    def build_messages(self, *, content, format_name, error_message, **kw):
        content = (content or '').strip()
        if len(content) > MAX_CONTENT_CHARS:
            content = content[:MAX_CONTENT_CHARS] + '\n... (truncated)'

        error_message = (error_message or '(no error message provided)').strip()

        line_hint = ''
        line_match = re.search(r'line (\d+)', error_message)
        if line_match:
            excerpt = _line_context(content, int(line_match.group(1)))
            if excerpt:
                line_hint = (
                    f"\n--- THE ERROR IS ON LINE {line_match.group(1)} SPECIFICALLY. "
                    "Here is that exact line (marked with >>>) and its immediate "
                    f"neighbors ---\n{excerpt}\n--- end line excerpt ---\n"
                )

        user_prompt = (
            f"Rule format: {format_name or 'unknown'}\n\n"
            f"{UNTRUSTED_DATA_PREAMBLE}\n\n"
            "--- BEGIN RULE CONTENT (fails to validate) ---\n"
            f"{content}\n"
            "--- END RULE CONTENT ---\n\n"
            "--- BEGIN VALIDATOR ERROR ---\n"
            f"{error_message}\n"
            "--- END VALIDATOR ERROR ---\n"
            f"{line_hint}\n"
            "Propose the smallest edit that resolves this exact error. Remember: "
            "\"fixed_content\" must be the ENTIRE rule above, in full, with only that "
            "edit applied — not just the changed line or section."
        )
        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

    def json_schema(self):
        return {
            "type": "object",
            "properties": {
                "fixed_content": {"type": "string"},
                "explanation": {"type": "string"},
                "could_not_fix": {"type": "boolean"},
            },
            "required": ["fixed_content", "could_not_fix"],
        }

    def parse_response(self, raw):
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            data = None

        if isinstance(data, dict):
            fixed = data.get('fixed_content')
            explanation = data.get('explanation') or ''
            # Smaller models (confirmed on this one) sometimes set
            # could_not_fix=true while STILL producing a real, usable
            # fixed_content in the same response — a self-contradiction, not
            # a reliable "I have nothing" signal. Only treat this as a hard
            # failure when there's genuinely no content to fall back on; a
            # real (if imperfect) candidate should go on to be validated by
            # verify_syntax_rule_by_format() — the actual ground truth — and
            # retried if it's wrong, rather than discarded on the model's own
            # self-assessment.
            if data.get('could_not_fix') and not (isinstance(fixed, str) and fixed.strip()):
                return AgentResult(
                    ok=False,
                    error="The model could not determine a targeted fix for this error.",
                    meta={'explanation': explanation},
                )
        else:
            # Structured-output mode should make this unreachable, but stay
            # resilient the same way rule_analysis_agent.py does.
            fixed = extract_json_string_field(raw, 'fixed_content')
            explanation = extract_json_string_field(raw, 'explanation') or ''

        if not isinstance(fixed, str) or not fixed.strip():
            return AgentResult(ok=False, error="Model did not return a usable fix.")

        return AgentResult(ok=True, content=strip_control_chars(fixed), meta={'explanation': explanation})
