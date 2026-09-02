"""
rule_generator_agent.py — RuleGeneratorAgent(AIAgent)

Drafts a brand-new YARA rule from a plain-language description. Beta, YARA
only for now — see ~/Documents/Rulezet/IA-Integration-plan/AI_03_RULE_GENERATOR.md.
Deliberately one-shot (same reasoning as rule_fixer_agent.py's redesign): the
caller (rule_generator_core.py) validates the result once via
verify_syntax_rule_by_format and shows the outcome to the human, but never
loops back into the model — the existing rule-creation form's own validation
is the real gate, this is only a draft to review before submitting.
"""

import json

from app.features.ai.ai_core import (
    AgentResult,
    AIAgent,
    UNTRUSTED_DATA_PREAMBLE,
    extract_json_string_field,
    strip_control_chars,
)

# Same reasoning as rule_fixer_agent.py — keep the description/sample well
# inside the model's context window alongside the system prompt.
MAX_INPUT_CHARS = 4000

_YARA_SKELETON = '''rule Example_Rule_Name
{
    meta:
        description = "One-line summary of what this detects"
        author = "Rulezet AI Generator"

    strings:
        $s1 = "some distinctive string" ascii wide
        $hex1 = { 6A 40 68 00 30 00 00 6A 14 8D 91 }

    condition:
        uint16(0) == 0x5A4D and any of them
}'''

# A second, PE-focused skeleton — PE import/export/section checks are one of
# the most commonly requested detection patterns and also the syntax local
# models get wrong most often (treating pe.imports/pe.exports as a
# membership check instead of the function call it actually is, or omitting
# the required "import" statement entirely). Confirmed necessary in
# practice: without this second example, a real request ("detect a PE that
# imports CredEnumerateW") produced `$x in PE.imports`, which does not
# compile — pe.imports() is a function, "pe" is lowercase, and the module
# must be imported.
_YARA_PE_SKELETON = '''import "pe"

rule Example_PE_Rule
{
    meta:
        description = "Example showing correct pe module usage"

    condition:
        pe.imports("kernel32.dll", "CreateProcessW") and
        pe.number_of_sections > 2
}'''

_SYSTEM_PROMPT = """You are a YARA detection-rule drafting assistant. You will be given a \
plain-language description of what a user wants to detect (and, optionally, a sample — \
a string, hex pattern, or short excerpt). Produce a single, syntactically valid, working \
DRAFT YARA rule for it.

Here is a minimal, valid YARA rule showing the required structure — use it only as a \
syntax reminder, never copy its content into your answer:
--- SKELETON ---
""" + _YARA_SKELETON + """
--- END SKELETON ---

If the request involves a Windows executable's imports, exports, sections, or other PE \
metadata, the "pe" module is a FUNCTION-BASED API, not a membership check — study this \
example before writing any pe.* condition. Every argument to pe.imports(...) MUST be a \
literal quoted string (e.g. "CredEnumerateW") — NEVER a $string_id variable, even if \
you also defined a $string with that same text in the strings: section:
--- PE SKELETON ---
""" + _YARA_PE_SKELETON + """
--- END PE SKELETON ---

Rules you must follow:
- Output ONLY valid YARA syntax — a real, complete rule block, never pseudo-code, never \
a code fence, never commentary outside the JSON response.
- Keep the rule narrowly scoped to exactly what was described. Do not invent unrelated \
detection logic, do not add speculative conditions, do not pad the rule with strings or \
checks that weren't implied by the request.
- The rule's `meta.description` must summarize what it detects. Give the rule a short, \
descriptive, valid YARA identifier as its name (letters, digits, underscores only, must \
not start with a digit) — reuse it as "title" in your response.
- If a sample was provided, ground the rule's strings/patterns in it directly rather \
than guessing generic ones.
- This is a DRAFT a human will review before anything is saved — if the request is too \
vague to produce a meaningful rule, do your best with a clearly-scoped narrow attempt \
and say so in "explanation" rather than refusing outright.

Respond with ONLY a JSON object of this exact shape, nothing else:
{"rule_content": "<the complete YARA rule, in full>", "title": "<the rule's identifier, \
matching the name used in rule_content>", "explanation": "<one short paragraph on what \
the rule detects and why it's built this way>"}"""


class RuleGeneratorAgent(AIAgent):
    @property
    def key(self):
        return 'rule_generator'

    @property
    def display_name(self):
        return 'Rule Generator'

    def build_messages(self, *, description=None, sample=None, **kw):
        description = (description or '').strip()
        sample = (sample or '').strip()
        if len(description) > MAX_INPUT_CHARS:
            description = description[:MAX_INPUT_CHARS] + '\n... (truncated)'
        if len(sample) > MAX_INPUT_CHARS:
            sample = sample[:MAX_INPUT_CHARS] + '\n... (truncated)'

        parts = [UNTRUSTED_DATA_PREAMBLE, '', '--- BEGIN REQUEST (describes what to detect) ---']
        parts.append(description or '(no description provided)')
        parts.append('--- END REQUEST ---')
        if sample:
            parts.append('')
            parts.append('--- BEGIN SAMPLE (ground the rule in this) ---')
            parts.append(sample)
            parts.append('--- END SAMPLE ---')
        parts.append('')
        parts.append(
            'Draft one YARA rule for this request. Remember: "rule_content" must be the '
            'complete rule, valid syntax, nothing else.'
        )
        user_prompt = '\n'.join(parts)

        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

    def json_schema(self):
        return {
            "type": "object",
            "properties": {
                "rule_content": {"type": "string"},
                "title": {"type": "string"},
                "explanation": {"type": "string"},
            },
            "required": ["rule_content", "title"],
        }

    def parse_response(self, raw):
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            data = None

        if isinstance(data, dict):
            content = data.get('rule_content')
            title = data.get('title') or ''
            explanation = data.get('explanation') or ''
        else:
            # Structured-output mode should make this unreachable, but stay
            # resilient the same way the other agents do.
            content = extract_json_string_field(raw, 'rule_content')
            title = extract_json_string_field(raw, 'title') or ''
            explanation = extract_json_string_field(raw, 'explanation') or ''

        if not isinstance(content, str) or not content.strip():
            return AgentResult(ok=False, error="Model did not return a usable rule draft.")

        return AgentResult(
            ok=True,
            content=strip_control_chars(content),
            meta={'title': title.strip(), 'explanation': explanation},
        )
