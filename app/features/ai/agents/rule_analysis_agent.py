"""
rule_analysis_agent.py — RuleAnalysisAgent(AIAgent)

Per-rule Markdown analysis report, grounded in the rule's own content plus
its real tags/ATT&CK techniques/CVEs (curated platform data, not free
text) — especially valuable when the rule itself has little or no
description. See AI_02_RULE_ANALYSIS.md.

The prompt and validation logic below is carried over near-verbatim from
the reverted `ai_rule_analysis` branch's postmortem (its prompt design was
correct — the bugs were in num_predict being left unset and in requiring a
minimum output length, both fixed by going through AIAgent/OllamaClient and
by deliberately NOT re-adding a minimum-length gate here).
"""

from app.features.ai.ai_core import (
    AgentResult,
    AIAgent,
    UNTRUSTED_DATA_PREAMBLE,
    extract_json_string_field,
    strip_control_chars,
)

# Rule content shares a limited context window with the system prompt and
# the requested output — an unbounded rule body would silently truncate the
# instructions themselves instead of erroring.
MAX_CONTENT_CHARS = 10000

# Sanity ceiling on what's worth storing. A response beyond this is far more
# likely a degenerate repetition loop (a known small-model failure mode)
# than a genuinely useful report.
MAX_SUMMARY_CHARS = 12000

_SYSTEM_PROMPT = """You are a senior detection engineer and threat analyst writing a \
formal analysis report for a SOC team. You will be given the full content of a detection \
rule (YARA, Sigma, or another format) and must produce a thorough, detailed, professional \
report about it, in English Markdown — not a one-line summary.

Write a genuinely in-depth report. Go through the rule's actual structure and reference \
its real fields, sections, strings, patterns, or condition logic by their actual names or \
values wherever relevant — do not write generic filler that could apply to any rule. \
Every claim must be grounded in what is actually present in the rule's title, description, \
metadata, or content.

Structure your report with exactly these Markdown sections. Every section is MANDATORY \
and must be substantial whenever the rule actually has material to support it — but if \
the rule is genuinely sparse (little metadata, few strings/conditions), a short, honest \
section is a correct and acceptable result, never pad it with invented specifics.

## Overview
What this rule is, its overall purpose, and the general category of threat, technique, or \
activity it targets. Name the actual technique/behavior, not just "malicious activity".

## Rule Structure & Fields
A bullet list, one bullet per actual field/section present in the rule (metadata block \
entries one by one — author, references, level, date, etc. if present; every distinct \
string/pattern/selection; the detection/condition block; log source; anything else that \
exists in this specific rule), PLUS one bullet for the platform tags, one for each linked \
MITRE ATT&CK technique, and one for each linked CVE, if any of those are provided below. \
For EACH bullet, quote or name the real value and explain in a full sentence what it is \
for. If a field is genuinely absent, say so explicitly rather than omitting the bullet.

## Detection Logic
A step-by-step walkthrough of the real detection logic — exactly which conditions must \
all be true (or which alternative conditions can trigger it) for this rule to fire, \
referencing the actual operators/keywords/thresholds used.

## Security Implications
What a match on this rule would realistically indicate from a security/incident-response \
perspective. If ATT&CK techniques or CVEs are linked to this rule, explicitly tie this \
section back to them.

## Limitations & Caveats
Concrete, specific caveats grounded in how the rule is actually written — realistic false \
positive sources tied to its actual strings/conditions, plausible evasion of THIS rule's \
specific logic, and scope limitations. Generic caveats like "may have false positives" \
without a concrete reason are not acceptable.

Only state facts directly supported by the rule's title, description, metadata, content, \
or the tags/ATT&CK techniques/CVEs listed. Never invent or guess specifics that are not \
present there — no CVE numbers, no threat actor or malware family names, no vendor \
products, no version numbers — unless they are literally listed or written in the rule \
itself.

Respond with ONLY a JSON object of this exact shape, nothing else:
{"summary": "<the full markdown report as a single string>"}"""


class RuleAnalysisAgent(AIAgent):
    @property
    def key(self):
        return 'rule_analysis'

    @property
    def display_name(self):
        return 'Rule Analysis'

    def build_messages(self, *, rule_stub, **kw):
        """rule_stub: a lightweight object (SimpleNamespace, keeps the bulk
        job from loading a full ORM Rule per row) carrying title, format,
        description, to_string, tags (list[str]), attack_techniques
        (list[str] "T1059 (name)"), cve_ids (list[str])."""
        content = (rule_stub.to_string or '').strip()
        if len(content) > MAX_CONTENT_CHARS:
            content = content[:MAX_CONTENT_CHARS] + '\n... (truncated)'

        tags    = list(getattr(rule_stub, 'tags', None) or [])
        attacks = list(getattr(rule_stub, 'attack_techniques', None) or [])
        cve_ids = list(getattr(rule_stub, 'cve_ids', None) or [])

        user_prompt = (
            f"Rule title: {rule_stub.title or '(untitled)'}\n"
            f"Rule format: {rule_stub.format or 'unknown'}\n"
            f"Existing description: {rule_stub.description or '(none provided)'}\n"
            f"Tags on this platform: {', '.join(tags) if tags else '(none)'}\n"
            f"MITRE ATT&CK techniques linked to this rule: {', '.join(attacks) if attacks else '(none)'}\n"
            f"CVE(s) linked to this rule: {', '.join(cve_ids) if cve_ids else '(none)'}\n\n"
            f"{UNTRUSTED_DATA_PREAMBLE}\n\n"
            "--- BEGIN RULE CONTENT ---\n"
            f"{content}\n"
            "--- END RULE CONTENT ---\n\n"
            "Write the Markdown report as instructed. Use the tags, ATT&CK techniques, and CVEs "
            "above as real, grounded material — explain what a linked technique or CVE actually "
            "means for this rule, don't just restate the identifier. If the rule's own content or "
            "description is sparse, lean on this metadata to keep the report substantial rather "
            "than leaving sections thin — but never invent tags, techniques, or CVEs beyond what "
            "is listed here or literally present in the rule content."
        )
        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

    def json_schema(self):
        return {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
        }

    def parse_response(self, raw):
        summary = extract_json_string_field(raw, 'summary')
        if not isinstance(summary, str) or not summary.strip():
            return AgentResult(ok=False, error="Response had no non-empty 'summary' string.")

        summary = strip_control_chars(summary.strip())
        if len(summary) > MAX_SUMMARY_CHARS:
            return AgentResult(
                ok=False,
                error=f"Response too long ({len(summary)} chars) — likely a degenerate/repeating generation.",
            )
        # Deliberately no minimum-length or required-section check: a sparse
        # rule can honestly produce a short report, and that's a legitimate
        # result, not a failure to reject.
        return AgentResult(ok=True, content=summary)
