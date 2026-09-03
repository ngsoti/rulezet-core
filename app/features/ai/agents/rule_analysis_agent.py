"""
rule_analysis_agent.py — RuleAnalysisAgent(AIAgent)

Per-rule analysis report, grounded in the rule's own content plus its real
tags/ATT&CK techniques/CVEs (curated platform data, not free text) —
especially valuable when the rule itself has little or no description.
See AI_02_RULE_ANALYSIS.md.

Structured-output schema (severity/confidence/recommendations/etc as real
fields, not prose buried in a single Markdown blob) — denser, more
bounded-length output per field than open-ended sections, which is both
more detailed (new fields that didn't exist before) and faster to generate
than the old single free-form "summary" string. parse_response() composes
the fields back into one Markdown report (stored in AIGeneration.content,
so the existing Markdown/PDF download routes and clipboard copy need no
changes) and also keeps the structured fields (AIGeneration.meta) for a
richer "at a glance" panel on the rule's AI Analysis page.
"""
import json

from app.features.ai.ai_core import (
    AgentResult,
    AIAgent,
    UNTRUSTED_DATA_PREAMBLE,
    strip_control_chars,
)

# Rule content shares a limited context window with the system prompt and
# the requested output — an unbounded rule body would silently truncate the
# instructions themselves instead of erroring.
MAX_CONTENT_CHARS = 10000

# Sanity ceiling on what's worth storing. A response beyond this is far more
# likely a degenerate repetition loop (a known small-model failure mode)
# than a genuinely useful report. Bumped up from the old single-summary
# schema's ceiling since the composed report now has two extra sections.
MAX_SUMMARY_CHARS = 14000

_SEVERITIES  = {'critical', 'high', 'medium', 'low', 'info'}
_CONFIDENCES = {'high', 'medium', 'low'}

_SYSTEM_PROMPT = """You are a senior detection engineer writing a structured analysis for a SOC \
team, of a detection rule (YARA, Sigma, or another format) you will be given.

Ground every claim in what is actually present in the rule's title, description, metadata, \
content, or the tags/ATT&CK techniques/CVEs listed for it. Never invent specifics that \
aren't there — no CVE numbers, threat actor or malware family names, vendor products, or \
version numbers unless literally present in the input. If the rule is genuinely sparse, \
say so plainly rather than padding with invented detail — a short, honest field is correct.

Reference the rule's actual fields, strings, patterns, and condition logic by their real \
names/values. Keep every field concise and concrete — short phrases and sentences, not \
padded paragraphs; a bullet-style fact beats a restated one.

Respond with ONLY a JSON object of this exact shape, nothing else:
{
  "severity": "critical|high|medium|low|info — how dangerous a real match is",
  "confidence": "high|medium|low — how reliable this rule's own detection logic is",
  "overview": "1-3 sentences: what this rule targets and the general threat/technique category",
  "fields_breakdown": [
    {"field": "<actual field/string/condition name from the rule>", "explanation": "<one sentence>"}
  ],
  "detection_logic": "step-by-step walkthrough of the real condition logic — which parts must all be true, or which alternatives can fire it, referencing actual operators/keywords",
  "security_implications": "what a real match would indicate from an incident-response perspective; tie back to any linked ATT&CK techniques/CVEs by name",
  "mitre_relevance": [
    {"technique": "<technique id and/or name from the list given>", "relevance": "<one sentence on why it applies here>"}
  ],
  "false_positive_risks": ["<concrete FP source tied to an actual string/condition>", "..."],
  "evasion_techniques": ["<concrete way THIS rule's specific logic could be bypassed>", "..."],
  "recommendations": ["<one concrete, actionable next step for a SOC analyst or rule maintainer>", "..."]
}

fields_breakdown: one entry per actual field/section present in the rule (metadata entries, \
each distinct string/pattern/selection, the detection/condition block, log source, etc.) \
plus one entry each for the platform tags, linked ATT&CK techniques, and linked CVEs if any \
are provided. mitre_relevance: only include entries for techniques actually listed below — \
empty array if none. false_positive_risks/evasion_techniques/recommendations: real arrays of \
short strings (empty array if genuinely nothing concrete applies, never a filler entry)."""


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
            "Fill in the JSON object as instructed. Use the tags, ATT&CK techniques, and CVEs "
            "above as real, grounded material — but never invent tags, techniques, or CVEs "
            "beyond what is listed here or literally present in the rule content."
        )
        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

    def json_schema(self):
        string_list = {"type": "array", "items": {"type": "string"}}
        return {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": sorted(_SEVERITIES)},
                "confidence": {"type": "string", "enum": sorted(_CONFIDENCES)},
                "overview": {"type": "string"},
                "fields_breakdown": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"field": {"type": "string"}, "explanation": {"type": "string"}},
                        "required": ["field", "explanation"],
                    },
                },
                "detection_logic": {"type": "string"},
                "security_implications": {"type": "string"},
                "mitre_relevance": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"technique": {"type": "string"}, "relevance": {"type": "string"}},
                        "required": ["technique", "relevance"],
                    },
                },
                "false_positive_risks": string_list,
                "evasion_techniques": string_list,
                "recommendations": string_list,
            },
            "required": [
                "severity", "confidence", "overview", "fields_breakdown", "detection_logic",
                "security_implications", "false_positive_risks", "evasion_techniques", "recommendations",
            ],
        }

    def parse_response(self, raw):
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return AgentResult(ok=False, error="Response was not valid JSON.")

        if not isinstance(data, dict):
            return AgentResult(ok=False, error="Response JSON was not an object.")

        required_strings = ('overview', 'detection_logic', 'security_implications')
        required_lists   = ('fields_breakdown', 'false_positive_risks', 'evasion_techniques', 'recommendations')

        for key in required_strings:
            if not isinstance(data.get(key), str) or not data[key].strip():
                return AgentResult(ok=False, error=f"Response is missing a non-empty '{key}' field.")
        for key in required_lists:
            if not isinstance(data.get(key), list):
                return AgentResult(ok=False, error=f"Response is missing a '{key}' array.")

        severity = data.get('severity') if data.get('severity') in _SEVERITIES else 'info'
        confidence = data.get('confidence') if data.get('confidence') in _CONFIDENCES else 'medium'
        mitre_relevance = [
            m for m in (data.get('mitre_relevance') or [])
            if isinstance(m, dict) and m.get('technique') and m.get('relevance')
        ]
        fields_breakdown = [
            f for f in data['fields_breakdown']
            if isinstance(f, dict) and f.get('field') and f.get('explanation')
        ]
        fp_risks    = [s for s in data['false_positive_risks'] if isinstance(s, str) and s.strip()]
        evasion     = [s for s in data['evasion_techniques'] if isinstance(s, str) and s.strip()]
        recommends  = [s for s in data['recommendations'] if isinstance(s, str) and s.strip()]

        meta = {
            'severity': severity,
            'confidence': confidence,
            'fields_breakdown': fields_breakdown,
            'mitre_relevance': mitre_relevance,
            'false_positive_risks': fp_risks,
            'evasion_techniques': evasion,
            'recommendations': recommends,
        }

        content = strip_control_chars(_render_markdown(data, meta))
        if len(content) > MAX_SUMMARY_CHARS:
            return AgentResult(
                ok=False,
                error=f"Response too long ({len(content)} chars) — likely a degenerate/repeating generation.",
            )

        return AgentResult(ok=True, content=content, meta=meta)


def _render_markdown(data: dict, meta: dict) -> str:
    """Compose the structured fields into one Markdown report — same section
    layout as the old single-summary schema, plus two new sections, so the
    Markdown/PDF download routes and clipboard copy need no changes."""
    lines = [
        "## Severity & Confidence",
        f"- **Severity:** {meta['severity'].capitalize()}",
        f"- **Confidence:** {meta['confidence'].capitalize()}",
        "",
        "## Overview",
        data['overview'].strip(),
        "",
        "## Rule Structure & Fields",
    ]
    if meta['fields_breakdown']:
        for f in meta['fields_breakdown']:
            lines.append(f"- **{f['field']}**: {f['explanation']}")
    else:
        lines.append("_No distinct fields identified._")
    lines += [
        "",
        "## Detection Logic",
        data['detection_logic'].strip(),
        "",
        "## Security Implications",
        data['security_implications'].strip(),
        "",
    ]
    if meta['mitre_relevance']:
        lines.append("## MITRE ATT&CK Relevance")
        for m in meta['mitre_relevance']:
            lines.append(f"- **{m['technique']}**: {m['relevance']}")
        lines.append("")
    lines.append("## False Positive Risks")
    if meta['false_positive_risks']:
        lines += [f"- {s}" for s in meta['false_positive_risks']]
    else:
        lines.append("_None identified._")
    lines += ["", "## Evasion Techniques"]
    if meta['evasion_techniques']:
        lines += [f"- {s}" for s in meta['evasion_techniques']]
    else:
        lines.append("_None identified._")
    lines += ["", "## Recommendations"]
    if meta['recommendations']:
        lines += [f"- {s}" for s in meta['recommendations']]
    else:
        lines.append("_None._")
    return "\n".join(lines).strip()
