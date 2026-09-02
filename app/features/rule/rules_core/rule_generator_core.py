"""
rule_generator_core.py — Rule Generator (Beta, YARA only).

One-shot draft generation, same design as bad_rule_core.py's Rule Fixer
redesign: exactly one call to RuleGeneratorAgent, then a single syntax check
(verify_syntax_rule_by_format) purely as an informational signal for the
human — never a hard gate, and never looped back into the model. The draft
is always staged for the human to review/edit in the normal "Add a Detection
Rule" form and submit through the existing, unmodified creation pipeline
(parse_rule_by_format / add_rule_core are never called from here).

See ~/Documents/Rulezet/IA-Integration-plan/AI_03_RULE_GENERATOR.md.
"""

import uuid as uuid_mod

from app import db
from app.core.db_class.db import AIGeneration


def run_ai_generate_streaming(user, description: str, sample: str = None):
    """Generator version of the draft flow — yields one {"type": "step", ...}
    event per stage (the shared AI_00_FOUNDATION.md §10 protocol), then a
    single closing {"type": "result", ...} event.

    Result shape: {"ok": bool, "rule_content": str, "title": str,
    "explanation": str, "valid": bool | None, "validate_error": str | None,
    "model": str | None, "error": str | None}. `ok` means "a usable draft was
    produced" — `valid`
    is the separate, purely informational syntax-check outcome; a draft can
    be ok=True and valid=False (still shown, with a clear warning) since the
    human reviews and edits before anything reaches the real creation form.
    """
    from app.features.ai.ai_core import get_agent
    from app.features.rule.rule_format.main_format import verify_syntax_rule_by_format

    agent = get_agent('rule_generator')
    if agent is None:
        yield {"type": "step", "stage": "failed", "text": "Rule Generator agent is unavailable."}
        yield {"type": "result", "ok": False, "error": "Rule Generator agent is unavailable."}
        return

    yield {"type": "step", "stage": "reading", "text": "Reading your request…"}
    yield {"type": "step", "stage": "thinking", "text": "Drafting a YARA rule…"}

    # Pass the FULL description/sample (not a truncated preview) as
    # input_summary — this is what AIAgent.run() scans for prompt-injection
    # markers before ever truncating it for storage, so a phrase buried past
    # the first 200 characters still gets flagged for admin visibility.
    summary_text = f"Generate a YARA rule: {(description or '').strip()}"
    if sample:
        summary_text += f" | sample: {sample.strip()}"
    result = agent.run(
        user=user, input_summary=summary_text,
        description=description, sample=sample,
    )
    if not result.ok:
        yield {"type": "step", "stage": "failed", "text": result.error}
        yield {"type": "result", "ok": False, "error": result.error}
        return

    content = result.content
    title = result.meta.get('title') or ''
    explanation = result.meta.get('explanation') or ''

    yield {"type": "step", "stage": "validating", "text": "Checking that the draft compiles…"}
    is_valid, validate_error = verify_syntax_rule_by_format({"format": "yara", "to_string": content})

    db.session.add(AIGeneration(
        uuid=str(uuid_mod.uuid4()), agent_key='rule_generator', rule_id=None,
        user_id=getattr(user, 'id', None), content=content,
        model=result.model_used, is_public=True,
    ))
    db.session.commit()

    if is_valid:
        yield {"type": "step", "stage": "done", "text": "Draft ready — review it below before creating the rule."}
    else:
        yield {"type": "step", "stage": "done",
               "text": "Draft ready, but it didn't pass syntax validation — review carefully."}

    yield {
        "type": "result", "ok": True,
        "rule_content": content, "title": title, "explanation": explanation,
        "valid": is_valid, "validate_error": None if is_valid else validate_error,
        "model": result.model_used,
    }


def run_ai_generate(user, description: str, sample: str = None) -> dict:
    """Non-streaming convenience wrapper around run_ai_generate_streaming() —
    runs it to completion and returns just the final result dict. Used by
    tests and any non-HTTP caller; the live HTTP route streams the
    generator's events directly instead."""
    for event in run_ai_generate_streaming(user, description, sample=sample):
        if event.get("type") == "result":
            return {k: v for k, v in event.items() if k != "type"}
    return {"ok": False, "error": "The generation stream ended without a result."}
