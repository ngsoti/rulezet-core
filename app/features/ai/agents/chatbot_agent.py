"""
chatbot_agent.py — ChatbotAgent(AIAgent)

Migration only (AI_01_CHATBOT.md §3/§9 Phase 1): wraps the exact same system
prompt and JSON-envelope contract chatbot_core.py's call_ollama() used
directly, so it inherits the concurrency governor, rate limiting, and
unified AIExecutionLog logging for free, with no change to the action
vocabulary or dispatch logic (which stays in chatbot_core.py — it's
chatbot-specific business logic, not agent plumbing).
"""

import json

from app.features.ai.ai_core import AgentResult, AIAgent, UNTRUSTED_DATA_PREAMBLE


class ChatbotAgent(AIAgent):
    @property
    def key(self):
        return 'chatbot'

    @property
    def display_name(self):
        return 'Chatbot Assistant'

    def build_messages(self, *, history=None, message, **kw):
        # SYSTEM_PROMPT (with its closed _ROUTES vocabulary) stays defined in
        # chatbot_core.py — imported here rather than duplicated so there is
        # exactly one copy of it.
        from app.features.ai.chatbot.chatbot_core import SYSTEM_PROMPT

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        messages.extend(history or [])
        # The live user message is exactly as attacker-controlled as rule
        # content is — wrap it the same way, even though today's prompt
        # didn't (AI_01 §3/§8: this is a deliberate, new hardening step).
        messages.append({
            "role": "user",
            "content": f"{UNTRUSTED_DATA_PREAMBLE}\n\n{message}",
        })
        return messages

    def json_schema(self):
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "params": {"type": "object"},
                "reply": {"type": "string"},
            },
            "required": ["reply"],
        }

    def parse_response(self, raw):
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError
        except (ValueError, TypeError):
            # Not valid JSON at all — treat the raw text as a plain chat
            # reply rather than failing the whole exchange, same fallback
            # chatbot_core.py's old _dispatch_message used.
            return AgentResult(
                ok=True,
                content=raw.strip() or "Sorry, I didn't quite catch that.",
                meta={"action": "chat", "params": {}},
            )

        return AgentResult(
            ok=True,
            content=parsed.get('reply') or '',
            meta={"action": parsed.get('action', 'chat'), "params": parsed.get('params') or {}},
        )
