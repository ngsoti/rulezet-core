"""chatbot_core.py — Ollama-backed prototype assistant.

Talks to a self-hosted Ollama instance (no API key, no billing) and asks the
model to reply with a small structured JSON envelope instead of doing real
tool-calling — simple, and works with any instruction-following model you
happen to have pulled. When the model asks for an action we recognize
(create_rule, create_bundle), we call straight into the existing rule_core /
bundle_core functions — the chatbot never reimplements that logic, it's just
another caller.
"""

import datetime
import difflib
import json
import re

import requests as http_requests
from flask import current_app

_VALID_FORMATS = {'yara', 'sigma', 'suricata', 'zeek', 'wazuh', 'nse', 'crs', 'nova', 'elastic'}

# destination_key -> (path, minimum role). "admin" destinations are refused
# for a non-admin caller in _navigate() below — the model only ever picks a
# key from this closed vocabulary, it never gets to invent or supply a raw
# path, so there's no way a request can be steered somewhere unintended.
_ROUTES = {
    'home':                  ('/', 'user'),
    'my_rules':               ('/rule/owner_rules', 'user'),
    'rules_list':             ('/rule/rules_list', 'user'),
    'create_rule_page':       ('/rule/create_rule', 'user'),
    'bundles_list':           ('/bundle/list', 'user'),
    'create_bundle_page':     ('/bundle/create', 'user'),
    'workspaces':             ('/workspace/my_rules', 'user'),
    'dashboard':              ('/dashboard/', 'user'),
    'notifications':          ('/notifications/', 'user'),
    'my_tags':                ('/tags/my_tags', 'user'),
    'blog':                   ('/blog/', 'user'),
    'comments_hub':           ('/community/comments', 'user'),
    'leaderboard':            ('/account/contributor', 'user'),
    'profile':                ('/account/profil', 'user'),
    'ownership_requests':     ('/requests', 'user'),
    'attack_heatmap':         ('/attack/heatmap', 'user'),
    'docs':                   ('/docs/', 'user'),
    'docs_full':              ('/docs/full', 'user'),
    'settings':               ('/settings', 'user'),
    'connector_how_it_works': ('/connector/how-it-works', 'user'),
    'my_jobs':                ('/jobs/list', 'user'),
    'platform_insights':      ('/platform/insights', 'user'),
    'activity_feed':          ('/activity_feed', 'user'),
    'about':                  ('/about', 'user'),
    'privacy_policy':         ('/privacy', 'user'),
    'legal_notice':           ('/legal', 'user'),
    'admin_settings':         ('/admin/settings', 'admin'),
    'admin_logs':             ('/admin/logs', 'admin'),
    'admin_chatbot_history':  ('/chatbot/admin/conversations', 'admin'),
    'admin_users':            ('/account/admin/all_users', 'admin'),
    'admin_reports':          ('/report/admin', 'admin'),
    'admin_formats':          ('/rule/admin/manage_format_rule', 'admin'),
    'admin_similar_rules':    ('/admin/similar_rules', 'admin'),
    'trash':                  ('/rule/trash', 'admin'),
    'connectors':             ('/connector/list', 'admin'),
    # Deliberately NOT mapped: backups. A DB backup is a full data dump —
    # too sensitive to be reachable through an LLM-mediated interface at
    # all, even behind the admin check every other destination here gets.
    # Not a permission bug to fix, a destination that's intentionally absent.
}

SYSTEM_PROMPT = """Rulezet: open-source platform for cybersecurity detection rules (""" + ', '.join(sorted(_VALID_FORMATS)) + """). Users write/import rules, group into bundles, tag them (MISP/ATT&CK), propose edits, comment/vote, sync via connectors.
Always reply in English, even if the user writes in another language or in gibberish.
If the message is gibberish/unclear/off-topic -> action "ask", reply politely asking them to rephrase what they'd like to do — never leave "reply" blank.
If asked "what is Rulezet" -> brief chat summary of the above, nothing invented.
If asked what a detection rule is, or what a specific format does/is for -> action "chat", one concise accurate sentence, never invent a capability.
If asked what formats are supported/available/exist (this is NOT search_rules, there is nothing to search for) -> action "chat", answer exactly: """ + ', '.join(sorted(_VALID_FORMATS)) + """.

Pick ONE action, or just chat:
- create_rule: user wants a NEW rule WRITTEN ("write/create/make/generate a rule..."). Needs format (one of: """ + ', '.join(sorted(_VALID_FORMATS)) + """) and content. Title is auto-extracted from the rule content itself — never ask for one.
- create_bundle: needs name. Optional: description.
- navigate: user wants to GO TO a page. Needs "destination" = EXACTLY one key from this list, nothing else, never a raw URL: """ + ', '.join(sorted(_ROUTES)) + """
- search_rules: user wants to FIND existing rules ("rules for CVE-X", "rules tagged X") — NOT create_rule unless they said write/create/make/generate. Optional fields (lists unless noted): search (text), rule_type (usually one format, pass through as typed even if misspelled e.g. "ayara" — backend fuzzy-matches it; if the user names SEVERAL formats at once, e.g. "suricata and yara", pass them all as a list ["suricata","yara"] — backend proposes one link per format, the list can only be filtered by one at a time), tags, sources, licenses, vulnerabilities (CVE ids), attacks (ATT&CK ids), authors OR editors, terms (a value with NO field word attached, e.g. "tlp:clear" alone — backend tries it as tag, then CVE, then free text).

Rules:
1. Never invent a value. Field named but no value given ("a CVE", "a tag") -> "ask" for that exact missing value.
2. Several concrete values in one message -> ALL in one search_rules call, never split across turns.
3. One concrete value already known is enough to search immediately — never ask extra optional questions.
4. User replies "no"/"that's all"/"nothing else" after a clarifying question -> search_rules NOW with whatever's already known. Never re-ask, never switch action.
5. A value with no field word attached -> "terms", never guessed into tags/authors/etc.
6. No format mentioned at all -> omit rule_type, don't ask about it.

Examples:
"I want yara rules with a CVE" -> ask: "Which CVE?"
"yara rules tagged ransomware, CVE-2024-1234, by jdoe" -> search_rules {"rule_type":"yara","tags":["ransomware"],"vulnerabilities":["CVE-2024-1234"],"authors":["jdoe"]}
"rules for CVE-2026-15155?" -> search_rules {"vulnerabilities":["CVE-2026-15155"]}  (search, not create — no write/create verb)
...then "no just this param" -> search_rules {"vulnerabilities":["CVE-2026-15155"]}  (run it now, don't re-ask)
"found ayara rules" -> search_rules {"rule_type":"ayara"}  (pass through, backend fixes the typo)
"I want suricata and yara rules" -> search_rules {"rule_type":["suricata","yara"]}  (several formats -> list, never a single joined string)
"search tlp:clear" -> search_rules {"terms":["tlp:clear"]}
"take me to my rules" -> navigate {"destination":"my_rules"}
"go to admin logs" -> navigate {"destination":"admin_logs"}  (pass through regardless of admin status — backend checks permission, never decide it yourself)

Reply with ONLY a single JSON object, no other text, in exactly one of these shapes:

{"action": "create_rule", "params": {"format": "...", "content": "..."}, "reply": "short confirmation message"}
{"action": "create_bundle", "params": {"name": "...", "description": "..."}, "reply": "short confirmation message"}
{"action": "search_rules", "params": {"tags": ["..."], "vulnerabilities": ["CVE-..."], "attacks": ["T..."]}, "reply": "short confirmation message"}
{"action": "navigate", "params": {"destination": "one_of_the_keys_above"}, "reply": "short confirmation message"}
{"action": "ask", "params": {}, "reply": "a question asking the user for whatever specific value is still missing"}
{"action": "chat", "params": {}, "reply": "your normal conversational response"}

Never invent a rule's content or a missing required field yourself — use "ask" instead. Keep "reply" short and plain text (no markdown)."""


def call_ollama(messages: list) -> str:
    base = (current_app.config.get('OLLAMA_URL') or 'http://localhost:11434').rstrip('/')
    model = current_app.config.get('OLLAMA_MODEL') or 'qwen2.5:1.5b'
    try:
        resp = http_requests.post(
            f"{base}/api/chat",
            json={
                "model": model, "messages": messages, "stream": False, "format": "json",
                # keep_alive: without this Ollama unloads the model after 5 min
                # idle by default, so any pause between chat messages pays the
                # full cold-load cost again on the next one.
                "keep_alive": "30m",
                # num_ctx: Ollama defaults to a 2048-token context window,
                # which the system prompt alone (~1200+ tokens) plus history
                # can silently exceed — the model then quietly loses part of
                # its instructions instead of erroring. qwen2.5 supports a
                # much larger window; make room deliberately rather than
                # relying on the (small) default.
                "options": {"num_ctx": 8192},
            },
            # The system prompt alone is now ~2000 tokens (it grew a lot
            # across correctness fixes: disambiguation rules, the route
            # list, few-shot examples) — on CPU-only hardware with no GPU
            # that reprocesses on every message, 90s was cutting it close.
            timeout=180,
        )
        resp.raise_for_status()
    except http_requests.RequestException:
        raise ConnectionError(
            f"Could not reach Ollama at {base}. Is it running? "
            f"Try `ollama serve` and make sure `{model}` is pulled (`ollama pull {model}`)."
        )
    return resp.json().get('message', {}).get('content', '')


def _looks_like_rule_content(content: str) -> bool:
    """A hallucinated placeholder ('rule', 'test rule', ...) shouldn't reach
    the syntax validator and produce a confusing technical error — real rule
    content is never just one bare word, it always has some structure."""
    text = content.strip()
    if len(text) < 15:
        return False
    return any(c in text for c in ('{', ':', '\n'))


def _create_rule(user, params: dict) -> dict:
    from app.features.rule.rule_format.main_format import parse_rule_by_format, verify_syntax_rule_by_format

    fmt = (params.get('format') or '').strip().lower()
    content = params.get('content') or ''

    if not content or not _looks_like_rule_content(content):
        return {"success": False, "reply": "I still need the actual rule content to create it — paste the rule text you'd like me to use."}
    if fmt not in _VALID_FORMATS:
        return {"success": False, "reply": f"'{fmt}' isn't a format Rulezet knows — try one of: {', '.join(sorted(_VALID_FORMATS))}."}

    # Same syntax check the manual create-rule form runs, kept only for a
    # detailed error message — parse_rule_by_format below re-validates
    # internally too but only ever reports a generic "Invalid rule" on failure.
    valid, syntax_error = verify_syntax_rule_by_format({"format": fmt, "to_string": content})
    if not valid:
        return {"success": False, "reply": f"Your content doesn't pass the validator with this error: {syntax_error}"}

    # Same parse-and-import path /rule/create_rule's "Parse" tab uses — title
    # and other metadata are extracted straight from the rule content itself
    # (e.g. YARA's `rule <name> { ... }` name), so the model never has to
    # invent a title; duplicate-checking and creation happen in this one call.
    success, message, rule = parse_rule_by_format(content, user, fmt)
    if not success:
        if rule is not None:
            return {"success": False, "reply": message, "link": f"/rule/detail_rule/{rule.id}"}
        return {"success": False, "reply": f"Couldn't create the rule: {message}"}

    return {"success": True, "reply": f"Done — created \"{rule.title}\".", "link": f"/rule/detail_rule/{rule.id}"}


def _resolve_format(raw_fmt: str):
    """Fuzzy-match a user-typed format name against the known list, so small
    typos/variations ('ayara', 'sigmaa') still resolve correctly instead of
    being rejected outright.

    Returns (resolved_format_or_None, was_attempted). was_attempted is True
    whenever raw_fmt was non-empty — i.e. the user clearly tried to name a
    format — so the caller can tell "no format resolved" apart from
    "no format was even mentioned".
    """
    if not raw_fmt or not raw_fmt.strip():
        return None, False
    raw = raw_fmt.strip().lower()
    if raw in _VALID_FORMATS:
        return raw, True
    # Substring either direction catches the common typo shapes: "ayara"
    # contains "yara"; "yar" is contained in "yara".
    substring_matches = [f for f in _VALID_FORMATS if f in raw or raw in f]
    if len(substring_matches) == 1:
        return substring_matches[0], True
    # Fall back to a general fuzzy match for anything substring didn't catch.
    close = difflib.get_close_matches(raw, _VALID_FORMATS, n=1, cutoff=0.6)
    if close:
        return close[0], True
    return None, True


def _split_format_tokens(raw) -> list:
    """rule_type is usually one format, but the model sometimes gets several
    ("suricata and yara") — accept a real list, or split a string on commas/
    "and"/"or" so a Python-list repr like "['suricata', 'yara']" never reaches
    _resolve_format as one unrecognizable token."""
    if isinstance(raw, list):
        tokens = [str(v) for v in raw]
    else:
        tokens = re.split(r',|\band\b|\bor\b', str(raw), flags=re.IGNORECASE)
    return [t.strip(" []'\"") for t in tokens if t.strip(" []'\"")]


def _find_matching_tag(term: str):
    from app.core.db_class.db import Tag
    exact = Tag.query.filter(Tag.name.ilike(term)).first()
    if exact:
        return exact.name
    partial = Tag.query.filter(Tag.name.ilike(f"%{term}%")).first()
    return partial.name if partial else None


_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)


def _search_rules(params: dict) -> dict:
    """Build a /rule/rules_list URL with query params matching exactly what
    ruleList.js reads on mount (see its setup(): _p()/_arr() calls) — no
    search API is called here, the chatbot just hands off to the same
    filtered list page a user would reach by clicking filters themselves."""
    from urllib.parse import urlencode

    def _csv(key):
        val = params.get(key)
        if not val:
            return None
        if isinstance(val, list):
            val = [str(v).strip() for v in val if str(v).strip()]
            return ','.join(val) if val else None
        return str(val).strip() or None

    def _append(bucket: dict, key: str, value: str):
        existing = bucket.get(key)
        bucket[key] = f"{existing},{value}" if existing else value

    query = {}
    if params.get('search'):
        query['search'] = str(params['search']).strip()

    # Format: resolve fuzzily; only block the search with a question if the
    # user clearly tried to name one and nothing matched at all. The rules_list
    # page can only filter by ONE format at a time, so if several were named
    # ("suricata and yara") we resolve them all and build one link per format
    # further down instead of cramming a list into a single-value filter.
    multi_formats = None
    if params.get('rule_type'):
        tokens = _split_format_tokens(params['rule_type'])
        resolved_formats, unresolved = [], []
        for tok in tokens:
            resolved, attempted = _resolve_format(tok)
            if resolved:
                if resolved not in resolved_formats:
                    resolved_formats.append(resolved)
            elif attempted:
                unresolved.append(tok)
        if not resolved_formats:
            bad = ', '.join(unresolved) or str(params['rule_type'])
            return {
                "success": False,
                "reply": f"I don't recognize '{bad}' as a format — which one did you mean? ({', '.join(sorted(_VALID_FORMATS))})",
            }
        if len(resolved_formats) == 1:
            query['rule_type'] = resolved_formats[0]
        else:
            multi_formats = resolved_formats

    for key in ('tags', 'sources', 'licenses', 'vulnerabilities', 'attacks'):
        csv = _csv(key)
        if csv:
            query[key] = csv
    if _csv('editors'):
        query['editors'] = _csv('editors')
        query['person_mode'] = 'editor'
    elif _csv('authors'):
        query['authors'] = _csv('authors')

    # Unclassified terms — anything the model wasn't sure how to categorize
    # (e.g. "tlp:clear" typed with no "tag"/"cve" label attached). Try it as
    # a tag first (actual DB lookup, exact then partial match); if nothing
    # matches, try it as a CVE-shaped identifier; otherwise fall back to
    # plain free-text search rather than silently dropping it.
    for raw_term in (params.get('terms') or []):
        term = str(raw_term).strip()
        if not term:
            continue
        tag_match = _find_matching_tag(term)
        if tag_match:
            _append(query, 'tags', tag_match)
        elif _CVE_RE.match(term):
            _append(query, 'vulnerabilities', term.upper())
        else:
            query['search'] = f"{query['search']} {term}".strip() if query.get('search') else term

    if not query and not multi_formats:
        return {"success": False, "reply": "What should I search for — a tag, a CVE, an ATT&CK technique, an author?"}

    if multi_formats:
        links = [
            {"label": fmt, "url": '/rule/rules_list?' + urlencode({**query, 'rule_type': fmt})}
            for fmt in multi_formats
        ]
        names = ' or '.join(l["label"] for l in links)
        return {
            "success": True,
            "reply": f"I can only filter by one format at a time, so here's a link for each — {names}:",
            "links": links,
        }

    redirect = '/rule/rules_list?' + urlencode(query)
    return {"success": True, "reply": "Here's what I found — opening the filtered list.", "redirect": redirect}


def _create_bundle(user, params: dict) -> dict:
    from app.features.bundle import bundle_core as BundleModel

    name = (params.get('name') or '').strip()
    if not name:
        return {"success": False, "reply": "What should the bundle be called?"}

    form_dict = {"name": name, "description": params.get('description') or ''}
    bundle = BundleModel.create_bundle(form_dict, user)
    return {"success": True, "reply": f"Done — created bundle \"{name}\".", "link": f"/bundle/detail/{bundle.id}"}


def _navigate(user, params: dict) -> dict:
    dest = (params.get('destination') or '').strip().lower()
    entry = _ROUTES.get(dest)
    if not entry:
        return {"success": False, "reply": f"I don't know a page called '{dest}'."}

    path, min_role = entry
    if min_role == 'admin' and not user.is_admin():
        return {"success": False, "reply": "That page is admin-only, and your account isn't an admin — I can't take you there."}

    return {"success": True, "reply": f"Opening {dest.replace('_', ' ')}.", "redirect": path}


_CREATE_VERBS_RE = re.compile(r'\b(write|create|generate|make|build)\b', re.IGNORECASE)
_FORMAT_QUESTION_RE = re.compile(
    r'\b(what|which|list)\b.{0,30}\bformats?\b|\bformats?\b.{0,30}\b(available|supported|exist|do you support|can you use|are there)\b',
    re.IGNORECASE,
)


def _maybe_format_question(message: str):
    """This question has exactly one correct, context-free answer — answer it in
    code instead of trusting a small local model to reproduce a fixed list verbatim
    every time (it doesn't: it has misrouted this exact question to search_rules and
    once hallucinated "NSP" instead of "NSE")."""
    if _CREATE_VERBS_RE.search(message):
        return None
    if not _FORMAT_QUESTION_RE.search(message):
        return None
    return {
        "action": "chat",
        "reply": f"Rulezet supports: {', '.join(sorted(_VALID_FORMATS))}.",
        "success": True,
    }


_EXPLAIN_RE = re.compile(
    r"\b(what is|what's|what are|explain|tell me about|how does .{0,25}work|how (?:is|are) .{0,25}used)\b",
    re.IGNORECASE,
)

# One sentence per format, matching README.md's "Supported Rule Formats" table —
# kept here instead of left to the model for the same reason as _maybe_format_question:
# a fixed, factual answer shouldn't depend on a small model reproducing it faithfully.
_FORMAT_INFO = {
    'yara':     "YARA rules match patterns (strings, byte sequences, conditions) inside files or memory — the standard way to fingerprint and hunt for malware samples.",
    'sigma':    "Sigma is a generic, SIEM-agnostic signature format for log-based detections — you write one Sigma rule and it can be converted to many query languages.",
    'suricata': "Suricata rules describe network traffic patterns for an IDS/IPS engine — they inspect packets in real time and can alert on or block matching traffic.",
    'zeek':     "Zeek rules are scripts for the Zeek network monitor — they analyze traffic and produce rich logs/events rather than simple pattern matches.",
    'crs':      "CRS (OWASP Core Rule Set) rules protect web applications by detecting attack patterns like SQL injection or XSS at the WAF layer (ModSecurity/Coraza).",
    'nova':     "Nova rules hunt for malicious or anomalous behavior with a condition-based syntax, often used for threat hunting across structured data.",
    'nse':      "NSE (Nmap Scripting Engine) scripts extend Nmap to run scans, detect vulnerabilities, or gather extra info during a network scan.",
    'wazuh':    "Wazuh rules detect threats from host-based data — logs, file integrity, syscalls — feeding a SIEM/XDR pipeline.",
    'elastic':  "Elastic Security rules detect threats directly inside the Elastic Stack (logs, endpoint data) using EQL/KQL-style queries.",
}

_DETECTION_RULE_EXPLANATION = (
    "A detection rule is a piece of logic — a pattern, signature, or condition — written in a format like "
    + ', '.join(sorted(_VALID_FORMATS))
    + ", so a tool can automatically flag matching files, network traffic, logs, or behavior as suspicious or malicious."
)


def _maybe_explain_question(message: str):
    """Same rationale as _maybe_format_question: 'what is a detection rule' and
    'what is <format>' each have one fixed, context-free answer — skip the model
    entirely rather than risk it improvising or getting a format's purpose wrong."""
    if _CREATE_VERBS_RE.search(message):
        return None
    if not _EXPLAIN_RE.search(message):
        return None

    msg_lower = message.lower()
    for fmt in sorted(_FORMAT_INFO):
        if re.search(rf'\b{re.escape(fmt)}\b', msg_lower):
            return {"action": "chat", "reply": _FORMAT_INFO[fmt], "success": True}

    if re.search(r'\bdetection rules?\b', msg_lower):
        return {"action": "chat", "reply": _DETECTION_RULE_EXPLANATION, "success": True}

    return None


def _dispatch_message(user, history: list, message: str) -> dict:
    """history: list of {"role": "user"|"assistant", "content": "..."} from the current session only."""
    for shortcut_fn in (_maybe_format_question, _maybe_explain_question):
        shortcut = shortcut_fn(message)
        if shortcut is not None:
            return shortcut

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history[-10:])  # keep the prompt small — this is a prototype, not a full memory system
    messages.append({"role": "user", "content": message})

    raw = call_ollama(messages)
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError
    except (ValueError, TypeError):
        return {"action": "chat", "reply": raw.strip() or "Sorry, I didn't quite catch that.", "success": True}

    action = parsed.get('action', 'chat')
    params = parsed.get('params') or {}
    reply = parsed.get('reply') or ''

    if action == 'create_rule':
        # The model sometimes defaults to create_rule on garbage/unclear input
        # (seen live: gibberish text with no creation intent still got treated
        # as rule content, producing a confusing syntax-error reply). Only
        # honor create_rule if a creation verb appears somewhere in the recent
        # exchange — checking ONLY the current message broke legitimate
        # multi-turn flows: once we've asked "I still need the rule content",
        # the user's next reply is naturally just the content itself with no
        # verb at all, and that must still go through.
        recent_user_text = message + ' ' + ' '.join(
            h.get('content', '') for h in history[-6:] if h.get('role') == 'user'
        )
        if not _CREATE_VERBS_RE.search(recent_user_text):
            return {"action": "ask", "reply": "Sorry, I'm not sure what you'd like me to do — could you rephrase that?", "success": True}

        # The model must extract rule content from what the user actually
        # typed, never invent it — a "looks rule-shaped" check on the content
        # alone isn't enough (seen live: fabricated content with a colon/brace
        # still slipped through and hit the validator). Require it to really
        # appear, whitespace differences aside, in the user's own recent text.
        content = params.get('content') or ''
        normalize = lambda s: ' '.join(s.split())
        if content and normalize(content) not in normalize(recent_user_text):
            return {"action": "ask", "reply": "I still need the actual rule content to create it — paste the rule text you'd like me to use.", "success": True}

        outcome = _create_rule(user, params)
        return {"action": action, **outcome}
    if action == 'create_bundle':
        outcome = _create_bundle(user, params)
        return {"action": action, **outcome}
    if action == 'search_rules':
        outcome = _search_rules(params)
        return {"action": action, **outcome}
    if action == 'navigate':
        outcome = _navigate(user, params)
        return {"action": action, **outcome}

    # 'ask' or 'chat' — nothing to execute, just relay the model's reply.
    # A small model doesn't always follow the "never leave reply blank"
    # instruction (seen on real gibberish input) — backstop it in code rather
    # than showing the user an empty bubble.
    if not reply.strip():
        reply = "Sorry, I'm not sure what you mean — could you rephrase that?"
    return {"action": action, "reply": reply, "success": True}


def _persist_exchange(user, conversation_uuid: str, user_message: str, outcome: dict) -> str:
    """Store both sides of this exchange so admins can review, on
    /chatbot/admin/conversations, what every user asked and how the assistant
    responded — a fire-and-forget write, same spirit as log_activity: a DB
    hiccup here should never break the chat itself."""
    import uuid as uuid_mod

    from app import db
    from app.core.db_class.db import ChatbotConversation, ChatbotMessage
    from app.core.utils.activity_log import log_activity

    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        conv = None
        if conversation_uuid:
            conv = ChatbotConversation.query.filter_by(uuid=conversation_uuid, user_id=user.id).first()

        is_new = conv is None
        if is_new:
            conv = ChatbotConversation(uuid=conversation_uuid or str(uuid_mod.uuid4()), user_id=user.id,
                                       started_at=now, last_message_at=now)
            db.session.add(conv)
            db.session.flush()

        db.session.add(ChatbotMessage(conversation_id=conv.id, role='user', content=user_message, created_at=now))
        db.session.add(ChatbotMessage(
            conversation_id=conv.id, role='assistant', content=outcome.get('reply') or '',
            action=outcome.get('action'), success=outcome.get('success'),
            meta={k: outcome[k] for k in ('redirect', 'link', 'links') if k in outcome} or None,
            created_at=now,
        ))
        conv.message_count = (conv.message_count or 0) + 2
        if outcome.get('success') is False:
            conv.error_count = (conv.error_count or 0) + 1
        conv.last_message_at = now
        db.session.commit()

        if is_new:
            log_activity(
                "chatbot.conversation",
                f'Started a chatbot conversation: "{user_message[:120]}"',
                target_type="chatbot_conversation", target_id=conv.id, target_uuid=conv.uuid,
            )
        return conv.uuid
    except Exception:
        db.session.rollback()
        return conversation_uuid


def handle_message(user, history: list, message: str, conversation_uuid: str = None) -> dict:
    """history: list of {"role": "user"|"assistant", "content": "..."} from the current session only."""
    outcome = _dispatch_message(user, history, message)
    outcome['conversation_uuid'] = _persist_exchange(user, conversation_uuid, message, outcome)
    return outcome
