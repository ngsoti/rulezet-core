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
import re

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
    'velociraptor':           ('/velociraptor/list', 'admin'),
    'velociraptor_how_it_works': ('/velociraptor/how-it-works', 'admin'),
    # Deliberately NOT mapped: backups. A DB backup is a full data dump —
    # too sensitive to be reachable through an LLM-mediated interface at
    # all, even behind the admin check every other destination here gets.
    # Not a permission bug to fix, a destination that's intentionally absent.
}

SYSTEM_PROMPT = """You are Rulezy, Rulezet's assistant — that IS your name. When addressed by name ("hi Rulezy", "are you good, Rulezy?") or asked how you are, respond naturally in first person as yourself (e.g. "Doing great, thanks for asking!") — never talk about "Rulezy" as if it were someone else, and never echo the name back confused about who it refers to.
Rulezet: open-source platform for cybersecurity detection rules (""" + ', '.join(sorted(_VALID_FORMATS)) + """). Users write/import rules, group into bundles, tag them (MISP/ATT&CK), propose edits, comment/vote, sync via connectors.
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
"yara rules tagged ransomware, CVE-2024-1234, by Florian Roth" -> search_rules {"rule_type":"yara","tags":["ransomware"],"vulnerabilities":["CVE-2024-1234"],"authors":["Florian Roth"]}
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


# Calling Ollama directly used to happen here (call_ollama()) — now routed
# through ChatbotAgent + the shared OllamaClient (app/features/ai/ai_core.py),
# see _dispatch_message() below, so the concurrency governor, rate limiting,
# and unified execution logging apply here too instead of being reimplemented.


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
    return {"success": True, "reply": _search_result_reply(query), "redirect": redirect}


def _search_result_reply(query: dict) -> str:
    """A live count so the reply is honest about whether anything actually
    matched, instead of always claiming "here's what I found" even for a
    filter that turns up nothing — a count check failing for any reason
    (schema drift, etc.) must never block the redirect itself, so this
    always falls back to the old generic reply rather than raising."""
    try:
        from app.features.rule import rule_core as RuleModel

        _split = lambda key: query[key].split(',') if query.get(key) else None
        pagination = RuleModel.get_rules_data_table(
            page=1, per_page=1,
            search=query.get('search'),
            rule_type=query.get('rule_type'),
            author=_split('authors'),
            editor_names=_split('editors'),
            vulnerabilities=_split('vulnerabilities'),
            licenses=_split('licenses'),
            tags=_split('tags'),
            attacks=_split('attacks'),
            source=_split('sources'),
        )
        count = pagination.total
    except Exception:
        return "Here's what I found — opening the filtered list."

    if count == 0:
        return "I didn't find anything matching that, but here's the filtered view anyway in case I got a field wrong."
    return f"Found {count} matching rule{'s' if count != 1 else ''} — opening the filtered list."


# A CVE written without the literal "CVE-" prefix ("cve 3456-4567") and a
# genuinely open-ended topical ask ("do you have rule to detect Fortinet
# exploitation?") both confirmed to make the small local model hallucinate —
# action "chat" with a made-up "found X rules" reply for the first, action
# "chat" with the literal reply "ask" for the second, neither one actually
# calling search_rules. Handle both deterministically instead of trusting
# the model every time, same rationale as _maybe_format_question/
# _maybe_explain_question below.
_CVE_MENTION_RE = re.compile(r'\bcve[\s-]*(\d{4}-\d{2,7})\b', re.IGNORECASE)
_OPEN_SEARCH_RE = re.compile(
    r'''
    (?:
        \b(?:do\ you\ have|have\ you\ got|got\ any|is\ there|are\ there)\b.{0,40}?
        \b(?:rules?|detections?|signatures?)\b
      |
        \b(?:rules?|detections?|signatures?)\b
    )
    \s*(?:to\ detect|for|about|on|related\ to|regarding|that\ detect|that\ match|matching)\s+
    (?P<topic>.+?)\??\s*$
    ''',
    re.IGNORECASE | re.VERBOSE,
)
# "rules for a CVE" / "rules about a tag" — the field is named but no real
# value is given, which per the system prompt's own rules should be an "ask"
# for that value, not a free-text search for the literal words "a cve".
_VAGUE_TOPIC_RE = re.compile(r'^(?:a|an|some|any)\s+\w+$', re.IGNORECASE)

# The backend's free-text search is a single ILIKE("%...%") substring match
# (filter_rules() in rule_core.py), not a tokenized multi-word search — the
# full phrase "Fortinet exploitation" almost never appears verbatim in a
# title/description, while "Fortinet" alone matches broadly. Strip generic
# trailing security-jargon words and keep only the specific term(s).
_GENERIC_TOPIC_WORDS = {
    'exploitation', 'exploit', 'exploits', 'attack', 'attacks', 'activity',
    'vulnerability', 'vulnerabilities', 'campaign', 'campaigns', 'threat',
    'threats', 'malware', 'actor', 'actors', 'technique', 'techniques',
    'behavior', 'behaviour', 'incident', 'incidents', 'rule', 'rules',
}


def _simplify_search_topic(topic: str) -> str:
    words = topic.split()
    while len(words) > 1 and words[-1].lower().strip('.,!?') in _GENERIC_TOPIC_WORDS:
        words.pop()
    return ' '.join(words) if words else topic


# A source repo URL named alongside a rules-search framing ("do we have
# rules from https://github.com/X/Y") — same failure confirmed live: the
# model chatted a made-up yes/no answer instead of calling search_rules.
_URL_RE = re.compile(r'https?://\S+')
_RULE_MENTION_RE = re.compile(r'\b(?:rules?|detections?|signatures?)\b', re.IGNORECASE)

# MITRE ATT&CK technique id, e.g. "T1055" or "T1055.001".
_ATTACK_ID_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.IGNORECASE)

# "tagged ransomware" / "tag: apt" / "with the ransomware tag" — a word
# immediately next to "tag(ged)" is unambiguous, but common enough stray
# matches ("what tags are there") need excluding via _TAG_STOPWORDS.
_TAG_RE = re.compile(
    r'\btag(?:ged|s)?\b\s*(?:as|is|with|for|:)?\s*["\']?(?P<t1>[a-z0-9][\w:.\-]*)["\']?'
    r'|\bthe\s+["\']?(?P<t2>[a-z0-9][\w:.\-]*)["\']?\s+tag\b',
    re.IGNORECASE,
)
_TAG_STOPWORDS = {'are', 'is', 'exist', 'exists', 'available', 'there', 'do', 'does', 'can', 'a', 'an'}

_EDITOR_RE = re.compile(r'\bedited\s+by\s+(?P<v>[\w.\-]+(?:\s+[\w.\-]+)?)', re.IGNORECASE)
_AUTHOR_RE = re.compile(
    r'\b(?:written|authored|created|made)\s+by\s+(?P<a1>[\w.\-]+(?:\s+[\w.\-]+)?)'
    r'|\brules?\s+by\s+(?P<a2>[\w.\-]+(?:\s+[\w.\-]+)?)\b',
    re.IGNORECASE,
)
# "rules by author" / "rules by tag" means "filter BY that criterion", not a
# literal person named "author" or "tag" — never treat these as a real name.
_PERSON_STOPWORDS = {
    'tag', 'tags', 'author', 'authors', 'editor', 'editors', 'format', 'formats',
    'type', 'types', 'license', 'licenses', 'cve', 'source', 'sources',
}

# A clear request verb turns a bare format mention into real search intent
# ("show me yara rules") — without one, a format name alone stays too
# ambiguous ("does Rulezet support yara" must never search).
_REQUEST_VERB_RE = re.compile(r'\b(?:show|list|browse|find|get|give)\b', re.IGNORECASE)


def _extract_rule_type_from_message(message: str):
    msg_lower = message.lower()
    for fmt in sorted(_VALID_FORMATS):
        if re.search(rf'\b{re.escape(fmt)}\b', msg_lower):
            return fmt
    return None


def _extract_tag_from_message(message: str):
    """Only returns a tag that actually exists (via _find_matching_tag) —
    a confidently-wrong tag filter is worse than not filtering at all."""
    m = _TAG_RE.search(message)
    if not m:
        return None
    candidate = (m.group('t1') or m.group('t2') or '').strip().lower()
    if not candidate or candidate in _TAG_STOPWORDS:
        return None
    return _find_matching_tag(candidate)


def _maybe_search_rules_shortcut(message: str):
    """Converts an open-phrase rule search into the same structured params
    search_rules already accepts — a small local model is unreliable at
    recognizing this intent reliably beyond its own few-shot examples
    (confirmed live: a CVE without the "CVE-" prefix, an open topical ask,
    and a source-repo URL all got a hallucinated "chat" reply instead of an
    actual search). Every field detected below combines into one search;
    only a bare format name or a vague topic needs a clearer signal (a
    request verb, or "rule(s) for/about/to detect X" phrasing) before it's
    trusted, to avoid hijacking purely informational questions."""
    if _CREATE_VERBS_RE.search(message):
        return None

    params = {}
    precise_hit = False

    cve_match = _CVE_MENTION_RE.search(message)
    if cve_match:
        params['vulnerabilities'] = [f"CVE-{cve_match.group(1)}".upper()]
        precise_hit = True

    url_match = _URL_RE.search(message) if _RULE_MENTION_RE.search(message) else None
    if url_match:
        params['sources'] = [url_match.group(0).rstrip('.,!?)')]
        precise_hit = True

    attack_match = _ATTACK_ID_RE.search(message)
    if attack_match:
        params['attacks'] = [attack_match.group(0).upper()]
        precise_hit = True

    tag = _extract_tag_from_message(message)
    if tag:
        params['tags'] = [tag]
        precise_hit = True

    editor_match = _EDITOR_RE.search(message)
    editor_name = editor_match.group('v').strip() if editor_match else None
    if editor_name and editor_name.lower() not in _PERSON_STOPWORDS:
        params['editors'] = [editor_name]
        precise_hit = True
    else:
        author_match = _AUTHOR_RE.search(message)
        author_name = (author_match.group('a1') or author_match.group('a2')).strip() if author_match else None
        if author_name and author_name.lower() not in _PERSON_STOPWORDS:
            params['authors'] = [author_name]
            precise_hit = True

    # A repo path/name often contains a format-like substring of its own
    # ("Yara-Rules", "sigma-hq") — scan for rule_type with the URL itself
    # removed so the repo's name never gets misread as a format filter.
    format_scan_text = message.replace(url_match.group(0), ' ') if url_match else message
    rule_type = _extract_rule_type_from_message(format_scan_text)
    if rule_type:
        params['rule_type'] = rule_type
        if precise_hit or _REQUEST_VERB_RE.search(message):
            precise_hit = True

    if not precise_hit:
        open_match = _OPEN_SEARCH_RE.search(message)
        if open_match:
            topic = open_match.group('topic').strip(' ?.!')
            if topic and not _VAGUE_TOPIC_RE.match(topic):
                params['search'] = _simplify_search_topic(topic)
                precise_hit = True

    if not precise_hit or not params:
        return None
    return _search_rules(params)


def _create_bundle(user, params: dict) -> dict:
    from app.features.bundle import bundle_core as BundleModel

    name = (params.get('name') or '').strip()
    if not name:
        return {"success": False, "reply": "What should the bundle be called?"}

    form_dict = {"name": name, "description": params.get('description') or ''}
    bundle = BundleModel.create_bundle(form_dict, user)
    return {"success": True, "reply": f"Done — created bundle \"{name}\".", "link": f"/bundle/detail/{bundle.id}"}


# "create a bundle called X" — confirmed live, and worse than the other
# hallucinations: the model didn't even attempt the action, it echoed the
# system prompt's own JSON template PLACEHOLDER text verbatim
# ({"reply": "short confirmation message"}) as if it were a real answer,
# 100% reproducible across several phrasings. A name is the only thing
# create_bundle actually needs, so skip the model for this shape entirely.
_BUNDLE_NAME_RE = re.compile(
    r'\bbundle\b\s*(?:called|named|titled)\s+["\']?(?P<name>.+?)["\']?[.!?]?\s*$',
    re.IGNORECASE,
)


def _maybe_create_bundle_shortcut(message: str, user):
    if not _CREATE_VERBS_RE.search(message):
        return None
    m = _BUNDLE_NAME_RE.search(message)
    if not m:
        return None
    name = m.group('name').strip()
    if not name:
        return None
    outcome = _create_bundle(user, {'name': name})
    return {"action": "create_bundle", **outcome}


def _navigate(user, params: dict) -> dict:
    dest = (params.get('destination') or '').strip().lower()
    entry = _ROUTES.get(dest)
    if not entry:
        return {"success": False, "reply": f"I don't know a page called '{dest}'."}

    path, min_role = entry
    if min_role == 'admin' and not user.is_admin():
        return {"success": False, "reply": "That page is admin-only, and your account isn't an admin — I can't take you there."}

    return {"success": True, "reply": f"Opening {dest.replace('_', ' ')}.", "redirect": path}


# "go to my tags" / "take me to the dashboard" — confirmed live: the model
# sometimes just chats the raw destination KEY back as text ("my_tags")
# instead of wrapping it in a real navigate action, so nothing ever
# redirects. Checked in order — first phrase match wins, most specific first.
_NAVIGATE_VERB_RE = re.compile(
    r'\b(?:go\s+to|take\s+me\s+to|navigate\s+to|bring\s+me\s+to|open\s+the|show\s+me\s+(?:the\s+)?)\b',
    re.IGNORECASE,
)
_NAVIGATE_KEYWORDS = (
    ('my_rules', ('my rule',)),
    ('rules_list', ('rule list', 'all rules', 'browse rules', 'the rules page')),
    ('my_tags', ('my tag',)),
    ('create_bundle_page', ('create a bundle', 'new bundle page', 'add a bundle')),
    ('bundles_list', ('bundle list', 'all bundles', 'my bundles', 'the bundles')),
    ('create_rule_page', ('create a rule', 'new rule page', 'add a rule')),
    ('workspaces', ('workspace',)),
    ('dashboard', ('dashboard',)),
    ('notifications', ('notification',)),
    ('blog', ('blog',)),
    ('comments_hub', ('comment',)),
    ('leaderboard', ('leaderboard', 'contributor', 'top contributors')),
    ('profile', ('my profile', 'my account', 'account settings')),
    ('ownership_requests', ('ownership request',)),
    ('attack_heatmap', ('attack heatmap', 'att&ck heatmap', 'attack matrix')),
    ('docs_full', ('full docs', 'full documentation')),
    ('docs', ('docs', 'documentation')),
    ('settings', ('settings',)),
    ('my_jobs', ('my job', 'job list', 'jobs page')),
    ('activity_feed', ('activity feed', 'recent activity')),
    ('about', ('about page', 'about rulezet')),
    ('privacy_policy', ('privacy policy',)),
    ('legal_notice', ('legal notice',)),
    ('trash', ('trash', 'deleted rule')),
    ('connectors', ('connector list', 'the connectors')),
    ('connector_how_it_works', ('how connectors work', 'connector documentation')),
    ('velociraptor_how_it_works', ('how velociraptor works',)),
    ('velociraptor', ('velociraptor',)),
    ('admin_settings', ('admin settings', 'instance settings')),
    ('admin_logs', ('admin logs', 'activity logs', 'the logs')),
    ('admin_chatbot_history', ('chatbot conversations', 'chatbot history')),
    ('admin_users', ('all users', 'manage users', 'user list')),
    ('admin_reports', ('admin reports', 'the reports')),
    ('admin_formats', ('manage formats', 'rule formats page')),
    ('admin_similar_rules', ('similar rules',)),
    ('home', ('the home page', 'the homepage')),
)


def _maybe_navigate_shortcut(message: str):
    if not _NAVIGATE_VERB_RE.search(message):
        return None
    msg_lower = message.lower()
    for dest, phrases in _NAVIGATE_KEYWORDS:
        if any(p in msg_lower for p in phrases):
            return dest
    return None


_CREATE_VERBS_RE = re.compile(r'\b(write|create|generate|make|build)\b', re.IGNORECASE)

# "I don't know, whatever you want" — a user punting the "what should it
# detect?" question back to the bot instead of answering it.
_PUNT_RE = re.compile(
    r"\b(i\s*don'?t\s*know|idk|whatever\s+you\s+want|whatever\s+works|you\s+decide|"
    r"up\s+to\s+you|your\s+choice|you\s+choose|surprise\s+me|no\s+preference|"
    r"don'?t\s+care|anything\s+you\s+want|as\s+you\s+(?:want|wish|like))\b",
    re.IGNORECASE,
)
_BETA_CANNOT_INVENT_REPLY = (
    "I'm just a prototype, so I can't freely invent a rule out of nothing — "
    "I need you to paste the actual rule content, or at least describe exactly "
    "what it should detect. If you'd rather I draft one from a description, "
    "try the \"Generate with AI\" tab on the create-rule page instead — that "
    "tool is actually built for it."
)

_FORMAT_QUESTION_RE = re.compile(
    r'\b(what|which|list)\b.{0,30}\bformats?\b|\bformats?\b.{0,30}\b(available|supported|exist|do you support|can you use|are there)\b',
    re.IGNORECASE,
)

# A bare "hi"/"hello" with nothing else has one obvious reply — a small
# model on the simplest possible input still confirmed live to sometimes
# just echo the greeting back verbatim instead of actually replying.
_GREETING_ONLY_RE = re.compile(
    r'^\s*(?:hi+|hello+|hey+|yo+|sup|howdy|greetings|good\s*(?:morning|afternoon|evening))\s*[!.,]*\s*$',
    re.IGNORECASE,
)
_GREETING_REPLY = "Hi! What can I do for you — create a rule, put together a bundle, or go dig through the rule list?"


def _maybe_greeting(message: str):
    if not _GREETING_ONLY_RE.match(message):
        return None
    return {"action": "chat", "reply": _GREETING_REPLY, "success": True}


# "who are you" / "what's your name" — confirmed live: even with the system
# prompt now stating the assistant's name is Rulezy, the model still answers
# "I am Rulezet" (the platform's name, mentioned one line later in the same
# prompt) instead of its own. A fixed identity answer, same rationale as
# _maybe_format_question below — don't trust a small model to keep two
# similar-looking proper nouns straight.
_WHO_ARE_YOU_RE = re.compile(
    r"\b(who are you|what'?s your name|what is your name|who'?s rulezy|what is rulezy)\b",
    re.IGNORECASE,
)
_WHO_ARE_YOU_REPLY = (
    "I'm Rulezy — Rulezet's assistant. I can create a rule or a bundle for you, "
    "or dig through the rule list by tag, CVE, ATT&CK technique, author, and more."
)


def _maybe_who_are_you(message: str):
    if not _WHO_ARE_YOU_RE.search(message):
        return None
    return {"action": "chat", "reply": _WHO_ARE_YOU_REPLY, "success": True}


# "I want you to create a new yara rule" — a create-rule REQUEST with no
# content yet. Confirmed live: the model is inconsistent here — sometimes
# it correctly asks for the content, sometimes it replies as if it were
# already doing something ("Creating a new yara rule...") without asking
# for the one thing it actually needs. Ask deterministically instead of
# leaving this to chance, same rationale as the other shortcuts.
def _maybe_create_rule_intent_shortcut(message: str):
    if not _CREATE_VERBS_RE.search(message):
        return None
    if not _RULE_MENTION_RE.search(message):
        return None
    if _looks_like_rule_content(message):
        return None  # real content is already here — a later shortcut handles this
    fmt = _extract_rule_type_from_message(message)
    if fmt:
        return {
            "action": "ask",
            "reply": f"Sure — paste the {fmt} rule content you'd like me to create, and I'll validate and save it.",
            "success": True,
        }
    return {
        "action": "ask",
        "reply": f"Sure — which format ({', '.join(sorted(_VALID_FORMATS))}), and paste the rule content you'd like me to create?",
        "success": True,
    }


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


# The exact placeholder strings from SYSTEM_PROMPT's own JSON-shape examples,
# plus the action names and every navigate destination key — all confirmed
# or plausible things the model could echo back verbatim as a "reply"
# instead of actually answering.
_TEMPLATE_LEAK_REPLIES = {
    'short confirmation message',
    'a question asking the user for whatever specific value is still missing',
    'your normal conversational response',
    'ask', 'chat', 'create_rule', 'create_bundle', 'navigate', 'search_rules',
} | set(_ROUTES)

# A looser variant confirmed live: instead of real JSON, the model wrote out
# its intended call as pseudo-structured text — "create_bundle, name: 'X',
# description: 'Y'" — as the chat reply itself. Any reply that starts with
# one of the action names immediately followed by a separator is that same
# leak, not a real answer.
_ACTION_LEAK_RE = re.compile(
    r'^(?:create_rule|create_bundle|navigate|search_rules|ask|chat)\s*[:,(]',
    re.IGNORECASE,
)


def _looks_like_template_leak(reply: str) -> bool:
    stripped = reply.strip()
    if stripped.strip('.').lower() in _TEMPLATE_LEAK_REPLIES:
        return True
    return bool(_ACTION_LEAK_RE.match(stripped))


def _agent_gate_check(user):
    """Mirrors AIAgent.run()'s own enabled/rate-limit checks (ai_core.py) —
    every shortcut below deliberately skips run() entirely (that's the
    point, to skip the unreliable model for a case we can answer for
    certain), but skipping run() must never also skip the admin's kill
    switch or a user's rate limit. Checked once, up front, so it applies
    uniformly whether a message ends up shortcut-served or model-served.
    Returns a refusal dict if blocked, else None."""
    from app.core.db_class.db import AIAgentConfig
    from app.features.ai.ai_core import check_rate_limit

    agent_config = AIAgentConfig.query.filter_by(agent_key='chatbot').first()
    if agent_config is not None and not agent_config.enabled:
        return {
            "action": "chat", "reply": "This AI feature is currently disabled.",
            "success": False, "_agent_status": "disabled",
        }

    max_per_hour = agent_config.max_per_hour if agent_config else None
    if not check_rate_limit(getattr(user, 'id', None), 'chatbot', max_per_hour):
        return {
            "action": "chat", "reply": "Rate limit reached, try again later.",
            "success": False, "_agent_status": "rate_limited",
        }
    return None


def _dispatch_message(user, history: list, message: str) -> dict:
    """history: list of {"role": "user"|"assistant", "content": "..."} from the current session only."""
    gate = _agent_gate_check(user)
    if gate is not None:
        return gate

    for shortcut_fn in (_maybe_greeting, _maybe_who_are_you, _maybe_format_question, _maybe_explain_question,
                        _maybe_search_rules_shortcut, _maybe_create_rule_intent_shortcut):
        shortcut = shortcut_fn(message)
        if shortcut is not None:
            return shortcut

    # "go to my tags" / "take me to the dashboard" — confirmed live: the
    # model sometimes chats the raw destination key back as plain text
    # instead of a real navigate action, so nothing ever redirects. Needs
    # user for the admin-permission check, so it can't join the loop above.
    nav_dest = _maybe_navigate_shortcut(message)
    if nav_dest:
        outcome = _navigate(user, {'destination': nav_dest})
        return {"action": "navigate", **outcome}

    # "create a bundle called X" — confirmed live to be the model's worst
    # failure of all: it echoed the JSON template's own placeholder text
    # back verbatim instead of attempting the action at all.
    bundle_shortcut = _maybe_create_bundle_shortcut(message, user)
    if bundle_shortcut is not None:
        return bundle_shortcut

    # A message that's just pasted rule content, with a create-verb somewhere
    # in recent history, is unambiguous — but confirmed live: handed the
    # exact rule text as the message, the model replied "Please provide the
    # content of the rule" instead of ever calling create_rule (it had
    # already asked for the content one turn earlier and didn't recognize
    # this as the answer). Bypass the model's own action-classification for
    # this one turn instead of trusting it, same rationale as the shortcuts
    # above — needs user/history unlike those, so it can't join that loop.
    if _looks_like_rule_content(message):
        recent_user_text = message + ' ' + ' '.join(
            h.get('content', '') for h in history[-6:] if h.get('role') == 'user'
        )
        if _CREATE_VERBS_RE.search(recent_user_text):
            fmt = _extract_rule_type_from_message(recent_user_text)
            if fmt:
                outcome = _create_rule(user, {'format': fmt, 'content': message})
                return {"action": "create_rule", **outcome}

    # "I don't know, whatever you want" after being asked what a rule should
    # detect — confirmed live: the model just gets confused and gives a
    # generic non-answer. This chatbot deliberately never invents rule
    # content on its own (create_rule requires the content to really appear
    # in what the user typed — a prior fix for hallucinated content slipping
    # past the validator), so answer honestly about that limit instead of
    # leaving the user with a reply that doesn't explain anything.
    if _PUNT_RE.search(message):
        recent_user_text = message + ' ' + ' '.join(
            h.get('content', '') for h in history[-6:] if h.get('role') == 'user'
        )
        if (_CREATE_VERBS_RE.search(recent_user_text) and _RULE_MENTION_RE.search(recent_user_text)
                and not re.search(r'\bbundles?\b', recent_user_text, re.IGNORECASE)):
            return {"action": "chat", "reply": _BETA_CANNOT_INVENT_REPLY, "success": True}

    from app.features.ai.ai_core import get_agent

    # keep the prompt small — this is a prototype, not a full memory system
    result = get_agent('chatbot').run(
        user=user, history=history[-10:], message=message, input_summary=message[:300],
    )
    if not result.ok:
        return {
            "action": "chat",
            "reply": result.error or "Sorry, something went wrong.",
            "success": False,
            "_agent_status": result.meta.get('status'),
        }

    action = result.meta.get('action', 'chat')
    params = result.meta.get('params') or {}
    reply = result.content or ''

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
    # instruction (seen on real gibberish input), and sometimes leaks its own
    # JSON template verbatim as if it were a real answer instead of filling
    # it in — confirmed live: create_bundle got back the literal placeholder
    # "short confirmation message", and a navigate request got the raw
    # destination key ("my_tags") as chat text. Backstop both in code rather
    # than showing the user template debris.
    if not reply.strip() or _looks_like_template_leak(reply):
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
