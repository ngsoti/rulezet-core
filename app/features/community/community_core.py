import datetime

from sqlalchemy import and_, case, func, literal, or_
from sqlalchemy.orm import aliased

from app import db
from app.core.db_class.db import (
    BlogPost,
    Bundle,
    Rule,
    RuleEditProposal,
    UnifiedComment,
    User,
)
from app.features.rule.rule_core import _active

_SORT_KEYS = {'last_activity', 'comment_count', 'title', 'object_type'}
# Kept for callers using the original recency-style sort values
_LEGACY_SORTS = {
    'recent':        ('last_activity', 'desc'),
    'oldest':        ('last_activity', 'asc'),
    'most_comments': ('comment_count', 'desc'),
}
_PARTICIPANTS_MAX = 5


def object_context_path(object_type, object_id, blog_slug=None):
    """Relative detail-page path for a commented object.

    Single source of truth for comment context links — also used by
    comment_api's GitHub-issue deep links."""
    if object_type == 'rule':
        return f'/rule/detail_rule/{object_id}'
    if object_type == 'bundle':
        return f'/bundle/detail/{object_id}'
    if object_type == 'proposal':
        return f'/rule/proposal_content_discuss?id={object_id}'
    if object_type == 'blog_post':
        return f'/blog/post/{blog_slug or object_id}'
    return '/'


def comment_deep_link(base_path, comment_id):
    sep = '&' if '?' in base_path else '?'
    return f'{base_path}{sep}comment={comment_id}'


def _parse_date(value, end_of_day=False):
    try:
        d = datetime.datetime.strptime(value, '%Y-%m-%d')
    except (TypeError, ValueError):
        return None
    if end_of_day:
        d += datetime.timedelta(days=1)
    return d


def _apply_hub_filters(query, user, scope, search, date_from, date_to):
    query = query.filter(UnifiedComment.is_active == True)

    if scope == 'main':
        query = query.filter(UnifiedComment.parent_id == None)
    if search:
        query = query.filter(UnifiedComment.content.ilike(f'%{search}%'))

    df = _parse_date(date_from)
    if df:
        query = query.filter(UnifiedComment.created_at >= df)
    dt = _parse_date(date_to, end_of_day=True)
    if dt:
        query = query.filter(UnifiedComment.created_at < dt)

    # Private bundles are visible to their owner and admins only — their
    # comments must never surface here for anyone else (same rule as the
    # notification logic in comment_api: is_public = bool(bundle.access)).
    if not (user.is_authenticated and user.is_admin()):
        hidden_bundle_ids = db.session.query(Bundle.id).filter(
            Bundle.access == False,
            Bundle.user_id != (user.id if user.is_authenticated else -1),
        )
        query = query.filter(~and_(
            UnifiedComment.object_type == 'bundle',
            UnifiedComment.object_id.in_(hidden_bundle_ids),
        ))

    # Soft-deleted rules are hidden everywhere on the platform — their groups
    # would deep-link to 404s. This also hides proposal-comments for such a
    # rule, since those get folded into the rule's own subject below.
    deleted_rule_ids = db.session.query(Rule.id).filter(Rule.is_deleted == True)
    query = query.filter(~and_(
        UnifiedComment.object_type == 'rule',
        UnifiedComment.object_id.in_(deleted_rule_ids),
    ))
    orphan_proposal_ids = db.session.query(RuleEditProposal.id).filter(
        RuleEditProposal.rule_id.in_(deleted_rule_ids)
    )
    query = query.filter(~and_(
        UnifiedComment.object_type == 'proposal',
        UnifiedComment.object_id.in_(orphan_proposal_ids),
    ))

    return query


def _load_objects_meta(rows):
    ids = {}
    for r in rows:
        ids.setdefault(r.subject_type, set()).add(r.subject_id)

    meta = {}

    if ids.get('rule'):
        for rule in _active().filter(Rule.id.in_(ids['rule'])).all():
            meta[('rule', rule.id)] = {
                'title': rule.title or f'Rule #{rule.id}',
                'link':  object_context_path('rule', rule.id),
            }

    if ids.get('bundle'):
        for bundle in Bundle.query.filter(Bundle.id.in_(ids['bundle'])).all():
            meta[('bundle', bundle.id)] = {
                'title':      bundle.name,
                'link':       object_context_path('bundle', bundle.id),
                'is_private': not bool(bundle.access),
            }

    if ids.get('blog_post'):
        for post in BlogPost.query.filter(BlogPost.id.in_(ids['blog_post'])).all():
            meta[('blog_post', post.id)] = {
                'title': post.title,
                'link':  object_context_path('blog_post', post.id, blog_slug=post.uuid),
            }

    return meta


def _pair_filter(pairs):
    """OR of (object_type == t AND object_id == i) for each pair — the
    portable way to match a heterogeneous set of (type, id) rows across
    SQLite (tests) and Postgres alike (tuple_ IN isn't reliable on both)."""
    return or_(*[
        and_(UnifiedComment.object_type == t, UnifiedComment.object_id == i)
        for t, i in pairs
    ])


def _group_categories_batch(rows, user, scope, search, date_from, date_to):
    """
    Batched version of the per-row "buckets of comments folded into one hub
    row" computation — one grouped query for every non-rule subject, one for
    every rule's own comments, one to list every proposal across every rule,
    and one grouped query for every proposal's comment count, instead of
    2-3 queries PER ROW (previously O(rows + total_proposals) round trips).

    A bundle/blog_post subject always has exactly one bucket (itself). A rule
    subject can have several: its own plain comments, plus one bucket per
    edit proposal that has discussion — these are shown as sub-categories in
    the UI ("Simple comments" vs "Suggested edit (status)") rather than as
    separate hub rows, since they're really the same conversation about the
    same rule.

    Returns {(subject_type, subject_id): [categories...]}.
    """
    result = {}

    non_rule_keys = [(r.subject_type, r.subject_id) for r in rows if r.subject_type != 'rule']
    rule_ids = [r.subject_id for r in rows if r.subject_type == 'rule']

    if non_rule_keys:
        q = db.session.query(
            UnifiedComment.object_type,
            UnifiedComment.object_id,
            func.count(UnifiedComment.id).label('cnt'),
        ).filter(_pair_filter(non_rule_keys))
        q = _apply_hub_filters(q, user, scope, search, date_from, date_to)
        q = q.group_by(UnifiedComment.object_type, UnifiedComment.object_id)
        counts = {(r.object_type, r.object_id): r.cnt for r in q.all()}

        # No 'link' here for blog_post: the correct URL needs the post's uuid
        # slug, which the caller (not this function) already resolved onto
        # the group's own `link` — the frontend falls back to that for the
        # only-one-category case, so this bucket doesn't need its own link.
        for t, i in non_rule_keys:
            result[(t, i)] = [{
                'key':         f'{t}:{i}',
                'kind':        'comment',
                'label':       'Comments',
                'object_type': t,
                'object_id':   i,
                'count':       counts.get((t, i), 0),
            }]

    if rule_ids:
        rq = db.session.query(
            UnifiedComment.object_id,
            func.count(UnifiedComment.id).label('cnt'),
        ).filter(UnifiedComment.object_type == 'rule', UnifiedComment.object_id.in_(rule_ids))
        rq = _apply_hub_filters(rq, user, scope, search, date_from, date_to)
        rq = rq.group_by(UnifiedComment.object_id)
        rule_counts = {r.object_id: r.cnt for r in rq.all()}

        proposals = RuleEditProposal.query.filter(RuleEditProposal.rule_id.in_(rule_ids)).all()
        proposals_by_rule = {}
        for p in proposals:
            proposals_by_rule.setdefault(p.rule_id, []).append(p)

        prop_counts = {}
        all_proposal_ids = [p.id for p in proposals]
        if all_proposal_ids:
            pq = db.session.query(
                UnifiedComment.object_id,
                func.count(UnifiedComment.id).label('cnt'),
            ).filter(UnifiedComment.object_type == 'proposal',
                     UnifiedComment.object_id.in_(all_proposal_ids))
            pq = _apply_hub_filters(pq, user, scope, search, date_from, date_to)
            pq = pq.group_by(UnifiedComment.object_id)
            prop_counts = {r.object_id: r.cnt for r in pq.all()}

        for rid in rule_ids:
            categories = []
            rule_count = rule_counts.get(rid, 0)
            if rule_count > 0:
                categories.append({
                    'key':         f'rule:{rid}',
                    'kind':        'comment',
                    'label':       'Simple comments',
                    'object_type': 'rule',
                    'object_id':   rid,
                    'count':       rule_count,
                    'link':        object_context_path('rule', rid),
                })
            for p in proposals_by_rule.get(rid, []):
                prop_count = prop_counts.get(p.id, 0)
                if prop_count > 0:
                    categories.append({
                        'key':             f'proposal:{p.id}',
                        'kind':            'proposal',
                        'label':           f'Suggested edit ({p.status})',
                        'object_type':     'proposal',
                        'object_id':       p.id,
                        'count':           prop_count,
                        'proposal_status': p.status,
                        'link':            object_context_path('proposal', p.id),
                    })
            result[('rule', rid)] = categories

    return result


def _group_participants_batch(pairs_by_key, limit=_PARTICIPANTS_MAX):
    """Batched version — one grouped query across every subject's buckets on
    the page, plus one User lookup, instead of 2 queries PER ROW.

    pairs_by_key: {(subject_type, subject_id): [(object_type, object_id), ...]}
    Returns {(subject_type, subject_id): (participants, total_count)}.
    """
    pair_to_key = {}
    all_pairs = []
    for key, pairs in pairs_by_key.items():
        for p in pairs:
            pair_to_key[p] = key
            all_pairs.append(p)

    if not all_pairs:
        return {}

    rows = (db.session.query(
                UnifiedComment.object_type,
                UnifiedComment.object_id,
                UnifiedComment.created_by,
                func.max(UnifiedComment.created_at).label('last_at'))
            .filter(_pair_filter(all_pairs),
                    UnifiedComment.is_active == True,
                    UnifiedComment.created_by != None)
            .group_by(UnifiedComment.object_type, UnifiedComment.object_id, UnifiedComment.created_by)
            .all())

    # A subject can span several buckets (a rule + its proposals) — roll up
    # to "last activity per (subject, author)" across every bucket it owns.
    last_at_by_subject_user = {}
    for r in rows:
        key = pair_to_key.get((r.object_type, r.object_id))
        if key is None:
            continue
        bucket = last_at_by_subject_user.setdefault(key, {})
        prev = bucket.get(r.created_by)
        if prev is None or r.last_at > prev:
            bucket[r.created_by] = r.last_at

    top_ids_by_key = {}
    total_by_key = {}
    all_top_ids = set()
    for key, by_user in last_at_by_subject_user.items():
        ordered = sorted(by_user.items(), key=lambda kv: kv[1], reverse=True)
        total_by_key[key] = len(ordered)
        top_ids = [uid for uid, _ in ordered[:limit]]
        top_ids_by_key[key] = top_ids
        all_top_ids.update(top_ids)

    users = {u.id: u for u in User.query.filter(User.id.in_(all_top_ids)).all()} if all_top_ids else {}

    result = {}
    for key, top_ids in top_ids_by_key.items():
        participants = []
        for uid in top_ids:
            u = users.get(uid)
            if u:
                participants.append({
                    'id':     u.id,
                    'name':   u.get_username(),
                    'avatar': u.get_avatar_url(),
                })
        result[key] = (participants, total_by_key.get(key, 0))
    return result


def _preview_comments_batch(rows, links_by_pair, user, scope, search, date_from, date_to, limit=3):
    """Batched version — one query (using a ROW_NUMBER() window function
    partitioned per subject) across every subject on the page, instead of
    one query PER ROW.

    Returns {(subject_type, subject_id): [preview comments...]}.
    """
    subject_keys = {(row.subject_type, row.subject_id) for row in rows}
    if not subject_keys:
        return {}

    PropSubj = aliased(RuleEditProposal)
    subj_type_expr = case(
        (UnifiedComment.object_type == 'proposal', literal('rule')),
        else_=UnifiedComment.object_type,
    )
    subj_id_expr = case(
        (UnifiedComment.object_type == 'proposal', PropSubj.rule_id),
        else_=UnifiedComment.object_id,
    )
    rn = func.row_number().over(
        partition_by=[subj_type_expr, subj_id_expr],
        order_by=UnifiedComment.created_at.desc(),
    ).label('rn')

    base_q = (
        db.session.query(
            UnifiedComment.id.label('id'),
            UnifiedComment.content.label('content'),
            UnifiedComment.parent_id.label('parent_id'),
            UnifiedComment.created_at.label('created_at'),
            UnifiedComment.created_by.label('created_by'),
            UnifiedComment.object_type.label('object_type'),
            UnifiedComment.object_id.label('object_id'),
            subj_type_expr.label('subj_type'),
            subj_id_expr.label('subj_id'),
            rn,
        )
        .outerjoin(PropSubj, and_(UnifiedComment.object_type == 'proposal',
                                  UnifiedComment.object_id == PropSubj.id))
    )
    base_q = _apply_hub_filters(base_q, user, scope, search, date_from, date_to)
    base_q = base_q.filter(or_(*[
        and_(subj_type_expr == t, subj_id_expr == i) for t, i in subject_keys
    ]))

    subq = base_q.subquery()
    final_rows = (
        db.session.query(subq)
        .filter(subq.c.rn <= limit)
        .order_by(subq.c.subj_type, subq.c.subj_id, subq.c.rn)
        .all()
    )

    author_ids = {r.created_by for r in final_rows if r.created_by}
    users = {u.id: u for u in User.query.filter(User.id.in_(author_ids)).all()} if author_ids else {}

    out = {}
    for r in final_rows:
        key = (r.subj_type, r.subj_id)
        base_link = links_by_pair.get((r.object_type, r.object_id), '/')
        u = users.get(r.created_by)
        out.setdefault(key, []).append({
            'id':         r.id,
            'excerpt':    r.content[:280] + ('…' if len(r.content) > 280 else ''),
            'is_reply':   r.parent_id is not None,
            'created_at': r.created_at.isoformat() if r.created_at else None,
            'link':       comment_deep_link(base_link, r.id),
            'author': {
                'id':     u.id if u else None,
                'name':   u.get_username() if u else 'Deleted user',
                'avatar': u.get_avatar_url() if u else None,
            },
        })
    return out


def get_comment_hub_groups(user, scope='main', search='', date_from='', date_to='',
                           sort='last_activity', direction='desc',
                           mine=False, min_comments=0, page=1, per_page=20):
    """Comments grouped by commented subject (a rule and all its edit-proposal
    discussions count as one subject), paginated on the groups."""
    if sort in _LEGACY_SORTS:
        sort, direction = _LEGACY_SORTS[sort]
    if sort not in _SORT_KEYS:
        sort = 'last_activity'
    if direction not in ('asc', 'desc'):
        direction = 'desc'

    PropSubj = aliased(RuleEditProposal)

    subject_type = case(
        (UnifiedComment.object_type == 'proposal', literal('rule')),
        else_=UnifiedComment.object_type,
    )
    subject_id = case(
        (UnifiedComment.object_type == 'proposal', PropSubj.rule_id),
        else_=UnifiedComment.object_id,
    )

    grouped = db.session.query(
        subject_type.label('subject_type'),
        subject_id.label('subject_id'),
        func.count(UnifiedComment.id).label('comment_count'),
        func.max(UnifiedComment.created_at).label('last_activity'),
    ).outerjoin(PropSubj, and_(UnifiedComment.object_type == 'proposal',
                               UnifiedComment.object_id == PropSubj.id))

    grouped = _apply_hub_filters(grouped, user, scope, search, date_from, date_to)
    # A proposal whose parent rule got hard-deleted has no PropSubj.rule_id match.
    grouped = grouped.filter(subject_id != None)

    if mine and user.is_authenticated:
        Mine = aliased(UnifiedComment)
        MineProp = aliased(RuleEditProposal)
        mine_subject_type = case(
            (Mine.object_type == 'proposal', literal('rule')),
            else_=Mine.object_type,
        )
        mine_subject_id = case(
            (Mine.object_type == 'proposal', MineProp.rule_id),
            else_=Mine.object_id,
        )
        grouped = grouped.filter(
            db.session.query(Mine.id)
            .outerjoin(MineProp, and_(Mine.object_type == 'proposal',
                                      Mine.object_id == MineProp.id))
            .filter(
                Mine.created_by == user.id,
                Mine.is_active == True,
                mine_subject_type == subject_type,
                mine_subject_id == subject_id,
            ).exists()
        )

    grouped = grouped.group_by(subject_type, subject_id)

    if min_comments and min_comments > 0:
        grouped = grouped.having(func.count(UnifiedComment.id) >= min_comments)

    if sort == 'title':
        RuleT, BundleT, BlogT = aliased(Rule), aliased(Bundle), aliased(BlogPost)
        grouped = (grouped
                   .outerjoin(RuleT, and_(subject_type == 'rule', subject_id == RuleT.id))
                   .outerjoin(BundleT, and_(subject_type == 'bundle', subject_id == BundleT.id))
                   .outerjoin(BlogT, and_(subject_type == 'blog_post', subject_id == BlogT.id)))
        order = func.min(func.lower(case(
            (subject_type == 'rule', RuleT.title),
            (subject_type == 'bundle', BundleT.name),
            (subject_type == 'blog_post', BlogT.title),
            else_='',
        )))
    elif sort == 'comment_count':
        order = func.count(UnifiedComment.id)
    elif sort == 'object_type':
        order = subject_type
    else:
        order = func.max(UnifiedComment.created_at)

    order = order.desc() if direction == 'desc' else order.asc()
    grouped = grouped.order_by(order, func.max(UnifiedComment.created_at).desc())

    total = grouped.count()
    page = max(page, 1)
    per_page = max(per_page, 1)
    rows = grouped.offset((page - 1) * per_page).limit(per_page).all()

    meta = _load_objects_meta(rows)

    def _meta_for(row):
        return meta.get((row.subject_type, row.subject_id)) or {
            'title': f'{row.subject_type.replace("_", " ").title()} #{row.subject_id}',
            'link':  object_context_path(row.subject_type, row.subject_id),
        }

    # ── Batched per-page lookups ────────────────────────────────────────
    # Previously each of these ran 2-4 queries PER ROW (categories,
    # participants, preview) — for a 20-row page that's 80-150+ round
    # trips. Now it's a small constant number of grouped queries covering
    # every row on the page at once.
    categories_by_key = _group_categories_batch(rows, user, scope, search, date_from, date_to)

    pairs_by_key = {}
    links_by_pair = {}
    for row in rows:
        key = (row.subject_type, row.subject_id)
        m = _meta_for(row)
        categories = categories_by_key.get(key, [])
        pairs_by_key[key] = [(c['object_type'], c['object_id']) for c in categories] or [key]
        for c in categories:
            links_by_pair[(c['object_type'], c['object_id'])] = c.get('link', m['link'])
        links_by_pair.setdefault(key, m['link'])

    participants_by_key = _group_participants_batch(pairs_by_key)
    preview_by_key = _preview_comments_batch(rows, links_by_pair, user, scope, search, date_from, date_to)

    items = []
    for row in rows:
        key = (row.subject_type, row.subject_id)
        m = _meta_for(row)
        categories = categories_by_key.get(key, [])
        participants, participant_count = participants_by_key.get(key, ([], 0))

        items.append({
            # Unique across subjects — DataTable keys/expands rows on item.id
            'id':                f'{row.subject_type}:{row.subject_id}',
            'object_type':       row.subject_type,
            'object_id':         row.subject_id,
            'participants':      participants,
            'participant_count': participant_count,
            'title':             m['title'],
            'link':              m['link'],
            'is_private':        m.get('is_private', False),
            'comment_count':     row.comment_count,
            'last_activity':     row.last_activity.isoformat() if row.last_activity else None,
            'categories':        categories,
            'preview':           preview_by_key.get(key, []),
        })

    return {
        'items':       items,
        'total':       total,
        'page':        page,
        'per_page':    per_page,
        'total_pages': max(1, -(-total // per_page)),
    }
