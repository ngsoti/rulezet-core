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


def _group_categories(subject_type, subject_id, user, scope, search, date_from, date_to):
    """
    The buckets of comments folded into one hub row.

    A bundle/blog_post subject always has exactly one bucket (itself). A rule
    subject can have several: its own plain comments, plus one bucket per
    edit proposal that has discussion — these are shown as sub-categories in
    the UI ("Simple comments" vs "Suggested edit (status)") rather than as
    separate hub rows, since they're really the same conversation about the
    same rule.
    """
    if subject_type != 'rule':
        q = UnifiedComment.query.filter(
            UnifiedComment.object_type == subject_type,
            UnifiedComment.object_id == subject_id,
        )
        q = _apply_hub_filters(q, user, scope, search, date_from, date_to)
        count = q.count()
        # No 'link' here for blog_post: the correct URL needs the post's uuid
        # slug, which the caller (not this function) already resolved onto
        # the group's own `link` — the frontend falls back to that for the
        # only-one-category case, so this bucket doesn't need its own link.
        return [{
            'key':         f'{subject_type}:{subject_id}',
            'kind':        'comment',
            'label':       'Comments',
            'object_type': subject_type,
            'object_id':   subject_id,
            'count':       count,
        }]

    categories = []

    rule_q = UnifiedComment.query.filter(
        UnifiedComment.object_type == 'rule',
        UnifiedComment.object_id == subject_id,
    )
    rule_q = _apply_hub_filters(rule_q, user, scope, search, date_from, date_to)
    rule_count = rule_q.count()
    if rule_count > 0:
        categories.append({
            'key':         f'rule:{subject_id}',
            'kind':        'comment',
            'label':       'Simple comments',
            'object_type': 'rule',
            'object_id':   subject_id,
            'count':       rule_count,
            'link':        object_context_path('rule', subject_id),
        })

    proposals = RuleEditProposal.query.filter(RuleEditProposal.rule_id == subject_id).all()
    for p in proposals:
        prop_q = UnifiedComment.query.filter(
            UnifiedComment.object_type == 'proposal',
            UnifiedComment.object_id == p.id,
        )
        prop_q = _apply_hub_filters(prop_q, user, scope, search, date_from, date_to)
        prop_count = prop_q.count()
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

    return categories


def _group_participants(pairs, limit=_PARTICIPANTS_MAX):
    rows = (db.session.query(
                UnifiedComment.created_by,
                func.max(UnifiedComment.created_at).label('last_at'))
            .filter(_pair_filter(pairs),
                    UnifiedComment.is_active == True,
                    UnifiedComment.created_by != None)
            .group_by(UnifiedComment.created_by)
            .order_by(func.max(UnifiedComment.created_at).desc())
            .all())
    total = len(rows)
    top_ids = [r.created_by for r in rows[:limit]]
    users = {u.id: u for u in User.query.filter(User.id.in_(top_ids)).all()} if top_ids else {}

    participants = []
    for uid in top_ids:
        u = users.get(uid)
        if u:
            participants.append({
                'id':     u.id,
                'name':   u.get_username(),
                'avatar': u.get_avatar_url(),
            })
    return participants, total


def _preview_comments(pairs, user, scope, search, date_from, date_to, links_by_pair, limit=3):
    q = UnifiedComment.query.filter(_pair_filter(pairs))
    q = _apply_hub_filters(q, user, scope, search, date_from, date_to)
    comments = q.order_by(UnifiedComment.created_at.desc()).limit(limit).all()

    out = []
    for c in comments:
        author = c.author
        base_link = links_by_pair.get((c.object_type, c.object_id), '/')
        out.append({
            'id':         c.id,
            'excerpt':    c.content[:280] + ('…' if len(c.content) > 280 else ''),
            'is_reply':   c.parent_id is not None,
            'created_at': c.created_at.isoformat() if c.created_at else None,
            'link':       comment_deep_link(base_link, c.id),
            'author': {
                'id':     author.id if author else None,
                'name':   author.get_username() if author else 'Deleted user',
                'avatar': author.get_avatar_url() if author else None,
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

    items = []
    for row in rows:
        m = meta.get((row.subject_type, row.subject_id)) or {
            'title': f'{row.subject_type.replace("_", " ").title()} #{row.subject_id}',
            'link':  object_context_path(row.subject_type, row.subject_id),
        }

        categories = _group_categories(row.subject_type, row.subject_id,
                                        user, scope, search, date_from, date_to)
        pairs = [(c['object_type'], c['object_id']) for c in categories] or \
                [(row.subject_type, row.subject_id)]
        links_by_pair = {
            (c['object_type'], c['object_id']): c.get('link', m['link'])
            for c in categories
        }
        links_by_pair.setdefault((row.subject_type, row.subject_id), m['link'])

        participants, participant_count = _group_participants(pairs)

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
            'preview':           _preview_comments(pairs, user, scope, search, date_from, date_to,
                                                    links_by_pair=links_by_pair),
        })

    return {
        'items':       items,
        'total':       total,
        'page':        page,
        'per_page':    per_page,
        'total_pages': max(1, -(-total // per_page)),
    }
