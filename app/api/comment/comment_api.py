"""
REST API for the unified comment system.

Endpoints (all under /api/comments):
  GET    /                        list root comments for an object (+ replies via parent_id param)
  POST   /                        create a comment or reply
  PUT    /<uuid>                   edit content (author or moderator)
  DELETE /<uuid>                   soft-delete (author or moderator)
  POST   /<uuid>/restore           restore a soft-deleted comment (moderator only)
  POST   /<uuid>/react             toggle like / dislike
"""
import datetime
import os
import uuid as _uuid_mod

import requests
from flask import request
from flask_login import current_user
from flask_restx import Namespace, Resource, fields

from app.core.db_class.db import UnifiedComment, UnifiedCommentReaction
from app.core.utils.activity_log import log_activity
from app import db

comment_ns = Namespace('comments', description='Unified comment thread API')

_VALID_OBJECT_TYPES = {'rule', 'bundle', 'proposal', 'blog_post'}
_PER_PAGE_MAX = 50

# Official rulezet-core repo — admin-proposed issues from comments always land here,
# regardless of which instance filed them.
_GITHUB_ISSUE_REPO = 'rulezet/rulezet-core'


def _get_or_404(uuid):
    c = UnifiedComment.query.filter_by(uuid=uuid).first()
    if not c:
        comment_ns.abort(404, 'Comment not found')
    return c


def _can_moderate():
    return current_user.is_authenticated and current_user.is_admin()


def _can_edit(comment):
    if not current_user.is_authenticated:
        return False
    return comment.created_by == current_user.id or _can_moderate()


def _comment_context_link(comment):
    """Best-effort deep link back to the comment, for the GitHub issue body."""
    from app.features.community.community_core import comment_deep_link, object_context_path

    base = (os.environ.get('INSTANCE_PUBLIC_URL') or request.url_root).rstrip('/')

    blog_slug = None
    if comment.object_type == 'blog_post':
        from app.core.db_class.db import BlogPost
        blog_post = BlogPost.query.get(comment.object_id)
        blog_slug = blog_post.uuid if blog_post else None

    path = object_context_path(comment.object_type, comment.object_id, blog_slug=blog_slug)
    return f'{base}{comment_deep_link(path, comment.id)}'


# ── List / Create ──────────────────────────────────────────────────────────────

@comment_ns.route('/')
class CommentList(Resource):

    def get(self):
        """List comments for an object (paginated). Pass parent_id to fetch replies."""
        object_type = request.args.get('object_type', '').strip()
        object_id   = request.args.get('object_id', type=int)
        parent_id   = request.args.get('parent_id', type=int, default=None)
        page        = request.args.get('page', 1, type=int)
        per_page    = min(request.args.get('per_page', 20, type=int), _PER_PAGE_MAX)

        if object_type not in _VALID_OBJECT_TYPES or not object_id:
            return {'message': 'object_type and object_id are required'}, 400

        uid = current_user.id if current_user.is_authenticated else None

        q = (UnifiedComment.query
             .filter_by(object_type=object_type, object_id=object_id, is_active=True)
             .filter(UnifiedComment.parent_id == parent_id)
             .order_by(UnifiedComment.created_at.asc()))

        paginated = q.paginate(page=page, per_page=per_page, error_out=False)

        return {
            'items':    [c.to_json(current_user_id=uid) for c in paginated.items],
            'total':    paginated.total,
            'page':     page,
            'per_page': per_page,
            'has_next': paginated.has_next,
        }

    def post(self):
        """Create a new comment or reply. Requires login."""
        if not current_user.is_authenticated:
            return {'message': 'Login required'}, 401

        data = request.get_json(silent=True) or {}
        object_type = data.get('object_type', '').strip()
        object_id   = data.get('object_id')
        content     = data.get('content', '').strip()
        parent_id   = data.get('parent_id')

        if object_type not in _VALID_OBJECT_TYPES:
            return {'message': f'object_type must be one of {_VALID_OBJECT_TYPES}'}, 400
        if not object_id:
            return {'message': 'object_id is required'}, 400
        if not content:
            return {'message': 'content is required'}, 400
        if len(content) > 10000:
            return {'message': 'comment too long (max 10 000 chars)'}, 400

        depth   = 0
        root_id = None

        if parent_id:
            parent = UnifiedComment.query.filter_by(id=parent_id, is_active=True).first()
            if not parent:
                return {'message': 'Parent comment not found'}, 404
            if parent.object_type != object_type or parent.object_id != object_id:
                return {'message': 'Parent comment does not belong to this object'}, 400
            depth   = parent.depth + 1
            root_id = parent.root_id or parent.id

        now = datetime.datetime.now(datetime.timezone.utc)
        comment = UnifiedComment(
            uuid=str(_uuid_mod.uuid4()),
            content=content,
            object_type=object_type,
            object_id=object_id,
            parent_id=parent_id,
            depth=depth,
            root_id=root_id,
            created_by=current_user.id,
            created_at=now,
            updated_at=now,
        )
        db.session.add(comment)
        db.session.commit()

        # ── Activity log + notifications ──────────────────────────────────────
        try:
            from app.features.notification.notification_core import (
                notify_owner_new_comment, notify_followers_new_comment,
                notify_comment_reply, notify_proposal_comment,
            )

            if object_type == 'rule':
                from app.core.db_class.db import Rule
                rule = Rule.query.get(object_id)
                log_activity("comment.add",
                             f"Added comment on rule '{rule.title if rule else object_id}'",
                             target_type="comment", target_id=comment.id,
                             extra={"rule_id": object_id, "rule_uuid": rule.uuid if rule else None})
                link  = f'/rule/detail_rule/{object_id}?comment={comment.id}'
                title = rule.title if rule else ''
                # Notify rule owner
                if rule:
                    notify_owner_new_comment(rule.user_id, current_user.id, 'rule_comment', title, link)
                # Notify followers of commenter (rules are always public)
                notify_followers_new_comment(current_user.id, title, link, is_public=True)
                # Notify parent comment author on reply
                if parent_id:
                    parent_comment = UnifiedComment.query.get(parent_id)
                    if parent_comment and parent_comment.created_by:
                        notify_comment_reply(parent_comment.created_by, current_user.id, title, link)

            elif object_type == 'bundle':
                from app.core.db_class.db import Bundle
                bundle    = Bundle.query.get(object_id)
                is_public = bool(bundle.access) if bundle else True
                log_activity("bundle_comment.add",
                             f"Added comment on bundle id={object_id}",
                             target_type="bundle_comment", target_id=comment.id,
                             extra={"bundle_id": object_id, "bundle_uuid": bundle.uuid if bundle else None},
                             is_public=is_public)
                link  = f'/bundle/detail/{object_id}?comment={comment.id}'
                title = bundle.name if bundle else ''
                # Always notify bundle owner (even on private bundle — they own it)
                if bundle:
                    notify_owner_new_comment(bundle.user_id, current_user.id, 'bundle_comment', title, link)
                # Only notify followers if bundle is public
                notify_followers_new_comment(current_user.id, title, link, is_public=is_public)
                # Notify parent comment author on reply (only if they can access the bundle)
                if parent_id:
                    parent_comment = UnifiedComment.query.get(parent_id)
                    if parent_comment and parent_comment.created_by:
                        can_notify = is_public or parent_comment.created_by == (bundle.user_id if bundle else None)
                        if can_notify:
                            notify_comment_reply(parent_comment.created_by, current_user.id, title, link)

            elif object_type == 'proposal':
                from app.core.db_class.db import RuleEditProposal, Rule
                proposal = RuleEditProposal.query.get(object_id)
                if proposal:
                    rule  = Rule.query.get(proposal.rule_id)
                    title = rule.title if rule else ''
                    # Notify the proposal creator when someone else comments
                    notify_proposal_comment(object_id, proposal.user_id, current_user.id, title,
                                            comment_id=comment.id)

            elif object_type == 'blog_post':
                from app.core.db_class.db import BlogPost
                blog_post = BlogPost.query.get(object_id)
                log_activity("blog_comment.add",
                             f"Added comment on blog post id={object_id}",
                             target_type="blog_comment", target_id=comment.id,
                             extra={"post_id": object_id})
                if blog_post and blog_post.is_public:
                    link  = f'/blog/post/{blog_post.uuid}?comment={comment.id}'
                    notify_followers_new_comment(current_user.id, blog_post.title, link, is_public=True)
                    if parent_id:
                        parent_comment = UnifiedComment.query.get(parent_id)
                        if parent_comment and parent_comment.created_by:
                            notify_comment_reply(parent_comment.created_by, current_user.id, blog_post.title, link)

        except Exception as _e:
            print(f"[comment_api] notification error: {_e}")

        return {'message': 'Comment posted', 'comment': comment.to_json(current_user_id=current_user.id)}, 201


# ── Cross-object hub ───────────────────────────────────────────────────────────

@comment_ns.route('/hub')
class CommentHub(Resource):

    def get(self):
        """Comments grouped by commented object (rule/bundle/proposal/blog_post), paginated on the groups."""
        if not current_user.is_authenticated:
            return {'message': 'Login required'}, 401

        from app.features.community.community_core import get_comment_hub_groups

        scope = request.args.get('scope', 'main').strip()
        if scope not in ('main', 'all'):
            scope = 'main'

        return get_comment_hub_groups(
            user=current_user,
            scope=scope,
            search=request.args.get('search', '').strip(),
            date_from=request.args.get('date_from', '').strip(),
            date_to=request.args.get('date_to', '').strip(),
            sort=request.args.get('sort', 'last_activity').strip(),
            direction=request.args.get('dir', 'desc').strip(),
            mine=request.args.get('mine', '').strip() in ('1', 'true'),
            min_comments=max(request.args.get('min_comments', 0, type=int) or 0, 0),
            page=request.args.get('page', 1, type=int),
            per_page=min(request.args.get('per_page', 20, type=int), _PER_PAGE_MAX),
        )


@comment_ns.route('/my_count')
class CommentMyCount(Resource):

    def get(self):
        """Total active comments authored by the current user — badge on the account page."""
        if not current_user.is_authenticated:
            return {'message': 'Login required'}, 401

        count = UnifiedComment.query.filter_by(
            created_by=current_user.id, is_active=True
        ).count()
        return {'count': count}


# ── Single comment ─────────────────────────────────────────────────────────────

@comment_ns.route('/<string:uuid>')
class CommentDetail(Resource):

    def put(self, uuid):
        """Edit a comment's content. Requires authorship or moderation."""
        if not current_user.is_authenticated:
            return {'message': 'Login required'}, 401

        comment = _get_or_404(uuid)
        if not _can_edit(comment):
            return {'message': 'Not allowed'}, 403
        if not comment.is_active:
            return {'message': 'Cannot edit a deleted comment'}, 400

        data    = request.get_json(silent=True) or {}
        content = data.get('content', '').strip()
        if not content:
            return {'message': 'content is required'}, 400
        if len(content) > 10000:
            return {'message': 'comment too long (max 10 000 chars)'}, 400

        if comment.content_original is None:
            comment.content_original = comment.content
        comment.content    = content
        comment.updated_at = datetime.datetime.now(datetime.timezone.utc)
        db.session.commit()

        return {'message': 'Comment updated', 'comment': comment.to_json(current_user_id=current_user.id)}

    def delete(self, uuid):
        """Soft-delete a comment. Requires authorship or moderation."""
        if not current_user.is_authenticated:
            return {'message': 'Login required'}, 401

        comment = _get_or_404(uuid)
        if not _can_edit(comment):
            return {'message': 'Not allowed'}, 403
        if not comment.is_active:
            return {'message': 'Already deleted'}, 400

        now = datetime.datetime.now(datetime.timezone.utc)
        comment.is_active  = False
        comment.deleted_at = now
        comment.deleted_by = current_user.id
        db.session.commit()

        return {'message': 'Comment deleted'}


# ── Hard-delete (admin only) ───────────────────────────────────────────────────

def _collect_subtree_ids(root_comment_id):
    """Return all comment IDs in the subtree rooted at root_comment_id (BFS, inclusive)."""
    ids = []
    queue = [root_comment_id]
    while queue:
        current_id = queue.pop()
        ids.append(current_id)
        children = (UnifiedComment.query
                    .filter_by(parent_id=current_id)
                    .with_entities(UnifiedComment.id)
                    .all())
        queue.extend(row.id for row in children)
    return ids


@comment_ns.route('/<string:uuid>/hard_delete')
class CommentHardDelete(Resource):

    def delete(self, uuid):
        """Hard-delete a comment and its entire reply subtree (admin only)."""
        if not _can_moderate():
            return {'message': 'Admin required'}, 403

        comment = _get_or_404(uuid)

        # Save scalar values before the bulk delete — the ORM object will be
        # expired/invalid after synchronize_session=False and accessing its
        # attributes would raise ObjectDeletedError.
        comment_id    = comment.id
        comment_uuid  = comment.uuid

        # Collect all descendant IDs before any delete (parent_id SET NULL on delete
        # would lose the tree structure if we deleted top-down)
        ids = _collect_subtree_ids(comment_id)

        # Bulk hard-delete — DB CASCADE handles reactions automatically
        UnifiedComment.query.filter(UnifiedComment.id.in_(ids)).delete(synchronize_session=False)
        db.session.commit()

        log_activity(
            "comment.hard_delete",
            f"Hard-deleted comment uuid={comment_uuid} and {len(ids) - 1} descendant(s)",
            target_type="comment", target_id=comment_id,
            is_public=False,
        )

        return {'message': f'Comment and {len(ids) - 1} reply/replies permanently deleted',
                'deleted_ids': ids}


# ── Restore ────────────────────────────────────────────────────────────────────

@comment_ns.route('/<string:uuid>/restore')
class CommentRestore(Resource):

    def post(self, uuid):
        """Restore a soft-deleted comment (moderators only)."""
        if not _can_moderate():
            return {'message': 'Moderation required'}, 403

        comment = _get_or_404(uuid)
        if comment.is_active:
            return {'message': 'Comment is not deleted'}, 400

        comment.is_active  = True
        comment.deleted_at = None
        comment.deleted_by = None
        db.session.commit()

        return {'message': 'Comment restored', 'comment': comment.to_json(current_user_id=current_user.id)}


# ── Resolve (deep-link helper) ────────────────────────────────────────────────

@comment_ns.route('/resolve/<int:comment_id>')
class CommentResolve(Resource):

    def get(self, comment_id):
        """Return a comment's root_id and ordered ancestor chain for deep-link navigation."""
        c = UnifiedComment.query.get(comment_id)
        if not c or not c.is_active:
            return {'message': 'Comment not found'}, 404

        ancestors = []
        cur = c
        while cur.parent_id:
            parent = UnifiedComment.query.get(cur.parent_id)
            if not parent:
                break
            ancestors.insert(0, parent.id)
            cur = parent

        return {
            'id':       c.id,
            'root_id':  c.root_id,
            'ancestors': ancestors,
        }


# ── React ──────────────────────────────────────────────────────────────────────

@comment_ns.route('/<string:uuid>/react')
class CommentReact(Resource):

    def post(self, uuid):
        """Toggle a like or dislike on a comment. Requires login."""
        if not current_user.is_authenticated:
            return {'message': 'Login required'}, 401

        comment = _get_or_404(uuid)
        if not comment.is_active:
            return {'message': 'Cannot react to a deleted comment'}, 400

        data     = request.get_json(silent=True) or {}
        reaction = data.get('reaction', '').strip()
        if reaction not in ('like', 'dislike'):
            return {'message': 'reaction must be "like" or "dislike"'}, 400

        existing = UnifiedCommentReaction.query.filter_by(
            comment_id=comment.id, user_id=current_user.id
        ).first()

        if existing:
            if existing.reaction == reaction:
                # toggle off
                db.session.delete(existing)
            else:
                existing.reaction = reaction
        else:
            db.session.add(UnifiedCommentReaction(
                comment_id=comment.id,
                user_id=current_user.id,
                reaction=reaction,
                created_at=datetime.datetime.now(datetime.timezone.utc),
            ))

        db.session.commit()

        # Re-query counts after commit
        like_count    = UnifiedCommentReaction.query.filter_by(comment_id=comment.id, reaction='like').count()
        dislike_count = UnifiedCommentReaction.query.filter_by(comment_id=comment.id, reaction='dislike').count()
        new_rxn       = UnifiedCommentReaction.query.filter_by(comment_id=comment.id, user_id=current_user.id).first()

        return {
            'like_count':    like_count,
            'dislike_count': dislike_count,
            'user_reaction': new_rxn.reaction if new_rxn else None,
        }


# ── Create GitHub issue (admin only) ────────────────────────────────────────────

@comment_ns.route('/<string:uuid>/create_issue')
class CommentCreateIssue(Resource):

    def post(self, uuid):
        """Turn a comment into an issue on the official rulezet-core GitHub repo (admin only)."""
        if not _can_moderate():
            return {'message': 'Admin required'}, 403

        comment = _get_or_404(uuid)
        if not comment.is_active:
            return {'message': 'Cannot create an issue from a deleted comment'}, 400
        if comment.github_issue_url:
            return {'message': 'An issue was already created for this comment',
                    'issue_url': comment.github_issue_url}, 400

        token = os.environ.get('GITHUB_TOKEN')
        if not token:
            return {'message': 'GITHUB_TOKEN is not configured on this instance (Admin → Settings)'}, 400

        excerpt = ' '.join(comment.content.split())
        if len(excerpt) > 80:
            excerpt = excerpt[:77] + '...'
        title = f'[Admin Proposed] {excerpt}'

        author = comment.author
        author_name = author.get_username() if author else 'unknown user'

        body = (
            f'**Proposed by admin {current_user.get_username()}, filed from a comment on the platform.**\n\n'
            f'> {comment.content}\n\n'
            f'---\n'
            f'- Original comment author: {author_name}\n'
            f'- Context: {comment.object_type} #{comment.object_id}\n'
            f'- Comment link: {_comment_context_link(comment)}\n'
        )

        data   = request.get_json(silent=True) or {}
        labels = data.get('labels') or ['admin-proposed']

        try:
            res = requests.post(
                f'https://api.github.com/repos/{_GITHUB_ISSUE_REPO}/issues',
                headers={
                    'Authorization': f'Bearer {token}',
                    'Accept': 'application/vnd.github+json',
                },
                json={'title': title, 'body': body, 'labels': labels},
                timeout=10,
            )
        except requests.RequestException as exc:
            return {'message': f'Network error contacting GitHub: {exc}'}, 502

        if res.status_code == 401:
            from app.features.notification.notification_core import notify_admins_github_token_invalid
            notify_admins_github_token_invalid(
                'The configured GITHUB_TOKEN was rejected (401 Bad credentials) while filing '
                'an issue from a comment. GitHub-backed features are down until it is replaced.'
            )
            return {'message': 'GITHUB_TOKEN is invalid or expired — all admins have been alerted. '
                                'Set a new token in Server Settings.'}, 502

        if res.status_code not in (200, 201):
            return {'message': f'GitHub API error ({res.status_code}): {res.text[:300]}'}, 502

        issue = res.json()
        comment.github_issue_url    = issue.get('html_url')
        comment.github_issue_number = issue.get('number')
        db.session.commit()

        log_activity(
            "comment.create_github_issue",
            f"Filed GitHub issue #{issue.get('number')} from comment uuid={comment.uuid}",
            target_type="comment", target_id=comment.id,
            extra={"issue_url": issue.get('html_url')},
            is_public=False,
        )

        return {
            'message':      'GitHub issue created',
            'issue_url':    issue.get('html_url'),
            'issue_number': issue.get('number'),
        }, 201
