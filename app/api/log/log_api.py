from functools import wraps

from flask import request
from flask_login import current_user
from flask_restx import Namespace, Resource
from sqlalchemy import or_

from ... import db
from ...core.db_class.db import ActivityLog

log_ns = Namespace('log', description='Activity logs — admin only')

_ALLOWED_SORTS = frozenset({'id', 'created_at', 'category', 'level', 'action'})


def _require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            return {'message': 'Admin access required'}, 403
        return f(*args, **kwargs)
    return wrapper


@log_ns.route('/')
class LogList(Resource):
    """Paginated, filtered, sorted list of activity logs."""
    method_decorators = [_require_admin]

    def get(self):
        try:
            page     = max(1, int(request.args.get('page', 1)))
            per_page = min(100, max(1, int(request.args.get('per_page', 25))))
        except (TypeError, ValueError):
            page, per_page = 1, 25

        search   = (request.args.get('search') or '').strip()
        category = (request.args.get('category') or '').strip()
        level    = (request.args.get('level') or '').strip()
        sort_key = request.args.get('sort', 'created_at')
        sort_dir = request.args.get('dir', 'desc')

        user_id_raw = request.args.get('user_id')
        user_id = None
        if user_id_raw:
            try:
                user_id = int(user_id_raw)
            except (TypeError, ValueError):
                pass

        if sort_key not in _ALLOWED_SORTS:
            sort_key = 'created_at'
        if sort_dir not in ('asc', 'desc'):
            sort_dir = 'desc'

        q = ActivityLog.query

        if search:
            like = f'%{search}%'
            q = q.filter(or_(
                ActivityLog.title.ilike(like),
                ActivityLog.action.ilike(like),
                ActivityLog.description.ilike(like),
            ))

        if category:
            q = q.filter(ActivityLog.category == category)

        if level:
            q = q.filter(ActivityLog.level == level)

        if user_id is not None:
            q = q.filter(ActivityLog.user_id == user_id)

        sort_col = getattr(ActivityLog, sort_key)
        q = q.order_by(sort_col.asc() if sort_dir == 'asc' else sort_col.desc())

        total       = q.count()
        total_pages = max(1, (total + per_page - 1) // per_page)
        page        = min(page, total_pages)
        items       = q.offset((page - 1) * per_page).limit(per_page).all()

        return {
            'items':       [l.to_json() for l in items],
            'total':       total,
            'page':        page,
            'per_page':    per_page,
            'total_pages': total_pages,
        }, 200


@log_ns.route('/<string:log_uuid>')
class LogDetail(Resource):
    """Delete or update a single log entry by UUID."""
    method_decorators = [_require_admin]

    def delete(self, log_uuid):
        entry = ActivityLog.query.filter_by(uuid=log_uuid).first()
        if not entry:
            return {'message': 'Log not found'}, 404
        db.session.delete(entry)
        db.session.commit()
        return {'message': 'Log deleted'}, 200

    def patch(self, log_uuid):
        """Flip is_public on this one entry — independent of its action's
        default visibility (see /admin/log_definitions), since a single
        entry can carry more sensitive detail than the action type usually does."""
        data      = request.get_json(silent=True) or {}
        is_public = data.get('is_public')
        if not isinstance(is_public, bool):
            return {'message': 'is_public (bool) is required'}, 400

        entry = ActivityLog.query.filter_by(uuid=log_uuid).first()
        if not entry:
            return {'message': 'Log not found'}, 404
        entry.is_public = is_public
        db.session.commit()
        return {'message': 'Updated', 'log': entry.to_json()}, 200


@log_ns.route('/bulk-delete')
class LogBulkDelete(Resource):
    """Delete multiple log entries by UUID list."""
    method_decorators = [_require_admin]

    def post(self):
        data = request.get_json(silent=True) or {}
        uuids = data.get('uuids', [])
        if not uuids or not isinstance(uuids, list):
            return {'message': 'No uuids provided'}, 400

        deleted = ActivityLog.query.filter(
            ActivityLog.uuid.in_(uuids)
        ).delete(synchronize_session=False)
        db.session.commit()
        return {'message': f'Deleted {deleted} log(s)', 'deleted': deleted}, 200


@log_ns.route('/bulk-visibility')
class LogBulkVisibility(Resource):
    """Set is_public on multiple log entries by UUID list."""
    method_decorators = [_require_admin]

    def post(self):
        data      = request.get_json(silent=True) or {}
        uuids     = data.get('uuids', [])
        is_public = data.get('is_public')
        if not uuids or not isinstance(uuids, list):
            return {'message': 'No uuids provided'}, 400
        if not isinstance(is_public, bool):
            return {'message': 'is_public (bool) is required'}, 400

        updated = ActivityLog.query.filter(
            ActivityLog.uuid.in_(uuids)
        ).update({'is_public': is_public}, synchronize_session=False)
        db.session.commit()
        return {'message': f'Updated {updated} log(s)', 'updated': updated}, 200
