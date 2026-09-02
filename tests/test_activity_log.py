"""blog.* actions must get their own 'blog' category, not fall back to
'system' — that fallback previously made every blog log row (view, create,
edit...) show a "System" category badge next to a perfectly real actor,
which read as if the action had no actor at all."""

from app.core.utils.activity_log import _auto_category
from app.core.db_class.db import ActivityLog


def test_blog_actions_get_their_own_category():
    assert _auto_category('blog.view') == 'blog'
    assert _auto_category('blog.create') == 'blog'


def test_unknown_prefix_still_falls_back_to_system():
    assert _auto_category('made_up_thing.foo') == 'system'


def test_blog_view_log_has_real_actor_and_blog_category(app, client):
    from app import db
    from app.core.db_class.db import BlogPost, User

    with app.app_context():
        admin = User.query.filter_by(admin=True).first()
        admin_id = admin.id
        post = BlogPost(uuid='11111111-1111-1111-1111-111111111111', slug='test-post',
                         title='Test post', content='hi', user_id=admin_id,
                         is_public=True, is_draft=False)
        db.session.add(post)
        db.session.commit()
        post_uuid = post.uuid

    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)
        sess["_fresh"] = True

    res = client.get(f'/blog/api/post/{post_uuid}')
    assert res.status_code == 200

    with app.app_context():
        log = ActivityLog.query.filter_by(action='blog.view').order_by(ActivityLog.id.desc()).first()
        assert log is not None
        assert log.user_id == admin_id
        assert log.category == 'blog'
