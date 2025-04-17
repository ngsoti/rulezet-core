import datetime
from flask_login import current_user
from .. import db
from ..db_class.db import Comment

def add_comment_core(rule_id, content):
    if not content.strip():
        return False, "Comment cannot be empty."

    comment = Comment(
        rule_id=rule_id,
        user_id=current_user.id,
        content=content.strip(),
        created_at=datetime.datetime.utcnow()
    )
    db.session.add(comment)
    db.session.commit()
    return True, "Comment posted successfully."


def get_comment_by_id(comment_id):
    return Comment.query.get(comment_id)

def update_comment(comment_id, new_content):
    comment = get_comment_by_id(comment_id)
    if comment:
        comment.content = new_content
        db.session.commit()
        return True
    return False

def delete_comment(comment_id):
    comment = get_comment_by_id(comment_id)
    if comment:
        db.session.delete(comment)
        db.session.commit()
        return True
    return False

def get_comments_for_rule(rule_id):
    return Comment.query.filter_by(rule_id=rule_id).order_by(Comment.created_at.desc()).all()

def like_comment(comment_id):
    """Increments the like count of a comment."""
    comment = Comment.query.get_or_404(comment_id)
    comment.likes += 1
    db.session.commit()

def dislike_comment(comment_id):
    """Increments the dislike count of a comment."""
    comment = Comment.query.get_or_404(comment_id)
    comment.dislikes += 1
    db.session.commit()