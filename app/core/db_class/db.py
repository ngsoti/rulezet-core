import datetime
import json
from sqlalchemy.orm import attributes
from sqlalchemy import String, TypeDecorator, func
from sqlalchemy import event
from ... import db, login_manager
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin, AnonymousUserMixin, current_user
from sqlalchemy.orm.attributes import PASSIVE_NO_INITIALIZE

#############
#   User    #
#############

@login_manager.user_loader
def load_user(user_id):
    """Loads the user from the session."""
    return User.query.get(int(user_id))

# ============================================================
# CHANGES TO APPLY IN app/db_class/db.py — User model only
# Replace the existing User class with this one.
# ============================================================

class User(UserMixin, db.Model):
    """User model for authentication and authorization."""

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(64), index=True)
    last_name = db.Column(db.String(64), index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    admin = db.Column(db.Boolean, default=False, index=True)
    password_hash = db.Column(db.String(165))
    api_key = db.Column(db.String(128), index=True)
    is_connected = db.Column(db.Boolean, default=False, index=True)

    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6), nullable=True)
    verification_expiration = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String(64), nullable=True, index=True)
    password_reset_expiration = db.Column(db.DateTime, nullable=True)
    pending_email = db.Column(db.String(64), nullable=True)
    email_change_token = db.Column(db.String(64), nullable=True, index=True)
    email_change_expiration = db.Column(db.DateTime, nullable=True)

    # --- NEW FIELDS ---

    # Profile
    username = db.Column(db.String(64), unique=True, nullable=True, index=True)
    bio = db.Column(db.Text, nullable=True)
    profile_picture = db.Column(db.String(256), nullable=True)  # relative path under /static/uploads/avatars/
    location = db.Column(db.String(128), nullable=True)

    # External links
    website_url = db.Column(db.String(256), nullable=True)
    github_url = db.Column(db.String(256), nullable=True)
    twitter_url = db.Column(db.String(256), nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)

    # --- END NEW FIELDS ---

    def is_admin(self):
        """Check if the user has admin privileges."""
        return self.admin

    def get_username(self):
        return self.username if self.username else (self.first_name + " " + self.last_name)

    def get_first_name(self):
        return self.first_name

    def get_avatar_url(self):
        """Return the profile picture URL or a default gravatar-style fallback."""
        if self.profile_picture:
            return "/static/uploads/avatars/" + self.profile_picture
        return None

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute.")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        """Check if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def is_anonymous(self):
        return False

    def to_json(self):
        """Serialize the user object to JSON."""
        
        return {
            "id": self.id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "admin": self.admin,
            "username": self.get_username(),
            "is_connected": self.is_connected,
            "is_verified": self.is_verified,
            "is_admin": self.is_admin(),
            # new
            "bio": self.bio,
            "profile_picture": self.get_avatar_url(),
            "location": self.location,
            "website_url": self.website_url,
            "github_url": self.github_url,
            "twitter_url": self.twitter_url,
            "created_at": self.created_at.strftime('%Y-%m-%d') if self.created_at else None,
            "last_seen": self.last_seen.strftime('%Y-%m-%d %H:%M') if self.last_seen else None,
        }

class AnonymousUser(AnonymousUserMixin):
    """Defines behavior for anonymous users (not logged in)."""
    
    def is_admin(self):
        return False
    
    def is_anonymous(self):
        return True

# Register AnonymousUser as the default for anonymous visitors
login_manager.anonymous_user = AnonymousUser

#############
#   Rule    #
#############

class Rule(db.Model):
    """Rule model to store and describe various rules."""
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer) # the user who import the rule
    version = db.Column(db.String)
    format = db.Column(db.String)
    title = db.Column(db.String)
    license = db.Column(db.String)
    description = db.Column(db.String)
    uuid = db.Column(db.String(36), index=True)
    original_uuid = db.Column(db.String , nullable=True)
    source = db.Column(db.String)
    author = db.Column(db.String) # the reel author of the rule
    creation_date = db.Column(db.DateTime, index=True)
    last_modif = db.Column(db.DateTime, index=True)
    vote_up = db.Column(db.Integer)
    vote_down = db.Column(db.Integer)
    to_string = db.Column(db.String)
    cve_id = db.Column(db.String , nullable=True)

    github_path = db.Column(db.String , nullable=True)

    # Soft delete
    is_deleted        = db.Column(db.Boolean, nullable=False, default=False, index=True)
    deleted_at        = db.Column(db.DateTime, nullable=True)
    deleted_by_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    delete_batch_uuid = db.Column(db.String(36), nullable=True, index=True)

    # Connector origin — set when a rule is imported via a connector
    connector_id       = db.Column(db.Integer, db.ForeignKey('connector.id', ondelete='SET NULL'), nullable=True, index=True)
    remote_rule_uuid   = db.Column(db.String(36), nullable=True, index=True)  # UUID on the remote instance
    sync_instance_url  = db.Column(db.String(255), nullable=True)             # Instance URL the rule was pulled from (persisted even if connector deleted)

    # Rule lifecycle status (personal management)
    status = db.Column(db.String(20), nullable=False, default='draft', index=True)

    #edit
    def get_rule_user_first_name_by_id(self):
        user = User.query.get(self.user_id)  
        return user.first_name + " " + user.last_name if user else None

    def get_rule_name_by_id(id):
        rule = Rule.query.get(id)
        return rule.title if rule else None
    
    def to_json(self):
        is_favorited = False
        if not current_user.is_anonymous():
            is_favorited = RuleFavoriteUser.query.filter_by(user_id=current_user.id, rule_id=self.id).first() is not None

        submitter = User.query.get(self.user_id)
        submitter_avatar = submitter.get_avatar_url() if submitter else None
        return {
            "id": self.id,
            "format": self.format,
            "title": self.title,
            "license": self.license,
            "description": self.description,
            "uuid": self.uuid,
            "original_uuid": self.original_uuid,
            "source": self.source,
            "author": self.author,
            "creation_date": self.creation_date.strftime('%Y-%m-%d %H:%M'),
            "last_modif": self.last_modif.strftime('%Y-%m-%d %H:%M'),
            "vote_up": self.vote_up,
            "vote_down": self.vote_down,
            "user_id": self.user_id,
            "version": self.version,
            "to_string": self.to_string,
            "is_favorited": is_favorited,
            "cve_id": self.cve_id if self.cve_id is not None else [],
            "editor": self.get_rule_user_first_name_by_id(),
            "github_path": self.github_path if self.github_path else None,
            "editor_avatar": submitter_avatar,
            "sync_instance_url": self.sync_instance_url,
            "status": self.status or 'draft',
        }

    def get_extension(self):
        """ Get the file extension for each format """
        format_name = self.format.lower() if self.format else ""
        
        extensions = {
            'yara': 'yar',
            'sigma': 'yml',
            'suricata': 'rules',
            'zeek': 'zeek',
            'wazuh': 'xml',
            'nse': 'nse',
            'crs': 'conf',
            'nova': 'nov'
        }
        
        return extensions.get(format_name, 'txt') 
    
    def to_json_detail(self):
        """ Return a detailed JSON representation of the rule, including all fields. This is used for the rule detail page. """
        
        # votes
        total_votes = (self.vote_up or 0) + (self.vote_down or 0)
        vote_ratio = round((self.vote_up or 0) / total_votes * 100) if total_votes > 0 else 0

        # favorites count
        favorites_count = self.favorited_by_users_assocs.count()

        # is favorited by current user
        is_favorited = False
        if not current_user.is_anonymous():
            is_favorited = RuleFavoriteUser.query.filter_by(user_id=current_user.id, rule_id=self.id).first() is not None

        # submitter
        submitter = User.query.get(self.user_id)
        submitter_info = None
        if submitter:
            gamification = submitter.gamification_stats
            submitter_info = {
                "id": submitter.id,
                "username": submitter.first_name + " " + submitter.last_name,
                "level": gamification.current_level if gamification else 1,
                "total_points": gamification.total_points if gamification else 0,
            }

        # tags
        tags = [assoc.to_json() for assoc in self.rule_tags_assocs]

        # comments
        comments = [c.to_json() for c in self.comments_rule.order_by(Comment.created_at.desc()).limit(20)]

        # edit proposals
        proposals = self.edit_proposals.order_by(RuleEditProposal.timestamp.desc()).limit(10).all()
        proposals_summary = [p.to_json_for_discuss() for p in proposals]

        # bundles containing this rule
        bundles = [
            {
                "id": assoc.bundle.id,
                "name": assoc.bundle.name,
                "uuid": assoc.bundle.uuid,
                "is_verified": assoc.bundle.is_verified,
            }
            for assoc in self.bundles_assoc.all()
            if assoc.bundle and assoc.bundle.access
        ]

        # update history
        history = self.rule_update_history.order_by(RuleUpdateHistory.analyzed_at.desc()).limit(5).all()
        update_history = [h.to_json() for h in history]

        # similar rules
        similar = RuleSimilarity.query.filter_by(rule_id=self.id).order_by(RuleSimilarity.score.desc()).limit(5).all()
        similar_rules = []
        for s in similar:
            r = Rule.query.get(s.similar_rule_id)
            if r:
                similar_rules.append({
                    "id": r.id,
                    "title": r.title,
                    "format": r.format,
                    "score": round(s.score * 100),
                })

        return {
            # --- identity ---
            "identity": {
                "id": self.id,
                "uuid": self.uuid,
                "original_uuid": self.original_uuid,
                "title": self.title,
                "version": self.version,
                "format": self.format,
            },

            # --- content ---
            "content": {
                "to_string": self.to_string,
                "description": self.description,
                "source": self.source,
                "github_path": self.github_path,
                "extension": self.get_extension(),
            },

            # --- authorship ---
            "authorship": {
                "author": self.author,
                "license": self.license,
                "creation_date": self.creation_date.strftime('%Y-%m-%d %H:%M'),
                "last_modif": self.last_modif.strftime('%Y-%m-%d %H:%M'),
                "submitter": submitter_info,
            },

            # --- community ---
            "community": {
                "votes": {
                    "up": self.vote_up or 0,
                    "down": self.vote_down or 0,
                    "total": total_votes,
                    "ratio_percent": vote_ratio,
                },
                "favorites": {
                    "count": favorites_count,
                    "is_favorited": is_favorited,
                },
                "comments": {
                    "count": self.comments_rule.count(),
                    "latest": comments,
                },
            },

            # --- relations ---
            "relations": {
                "tags": tags,
                "bundles": bundles,
                "similar_rules": similar_rules,
            },

            # --- vulnerability ---
            "vulnerability": {
                "cve_ids": self.cve_id if self.cve_id is not None else [],
            },

            # --- history ---
            "history": {
                "edit_proposals": {
                    "count": self.edit_proposals.count(),
                    "latest": proposals_summary,
                },
                "update_history": update_history,
            },
        }



class FormatRule(db.Model):
    """Table for all the formats of the rules"""
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    creation_date = db.Column(db.DateTime, index=True)
    can_be_execute = db.Column(db.Boolean, nullable=False)

    user = db.relationship('User', backref=db.backref('user_format', lazy='dynamic', cascade='all, delete-orphan'))

    def get_count_rule_with_this_format(self):
        """Return the number of rules with this format, ignoring leading/trailing spaces and case."""
        return Rule.query.filter(
            func.lower(func.trim(Rule.format)) == self.name.lower()
        ).count()

    def to_json(self):
        return {
            "id": self.id,
            "name": self.name,
            "creation_date": self.creation_date.strftime('%Y-%m-%d %H:%M'),
            "user_id": self.user_id,
            "can_be_execute": self.can_be_execute,
            "number_of_rule_with_this_format": self.get_count_rule_with_this_format()
        }
    
    def to_json_light(self):
        return {
            "id": self.id,
            "name": self.name,
            "creation_date": self.creation_date.strftime('%Y-%m-%d %H:%M'),
            "user_id": self.user_id,
            "can_be_execute": self.can_be_execute,
        }



class RuleFavoriteUser(db.Model):
    """Association table for User and Rule favorites."""
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime)

    # Define the relationships with cascade option
    user = db.relationship('User', backref=db.backref('favorite_rules_assocs', lazy='dynamic', cascade='all, delete-orphan'))
    rule = db.relationship('Rule', backref=db.backref('favorited_by_users_assocs', lazy='dynamic', cascade='all, delete-orphan'))


    def to_json(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "rule_id": self.rule_id,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M')
        }

class Comment(db.Model):
    """Model for user comments on rules."""

    id       = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid     = db.Column(db.String(36), unique=True, nullable=True, index=True)
    rule_id  = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    user_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_name = db.Column(db.Text, nullable=False)
    content  = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, index=True)
    updated_at = db.Column(db.DateTime, index=True)
    likes    = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    parent_comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)

    user = db.relationship('User', backref=db.backref('comments_user', lazy='dynamic', cascade='all, delete-orphan'))
    rule = db.relationship('Rule', backref=db.backref('comments_rule', lazy='dynamic', cascade='all, delete-orphan'))
    parent_comment = db.relationship('Comment', remote_side=[id],
                                     backref=db.backref('replies', lazy='dynamic', cascade='all, delete-orphan'))

    def _get_reactions(self):
        from app.core.db_class.db import RuleCommentReaction
        return RuleCommentReaction.query.filter_by(comment_id=self.id).all()

    def to_json(self, user_id=None, include_replies=True):
        reactions_raw = self._get_reactions()
        non_vote = [r.to_json() for r in reactions_raw if r.reaction_type not in ('like', 'dislike')]
        user_has_liked    = any(r.user_id == user_id and r.reaction_type == 'like'    for r in reactions_raw) if user_id else False
        user_has_disliked = any(r.user_id == user_id and r.reaction_type == 'dislike' for r in reactions_raw) if user_id else False
        data = {
            "id":               self.id,
            "uuid":             self.uuid,
            "rule_id":          self.rule_id,
            "user_id":          self.user_id,
            "user_name":        self.user_name,
            "content":          self.content,
            "created_at":       self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            "updated_at":       self.updated_at.strftime('%Y-%m-%d %H:%M') if self.updated_at else None,
            "likes":            self.likes,
            "dislikes":         self.dislikes,
            "is_admin":         self.user.is_admin() if self.user else False,
            "parent_comment_id": self.parent_comment_id,
            "reactions":        non_vote,
            "user_has_liked":   user_has_liked,
            "user_has_disliked": user_has_disliked,
        }
        if include_replies:
            data["replies"] = [r.to_json(user_id=user_id, include_replies=True)
                               for r in self.replies.order_by('id').all()]
        return data


class RuleCommentReaction(db.Model):
    """Like / dislike / emoji reaction on a rule comment."""
    __tablename__ = 'rule_comment_reaction'

    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid         = db.Column(db.String(36), unique=True, nullable=False, index=True)
    rule_id      = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    comment_id   = db.Column(db.Integer, db.ForeignKey('comment.id', ondelete='CASCADE'), nullable=False)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reaction_type = db.Column(db.String(50), nullable=False)
    created_at   = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    user    = db.relationship('User',    backref=db.backref('rule_comment_reactions', lazy='dynamic', cascade='all, delete-orphan'))
    rule    = db.relationship('Rule',    backref=db.backref('comment_reactions',      lazy='dynamic'))
    comment = db.relationship('Comment', backref=db.backref('rule_reactions',         lazy='dynamic', cascade='all, delete-orphan'))

    def to_json(self):
        return {
            "id":            self.id,
            "rule_id":       self.rule_id,
            "comment_id":    self.comment_id,
            "user_id":       self.user_id,
            "reaction_type": self.reaction_type,
            "created_at":    self.created_at.strftime('%Y-%m-%d %H:%M'),
        }


class RequestOwnerRule(db.Model):
    """Model for user-submitted requests visible by admins or rule owners."""
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), index=True)

    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=True)
    rule_source = db.Column(db.String, nullable=True)
    # Snapshot of every rule id covered by this entry — only set for manual
    # bulk ownership grants (bulk_transfer_ownership), which span many rules
    # across possibly-different sources with no single rule_id/rule_source
    # to point to, and can't be reconstructed after the fact by filtering
    # (the rules now belong to the new owner, not whoever "concerned rules"
    # lookups would otherwise search by).
    rule_ids = db.Column(db.JSON, nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Request creator
    user_id_to_send = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Owner targeted by the request

    title = db.Column(db.String(128), nullable=False)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(32), default="pending")

    created_at = db.Column(
        db.DateTime,
        default=datetime.datetime.now(tz=datetime.timezone.utc),
        index=True
    )
    updated_at = db.Column(
        db.DateTime,
        default=datetime.datetime.now(tz=datetime.timezone.utc),
        onupdate=datetime.datetime.now(tz=datetime.timezone.utc),
        index=True
    )

    # Relationships
    user = db.relationship(
        'User',
        foreign_keys=[user_id],
        backref=db.backref('requests', lazy='dynamic', cascade='all, delete-orphan')
    )

    user_owner_rule = db.relationship(
        'User',
        foreign_keys=[user_id_to_send],
        backref=db.backref('owned_requests', lazy='dynamic', cascade='all, delete-orphan')
    )

    rule = db.relationship(
        'Rule',
        foreign_keys=[rule_id],
        backref=db.backref('requests', lazy='dynamic', cascade='all, delete-orphan')
    )
    def get_user_name(self, user_id: int) -> str:
        user = User.query.get(user_id)
        return user.first_name if user else "Unknown"


    def to_json(self):
        return {
            "id": self.id,
            "uuid": self.uuid,
            "user_id": self.user_id,
            "user_who_made_request": self.user.first_name if self.user else "Unknown",
            "user_id_to_send": self.user_id_to_send,
            "user_who_owns_rule": self.user_owner_rule.get_username() if self.user_owner_rule else None,
            "title": self.title,
            "content": self.content,
            "status": self.status,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M'),
            "updated_at": self.updated_at.strftime('%Y-%m-%d %H:%M'),
            "rule_id": self.rule_id,
            "rule_source": self.rule_source,
            "rule_ids": self.rule_ids,
            "rule_count": len(self.rule_ids) if self.rule_ids else None,
        }





class RuleVote(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    vote_type = db.Column(db.String(10), nullable=False)  
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))

    user = db.relationship('User', backref=db.backref('rule_votes', lazy='dynamic', cascade='all, delete-orphan'))
    rule = db.relationship('Rule', backref=db.backref('votes', lazy='dynamic', cascade='all, delete-orphan'))

    def to_json(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "rule_id": self.rule_id,
            "vote_type": self.vote_type,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M')
        }



class InvalidRuleModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(512), nullable=False)
    error_message = db.Column(db.Text, nullable=False)
    raw_content = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))
    rule_type = db.Column(db.String(50), default="Sigma") 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.Text, nullable=False)
    license = db.Column(db.Text)

    github_path = db.Column(db.String , nullable=True)

    user = db.relationship('User', backref=db.backref('user', lazy='dynamic', cascade='all, delete-orphan'))

    def to_json(self):
        return {
            'id': self.id,
            'file_name': self.file_name,
            'error_message': self.error_message,
            'raw_content': self.raw_content,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
            'rule_type': self.rule_type,
            "user_id": self.user_id,
            "url": self.url,
            "license": self.license,
            "github_path": self.github_path if self.github_path else None
        }
    

class RuleEditProposal(db.Model):
    __tablename__ = 'rule_edit_proposal'

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 

    proposed_content = db.Column(db.Text, nullable=False)
    old_content = db.Column(db.Text) 
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.datetime.now(tz=datetime.timezone.utc))
    status = db.Column(db.String(20), default="pending") # pending, approved, rejected

    edit_type = db.Column(db.String(50), nullable=True) # ex: 'typo', 'content_update', 'legal'
    change_score = db.Column(db.Float, nullable=True)   # (0-100)
    
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    rejection_reason = db.Column(db.Text, nullable=True)

    # Relations
    rule = db.relationship('Rule', backref=db.backref('edit_proposals', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('proposed_edits', lazy='dynamic', cascade='all, delete-orphan'))
    reviewer = db.relationship('User', foreign_keys=[reviewed_by_id])

    def get_rule_title(self):
        rule_obj = Rule.query.get(self.rule_id)  
        return rule_obj.title if rule_obj else None


    def to_json(self):
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'rule_name': self.get_rule_title(),
            'user_id': self.user_id,
            'user_name': f"{self.user.first_name} {self.user.last_name}" if self.user else "Unknown",
            'user_avatar': self.user.get_avatar_url() if self.user else None,
            'proposed_content': self.proposed_content,
            'old_content': self.old_content,
            'message': self.message,
            'status': self.status,
            'edit_type': self.edit_type,
            'change_score': self.change_score,
            'comment_count': UnifiedComment.query.filter_by(
                object_type='proposal', object_id=self.id, is_active=True
            ).count(),
            'timestamp': self.timestamp.isoformat(),
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'reviewed_by_id': self.reviewed_by_id,
            'reviewed_by_name': f"{self.reviewer.first_name} {self.reviewer.last_name}" if self.reviewer else None,
            'reviewed_by_avatar': self.reviewer.get_avatar_url() if self.reviewer else None,
            'rejection_reason': self.rejection_reason,
            'comments': [comment.to_json() for comment in self.comments.order_by(RuleEditComment.created_at.asc())] if hasattr(self, 'comments') else []
        }
    def to_json_for_discuss(self):
        rule_obj = Rule.query.get(self.rule_id)
        
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'rule_name': rule_obj.title if rule_obj else "Unknown Rule",
            'rule_format': rule_obj.format if rule_obj else "N/A",
            'status': self.status,
            'edit_type': self.edit_type or 'general',
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M'),
            'change_score': self.change_score,
            'message': self.message,
            'discuss_url': f"/rule/proposal_content_discuss?id={self.id}",
            'status_color': {
                'pending': 'warning',
                'approved': 'success',
                'rejected': 'danger'
            }.get(self.status, 'secondary')
        }


class RuleEditComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    proposal_id = db.Column(db.Integer, db.ForeignKey('rule_edit_proposal.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))

    proposal = db.relationship('RuleEditProposal', backref=db.backref('comments', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User')

    def to_json(self):
        return {
            'id': self.id,
            'proposal_id': self.proposal_id,
            'user_id': self.user_id,
            'user_name': self.user.first_name if self.user else None,
            'content': self.content,
            'created_at': self.created_at.isoformat()
        }

class RuleEditContribution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    proposal_id = db.Column(db.Integer, db.ForeignKey('rule_edit_proposal.id'), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))

    user = db.relationship('User', backref=db.backref('contributions', lazy='dynamic', cascade='all, delete-orphan'))
    proposal = db.relationship('RuleEditProposal', backref=db.backref('contributors', lazy='dynamic', cascade='all, delete-orphan'))
    rule = db.relationship('Rule', backref=db.backref('RULE_proposals', lazy='dynamic',  cascade='all, delete-orphan'))

    def to_json(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "user_name": self.user.first_name if self.user else None,
            "proposal_id": self.proposal_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule.title if self.rule else None,
            'created_at': self.created_at.isoformat(),
            "user_name": self.user.first_name if self.user else None,
            "user_avatar": self.user.get_avatar_url() if self.user else None,
        }


class RepportRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # the user who made the repport
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False) # the rule which has repport
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))
    reason = db.Column(db.Text) # list (....differents reasons)

    user = db.relationship('User', backref=db.backref('user who repport', lazy='dynamic', cascade='all, delete-orphan'))
    rule = db.relationship('Rule', backref=db.backref('the rule repport', lazy='dynamic',  cascade='all, delete-orphan'))

    def to_json(self):
            return {
                "id": self.id,
                "user_id": self.user_id,
                "user_name": self.user.first_name if self.user else None,
                "rule_id": self.rule_id,
                "rule_name": self.rule.title if self.rule else None,
                "rule_user_owner": self.rule.get_rule_user_first_name_by_id() if self.rule else None,
                "rule_owner_id": self.rule.user_id if self.rule else None,
                "rule_owner_avatar": User.query.get(self.rule.user_id).get_avatar_url() if self.rule and self.rule.user_id else None,
                "rule_format": self.rule.format if self.rule else None,
                "message": self.message,
                'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
                "reason": self.reason,
                "content": self.rule.to_string if self.rule else None
            }
    

class Report(db.Model):
    """Unified report model for rules, bundles, and comments."""
    __tablename__ = 'report'

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    object_type = db.Column(db.String(20), nullable=False, index=True)   # 'rule' | 'bundle' | 'comment'
    object_id   = db.Column(db.Integer, nullable=False, index=True)
    reason      = db.Column(db.String(100), nullable=False)
    message     = db.Column(db.Text, nullable=True)
    created_at  = db.Column(db.DateTime,
                            default=lambda: datetime.datetime.now(datetime.timezone.utc),
                            index=True)
    status        = db.Column(db.String(20), default='pending', nullable=False, index=True)
    checked_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    checked_at    = db.Column(db.DateTime, nullable=True)

    user       = db.relationship('User', foreign_keys=[user_id], backref=db.backref('reports_submitted', lazy='dynamic'))
    checked_by = db.relationship('User', foreign_keys=[checked_by_id], backref=db.backref('reports_checked', lazy='dynamic'))

    def get_object_label(self):
        """Human-readable name of the reported object."""
        try:
            if self.object_type == 'rule':
                obj = Rule.query.get(self.object_id)
                return obj.title if obj else f'Rule #{self.object_id}'
            if self.object_type == 'bundle':
                obj = Bundle.query.get(self.object_id)
                return obj.name if obj else f'Bundle #{self.object_id}'
            if self.object_type == 'comment':
                obj = UnifiedComment.query.get(self.object_id)
                if obj and obj.object_type == 'proposal':
                    return f'Comment on proposal #{obj.object_id}'
                return f'Comment #{self.object_id}'
        except Exception:
            pass
        return f'{self.object_type} #{self.object_id}'

    def get_object_url(self):
        if self.object_type == 'rule':
            return f'/rule/detail_rule/{self.object_id}'
        if self.object_type == 'bundle':
            return f'/bundle/detail/{self.object_id}'
        if self.object_type == 'comment':
            c = UnifiedComment.query.get(self.object_id)
            if c:
                if c.object_type == 'rule':
                    return f'/rule/detail_rule/{c.object_id}?comment={c.id}'
                if c.object_type == 'bundle':
                    return f'/bundle/detail/{c.object_id}?comment={c.id}'
                if c.object_type == 'proposal':
                    return f'/rule/proposal_content_discuss?id={c.object_id}&comment={c.id}'
        return '#'

    def to_json(self):
        reporter = self.user
        checker  = self.checked_by
        return {
            'id':               self.id,
            'user_id':          self.user_id,
            'reporter_name':    reporter.get_username() if reporter else '?',
            'user_avatar':      reporter.get_avatar_url() if reporter else None,
            'object_type':      self.object_type,
            'object_id':        self.object_id,
            'object_label':     self.get_object_label(),
            'object_url':       self.get_object_url(),
            'reason':           self.reason,
            'message':          self.message,
            'created_at':       self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            'status':           self.status,
            'checked_by_id':    self.checked_by_id,
            'checked_by_name':  checker.get_username() if checker else None,
            'checked_by_avatar': checker.get_avatar_url() if checker else None,
            'checked_at':       self.checked_at.strftime('%Y-%m-%d %H:%M') if self.checked_at else None,
        }


class RuleUpdateHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    rule_title = db.Column(db.String(255), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    message = db.Column(db.Text, nullable=True)
    new_content = db.Column(db.Text, nullable=True)
    old_content = db.Column(db.Text, nullable=True)
    analyzed_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    analyzed_at = db.Column(db.DateTime, index=True)
    manuel_submit = db.Column(db.Boolean, default=False, nullable=True)
    

    analyzed_by = db.relationship("User", backref=db.backref("rule_updates", lazy='dynamic', cascade='all, delete-orphan'))
    rule = db.relationship("Rule", backref=db.backref("rule_update_history", lazy='dynamic', cascade='all, delete-orphan'))

    def get_rule_format(self):
        """
        Returns the format of the rule with rule_id
        """
        rule = Rule.query.get(self.rule_id)
        if rule:
            return rule.format
        return None
    def get_rule_source(self):
        """
        Returns the source of the rule with rule_id
        """
        rule = Rule.query.get(self.rule_id)
        if rule:
            return rule.source
        return None
    
    def to_json(self):
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "success": self.success,
            "message": self.message,
            "new_content": self.new_content,
            "old_content": self.old_content,
            "analyzed_by_user_id": self.analyzed_by_user_id,
            "analyzed_at": self.analyzed_at.strftime('%Y-%m-%d %H:%M'),
            "analyzed_by_user_name": self.analyzed_by.first_name,
            "rule_format": self.get_rule_format(),
            "rule_source": self.get_rule_source(),
            "manuel_submit": self.manuel_submit if self.manuel_submit else False
        }

class RuleTagAssociation(db.Model):
    __tablename__ = 'rule_tag_association'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # the user who added the tag to the bundle

    added_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))

    rule = db.relationship('Rule', backref=db.backref('rule_tags_assocs', lazy='dynamic', cascade='all, delete-orphan'))
    tag = db.relationship('Tag', backref=db.backref('rules_assocs', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('user_rule_tags_assocs', lazy='dynamic', cascade='all, delete-orphan'))

    def to_json(self):
        return {
            "id": self.id,
            "uuid": self.uuid,
            "rule_id": self.rule_id,
            "tag_id": self.tag_id,
            "user_id": self.user_id,
            "tag_name": self.tag.name if self.tag else None,
            "added_at": self.added_at.strftime('%Y-%m-%d %H:%M'),
        }
    
#############
#   Bundle  #
#############


class Bundle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(255), nullable=False, unique=True, index=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))
    updated_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))
    created_by = db.Column(db.String(255), nullable=False, default="user") # user or bot

    # the creator of the bundle
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


    vote_up = db.Column(db.Integer, nullable=False, default=0)
    vote_down = db.Column(db.Integer, nullable=False, default=0)
    view_count = db.Column(db.Integer, default=0)
    download_count = db.Column(db.Integer, default=0)
    is_verified = db.Column(db.Boolean, default=False) # Badge "officiel"

    # visibility
    access = db.Column(db.Boolean, nullable=False, default=True) # if true all user can see the bundle, if false only the creator can see it

    vulnerability_identifiers = db.Column(db.Text, nullable=True) # JSON string of vulnerability identifiers associated with the bundle

    # Connector origin
    connector_id        = db.Column(db.Integer, db.ForeignKey('connector.id', ondelete='SET NULL'), nullable=True, index=True)
    remote_bundle_uuid  = db.Column(db.String(36), nullable=True, index=True)

    # Set when this bundle was generated via a workspace's "Export as Bundle" action.
    source_workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id', ondelete='SET NULL'), nullable=True, index=True)

    user = db.relationship('User', backref=db.backref('user who create bundle', lazy='dynamic', cascade='all, delete-orphan'))

    def get_username_by_id(self):
        user = User.query.get(self.user_id)  
        return user.first_name if user else None
    def get_rule_user_first_name_by_id(self):
        user = User.query.get(self.user_id)  
        return user.first_name + " " + user.last_name if user else None

    def to_json(self):
        submitter = User.query.get(self.user_id)
        return {
            "id": self.id,
            "author_avatar": submitter.get_avatar_url() if submitter else None,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M'),
            "updated_at": self.updated_at.strftime('%Y-%m-%d %H:%M'),
            "author": self.get_username_by_id() ,
            "user_id": self.user_id,
            "access": self.access,
            "vote_up": self.vote_up,
            "vote_down": self.vote_down,
            "user_name": self.get_rule_user_first_name_by_id(),
            "list_of_format_of_rules": list(set([assoc.rule.format for assoc in self.rules_assoc])),
            "number_of_rules": len(self.rules_assoc.all()),
            "is_verified": self.is_verified,
            "view_count": self.view_count,
            "download_count": self.download_count,
            "uuid": self.uuid,
            "created_by": self.created_by,
            "vulnerability_identifiers": json.loads(self.vulnerability_identifiers) if self.vulnerability_identifiers else [],
            "source_workspace_id": self.source_workspace_id,
        }


class BundleNode(db.Model):
    __tablename__ = 'bundle_node'
    id = db.Column(db.Integer, primary_key=True)
    bundle_id = db.Column(db.Integer, db.ForeignKey('bundle.id', ondelete="CASCADE"), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('bundle_node.id', ondelete="CASCADE"), nullable=True)
    
    name = db.Column(db.String(255), nullable=False)
    node_type = db.Column(db.String(50), nullable=False) # 'folder' or 'file'
    
    custom_content = db.Column(db.Text, nullable=True)
    
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id', ondelete="CASCADE"), nullable=True)

    children = db.relationship(
        "BundleNode", 
        backref=db.backref('parent', remote_side=[id]), 
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    
    rule = db.relationship("Rule") 

    EXTENSION_MAP = {
        'yara': '.yar',
        'sigma': '.yaml',
        'suricata': '.rules',
        'zeek': '.zeek',
        'wazuh': '.xml',
        'nse': '.nse',
        'nova': '.yaml',
        'crs': '.conf',
        'no format': '.txt'
    }

    def to_tree_json(self):
        """Recursively converts nodes to the JSON tree expected by Vue.js"""
        if self.rule_id and self.rule:
            # Use lowercase format to match the mapping keys
            rule_format = self.rule.format.lower() if self.rule.format else 'no format'
            ext = self.EXTENSION_MAP.get(rule_format, '.txt')
            
            # Display name includes the extension in the tree explorer
            current_name = f"{self.rule.title}{ext}"
            current_content = self.rule.to_string
            node_id = f"rule_{self.rule_id}_{self.id}"
        else:
            current_name = self.name
            current_content = self.custom_content or ""
            node_id = f"node_{self.id}"

        node_data = {
            "id": node_id,
            "name": current_name,
            "type": self.node_type,
            "content": current_content,
            "children": [child.to_tree_json() for child in self.children]
        }
        
        if self.rule_id:
            node_data["rule_id"] = self.rule_id
            
        return node_data
    

class Tag(db.Model):
    __tablename__ = "tag"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    name = db.Column(db.Text, unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))
    updated_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))
    is_active = db.Column(db.Boolean, default=False)
    visibility = db.Column(db.String(255), nullable=True)
    external_id = db.Column(db.String, nullable=True)

    color = db.Column(db.String(50), nullable=True) # Hex color code, e.g., #FF5733
    icon = db.Column(db.String(50), nullable=True) # fontawesome icon name
    source = db.Column(db.String(255), nullable=True) # Taxonomy or Manuel or Other

    # Metadata for galxie (galaxie -> tag with galaxie_meta not null)
    galaxy_meta = db.Column(db.JSON, nullable=True)

    # Relationships

    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    is_approved_by_admin = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref=db.backref('tags', lazy='dynamic', cascade='all, delete-orphan'))

    def to_json(self):
        return {
            "id": self.id,
            "uuid": self.uuid,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M'),
            "updated_at": self.updated_at.strftime('%Y-%m-%d %H:%M'),
            "is_active": self.is_active,
            "visibility": self.visibility,
            "color": self.color,
            "icon": self.icon,
            "created_by_user_id": self.created_by,
            "created_by_user_name": self.user.first_name if self.user else None,
            "is_approved_by_admin": self.is_approved_by_admin,
            "external_id": self.external_id,
            "source": self.source,
            "galaxy_meta": self.galaxy_meta if self.galaxy_meta else None,
            # Injected by _inject_usage_counts() in tags_core.py — falls back to 0
            # when called outside a listing context (e.g. direct Tag.to_json()).
            "rule_count":   getattr(self, '_rule_count',   0),
            "bundle_count": getattr(self, '_bundle_count', 0),
        }
 


class CommentBundle(db.Model):
    """Model for user comments on Bundles."""
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    bundle_id = db.Column(db.Integer, db.ForeignKey('bundle.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_name = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, index=True)
    updated_at = db.Column(db.DateTime, index=True)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    # reaction = db.Column(db.String(50), nullable=True) # emodji reaction

    # respond from an other comment
    parent_comment_id = db.Column(db.Integer, db.ForeignKey('comment_bundle.id'), nullable=True)
   
    # Relations
    user = db.relationship('User', backref=db.backref('comments_users', lazy='dynamic' , cascade='all, delete-orphan'))
    bundle = db.relationship('Bundle', backref=db.backref('comments_bundles', lazy='dynamic', cascade='all, delete-orphan'))
    parent_comment = db.relationship(
        'CommentBundle', 
        remote_side=[id], 
        backref=db.backref('replies', lazy='dynamic', cascade='all, delete-orphan')
    )
    #get_all_reactions
    def get_all_reactions(self):
        """Only reaction different from like or dislike"""
        reactions = BundleReactionComment.query.filter_by(comment_id=self.id).all()
        # remove like and dislike from the list
        reactions = [reaction for reaction in reactions if reaction.reaction_type not in ['like', 'dislike']]
        return [reaction.to_json() for reaction in reactions]
    
    def get_username_by_id(self):
        user = User.query.get(self.user_id)  
        return user.first_name + " " + user.last_name if user else self.user_name

    def to_json(self, include_replies=True):
        data = {
            "id": self.id,
            "bundle_id": self.bundle_id,
            "user_id": self.user_id,
            "user_name": self.get_username_by_id(),
            "content": self.content,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            "is_admin": self.user.is_admin() if self.user else False,
            "parent_comment_id": self.parent_comment_id,
            "likes": self.likes,
            "dislikes": self.dislikes,
            # get all the reaction for this comment from BundleREactionComment not the champ reaction
            "reactions":  self.get_all_reactions(),
        }

        if include_replies:
            data["replies"] = [reply.to_json(include_replies=True) for reply in self.replies.all()]
        
        return data

class BundleReactionComment(db.Model):
    """ LIKE/DISLIKE/EMOJI reaction on comment in a Bundle """
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    bundle_id = db.Column(db.Integer, db.ForeignKey('bundle.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment_bundle.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reaction_type = db.Column(db.String(50), nullable=False) # e.g., 'like', 'dislike', 'emoji_name'
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))

    user = db.relationship('User', backref=db.backref('bundle_reactions', lazy='dynamic', cascade='all, delete-orphan'))
    bundle = db.relationship('Bundle', backref=db.backref('reactions', lazy='dynamic', cascade='all, delete-orphan'))
    comment = db.relationship('CommentBundle', backref=db.backref('reactions', lazy='dynamic', cascade='all, delete-orphan'))

    def to_json(self):
        return {
            "id": self.id,
            "bundle_id": self.bundle_id,
            "user_id": self.user_id,
            "reaction_type": self.reaction_type,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M'),
            "is_admin": self.user.is_admin(),
            "comment_id": self.comment_id
        }

class BundleVote(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bundle_id = db.Column(db.Integer, db.ForeignKey('bundle.id'), nullable=False)
    vote_type = db.Column(db.String(10), nullable=False)  
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))

    user = db.relationship('User', backref=db.backref('user_votes_bundle', lazy='dynamic', cascade='all, delete-orphan'))
    bundle = db.relationship('Bundle', backref=db.backref('bundle', lazy='dynamic', cascade='all, delete-orphan'))

    def to_json(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "bundle_id": self.bundle_id,
            "vote_type": self.vote_type,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M')
        }

class BundleTagAssociation(db.Model):
    __tablename__ = 'bundle_tag_association'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    bundle_id = db.Column(db.Integer, db.ForeignKey('bundle.id'), nullable=False)
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # the user who added the tag to the bundle

    added_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))

    bundle = db.relationship('Bundle', backref=db.backref('tags_assocs', lazy='dynamic', cascade='all, delete-orphan'))
    tag = db.relationship('Tag', backref=db.backref('bundles_assocs', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('user_tags_assocs', lazy='dynamic', cascade='all, delete-orphan'))

    def to_json(self):
        return {
            "id": self.id,
            "uuid": self.uuid,
            "bundle_id": self.bundle_id,
            "tag_id": self.tag_id,
            "user_id": self.user_id,
            "tag_name": self.tag.name if self.tag else None,
            "added_at": self.added_at.strftime('%Y-%m-%d %H:%M'),
        }


class BundleRuleAssociation(db.Model):
    # Table to associate rule and a bundle 
    # rule can be in many bundles and a bundle can have many rules
    id = db.Column(db.Integer, primary_key=True)
    bundle_id = db.Column(db.Integer, db.ForeignKey('bundle.id'), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    description = db.Column(db.Text)

    added_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))

    bundle = db.relationship('Bundle', backref=db.backref('rules_assoc', lazy='dynamic', cascade='all, delete-orphan'))
    rule = db.relationship('Rule', backref=db.backref('bundles_assoc', lazy='dynamic', cascade='all, delete-orphan'))

    def to_json(self):
        return {
            "id": self.id,
            "bundle_id": self.bundle_id,
            "rule_id": self.rule_id,
            "bundle_name": self.bundle.name if self.bundle else None,
            "rule_title": self.rule.title if self.rule else None,
            "description": self.description,
            "added_at": self.added_at.strftime('%Y-%m-%d %H:%M'),
        }

class JSONEncodedList(TypeDecorator):
    impl = String

    def process_bind_param(self, value, dialect):
        if value is None:
            return '[]'
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return []
        return json.loads(value)    

class ImporterResult(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    info = db.Column(db.String)
    bad_rules = db.Column(db.Integer, index=True)
    imported = db.Column(db.Integer, index=True)
    skipped = db.Column(db.Integer, index=True)
    total = db.Column(db.Integer, index=True)
    query_date = db.Column(db.DateTime, index=True)
    user_id = db.Column(db.Integer, index=True)
    count_per_format = db.Column(db.String)

    def to_json(self):
        json_dict = {
            "id": self.id,
            "uuid": self.uuid,
            "info": json.loads(self.info),
            "bad_rules": self.bad_rules,
            "imported": self.imported,
            "skipped": self.skipped,
            "total": self.total,
            "query_date": self.query_date.strftime('%Y-%m-%d %H:%M'),
            "user_id": self.user_id,
            "count_per_format": json.loads(self.count_per_format)
        }
        return json_dict
    
class UpdateResult(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), index=True, unique=True)

    user_id = db.Column(db.String, index=True)        # user that triggered the update
    mode = db.Column(db.String, nullable=False)        # update mode: url / rule / repo

    info = db.Column(db.Text, nullable=True)           # optional info (json encoded string)
    repo_sources = db.Column(db.Text, nullable=True)   # json list or dict encoded as text

    not_found = db.Column(db.Integer, default=0)
    found = db.Column(db.Integer, default=0)
    updated = db.Column(db.Integer, default=0)
    skipped = db.Column(db.Integer, default=0)
    total = db.Column(db.Integer, index=True)

    thread_count = db.Column(db.Integer, default=4)
    query_date = db.Column(db.DateTime, index=True)

    # Relationships
    rule_statuses = db.relationship(
        "RuleStatus",
        backref="update_result",
        cascade="all, delete-orphan",
        lazy=True
    )

    new_rules = db.relationship(
        "NewRule",
        backref="update_result",
        cascade="all, delete-orphan",
        lazy=True
    )


    def _get_rule_name_by_mode(self):
        if self.mode != "by_rule":
            return None

        try:
            repo_data = json.loads(self.repo_sources) if self.repo_sources else None
            if not repo_data:
                return None

            rule_ids = repo_data if isinstance(repo_data, list) else [repo_data]

            rule_names = []
            for rid in rule_ids:
                rule = Rule.get_rule_name_by_id(rid)
                if rule:
                    rule_names.append(rule if isinstance(rule, str) else getattr(rule, "title", str(rule)))
                else:
                    rule_names.append(f"Rule {rid} not found")

            return rule_names if len(rule_names) > 1 else rule_names[0]

        except Exception as e:
            return None


    def to_json(self):
        return {
            "id": self.id,
            "uuid": self.uuid,
            "user_id": self.user_id,
            "mode": self.mode,
            "info": json.loads(self.info) if self.info else None,
            "repo_sources": json.loads(self.repo_sources) if self.repo_sources else None,
            "not_found": self.not_found,
            "found": self.found,
            "updated": self.updated,
            "skipped": self.skipped,
            "total": self.total,
            "thread_count": self.thread_count,
            "query_date": self.query_date.strftime('%Y-%m-%d %H:%M') if self.query_date else None,
            "rules": [rule.to_json() for rule in self.rule_statuses] if self.rule_statuses else [],
            "new_rules": [nr.to_json() for nr in self.new_rules] if self.new_rules else []
        }
    
    def to_json_list(self):
        json_dict = self.to_json()
        del json_dict["rules"]
        json_dict["rule_name_by_rule_mode"] = self._get_rule_name_by_mode()
        return json_dict        
    

class RuleStatus(db.Model):
    __tablename__ = "rule_status"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), index=True, unique=True)

    update_result_id = db.Column(
        db.Integer,
        db.ForeignKey("update_result.id", ondelete="CASCADE"),
        nullable=False
    )

    date = db.Column(db.DateTime, index=True)
    name_rule = db.Column(db.String, nullable=False)
    rule_id = db.Column(db.String, nullable=True)

    # delete !

    message = db.Column(db.Text, nullable=True)

    found = db.Column(db.Boolean, default=False)
    update_available = db.Column(db.Boolean, default=False)
    rule_syntax_valid = db.Column(db.Boolean, default=True)
    error = db.Column(db.Boolean, default=False)

    history_id = db.Column(db.String, nullable=True)
    def _get_rule(self):
        if not self.rule_id:
            return None
        try:
            return Rule.query.filter_by(id=int(self.rule_id)).first()
        except (ValueError, TypeError):
            return None

    def get_format(self):
        r = self._get_rule()
        return r.format if r else None

    def get_title(self):
        r = self._get_rule()
        return r.title if r else None

    def to_json(self):
        return {
            "id": self.id,
            "uuid": self.uuid,
            "update_result_id": self.update_result_id,
            "date": self.date.strftime('%Y-%m-%d %H:%M') if self.date else None,
            "name_rule": self.name_rule,
            "rule_title": self.get_title(),
            "rule_id": self.rule_id,
            "message": self.message,
            "found": self.found,
            "update_available": self.update_available,
            "rule_syntax_valid": self.rule_syntax_valid,
            "error": self.error,
            "history_id": self.history_id,
            "format": self.get_format()
        }

class NewRule(db.Model):
    __tablename__ = "new_rule"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), index=True, unique=True)

    update_result_id = db.Column(
        db.Integer,
        db.ForeignKey("update_result.id", ondelete="CASCADE"),
        nullable=False
    )
    format = db.Column(db.String(50), nullable=True)
    date = db.Column(db.DateTime, index=True)
    name_rule = db.Column(db.String, nullable=False)
    rule_content = db.Column(db.Text, nullable=False)

    message = db.Column(db.Text, nullable=True)

    rule_syntax_valid = db.Column(db.Boolean, default=True)
    error = db.Column(db.Boolean, default=False)
    accept = db.Column(db.Boolean, default=False)
    github_path = db.Column(db.String, nullable=True)


    def to_json(self):
        return {
            "id": self.id,
            "uuid": self.uuid,
            "update_result_id": self.update_result_id,
            "date": self.date.strftime('%Y-%m-%d %H:%M') if self.date else None,
            "name_rule": self.name_rule,
            "rule_content": self.rule_content,
            "message": self.message,
            "format": self.format,
            "rule_syntax_valid": self.rule_syntax_valid,
            "error": self.error,
            "accept": self.accept,
            "github_path": self.github_path
        }



############################################
#    Gamification of users contribution    #
############################################

# --- Point Definitions (Used in Gamification Listener) ---
POINTS = {
    'suggestions_accepted': 100,
    'rules_owned': 10,
    'rules_liked_or_disliked': 1,
    'consecutive_days_active': 1,
    'rules_popular_score': 1
}

# if you have more than 15000 points you will be level 3...
LEVEL_THRESHOLDS = {
    1: 0,
    2: 500,
    3: 15000,
    4: 30000,
    5: 50000,
    10: 150000,
    20: 300000,
    100: 1500000
}

class Gamification(db.Model):
    __tablename__ = "gamification"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete='CASCADE'), nullable=False) 

    # ----------------------------------------------------
    # 1. CORE SCORES AND RANKING
    # ----------------------------------------------------
    total_points = db.Column(db.Integer, default=0, index=True)
    current_level = db.Column(db.Integer, default=1)
    # addition of all the level points
    
    # ----------------------------------------------------
    # 2. CONTRIBUTION METRICS (RuleSuggestion)
    # ----------------------------------------------------
    suggestions_submitted = db.Column(db.Integer, default=0)
    suggestions_accepted = db.Column(db.Integer, default=0, index=True)
    suggestions_rejected = db.Column(db.Integer, default=0)
    
    # ----------------------------------------------------
    # 3. RULE IMPORTATION METRICS (Rule)
    # ----------------------------------------------------
    rules_owned = db.Column(db.Integer, default=0)
    rules_popular_score = db.Column(db.Integer, default=0)
    
    # ----------------------------------------------------
    # 4. COMMUNITY INTERACTION METRICS (RuleLike)
    # ----------------------------------------------------
    rules_liked = db.Column(db.Integer, default=0, index=True)
    rules_disliked = db.Column(db.Integer, default=0)
    
    # ----------------------------------------------------
    # 5. ACTIVITY / TIMING
    # ----------------------------------------------------
    last_contribution_date = db.Column(db.DateTime, nullable=True)
    consecutive_days_active = db.Column(db.Integer, default=0)

    # ----------------------------------------------------
    # 6. RELATIONSHIP
    # ----------------------------------------------------

    user = db.relationship('User', backref=db.backref('gamification_stats', uselist=False, cascade='all, delete-orphan'))

    def to_json(self):
        return {
            "id": self.id,
            "uuid": self.uuid,
            "user_id": self.user_id,
            "user": self.user.to_json(),
            "total_points": self.total_points,
            "current_level": self.current_level,
            "suggestions_submitted": self.suggestions_submitted,
            "suggestions_accepted": self.suggestions_accepted,
            "suggestions_rejected": self.suggestions_rejected,
            "rules_owned": self.rules_owned,
            "rules_popular_score": self.rules_popular_score,
            "rules_liked": self.rules_liked,
            "rules_disliked": self.rules_disliked,
            "last_contribution_date": self.last_contribution_date,
            "consecutive_days_active": self.consecutive_days_active,
            "global_rank": self.get_global_rank()
        }
    
    def get_global_rank(self):
        if self.total_points is None:
            return None
        
        try:
            rank = (
                db.session.query(Gamification)
                .filter(Gamification.total_points > self.total_points)
                .count()
            )
            return rank + 1
            
        except Exception as e:
            return None
    def calculate_total_points(self):
        score = 0
        score += self.suggestions_accepted * POINTS['suggestions_accepted']
        score += self.rules_owned * POINTS['rules_owned']
        score += self.rules_popular_score * POINTS['rules_popular_score']
        score += self.rules_liked * POINTS['rules_liked_or_disliked']
        return score

    def calculate_current_level(self, points):
        level = 1
        sorted_levels = sorted(LEVEL_THRESHOLDS.keys(), reverse=True)
        
        for lvl in sorted_levels:
            if points >= LEVEL_THRESHOLDS[lvl]:
                level = lvl
                break
        return level

    def update_scores(self):
        new_points = self.calculate_total_points()
        
        if self.total_points != new_points:
            self.total_points = new_points
            self.current_level = self.calculate_current_level(new_points)

def receive_before_flush(session, flush_context, instances):
    """
    Listener to check and update Gamification scores before a transaction is committed.
    """
    for instance in session.dirty:
        if isinstance(instance, Gamification):
            has_changed = False
            for field in ['suggestions_accepted', 'rules_owned', 'rules_liked', 'rules_popular_score', 'consecutive_days_active']:
                
               
                history = attributes.instance_state(instance).get_history(field, passive=PASSIVE_NO_INITIALIZE)

                
                if history.has_changes():
                    has_changed = True
                    break
            
            if has_changed:
                instance.update_scores()

event.listen(db.session, 'before_flush', receive_before_flush)

#####################
#   Similar Rule    #
#####################

class SimilarResult(db.Model):
    """Stores the summary/history of a similarity computation task."""
    __tablename__ = "similar_result"
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    info = db.Column(db.String)  # Description or parameters used
    date = db.Column(db.DateTime, index=True, default=func.now())
    
    # 'global' for all rules, 'specific' for a subset/single rule
    mode = db.Column(db.String(20), nullable=False) 
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete='CASCADE'), nullable=False)

    total_rules_processed = db.Column(db.Integer, default=0)
    similar_pairs_found = db.Column(db.Integer, default=0)
    time_taken = db.Column(db.Integer, default=0) # in seconds

    def to_json(self):
        return {
            "uuid": self.uuid,
            "info": self.info,
            "date": self.date.isoformat() if self.date else None,
            "mode": self.mode,
            "total_rules_processed": self.total_rules_processed,
            "similar_pairs_found": self.similar_pairs_found,
            "time_taken": self.time_taken
        }

class RuleSimilarity(db.Model):
    """
    Association table storing the similarity score between two rules.
    We only store the Top 50 per rule.
    """
    __tablename__ = "rule_similarity"
    
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("rule.id", ondelete='CASCADE'), index=True)
    similar_rule_id = db.Column(db.Integer, db.ForeignKey("rule.id", ondelete='CASCADE'))
    
    # score between 0.0 and 1.0
    score = db.Column(db.Float, index=True) 
    
    # Reference to which scan produced this result
    result_uuid = db.Column(db.String(36), db.ForeignKey("similar_result.uuid"))

    # Ensure we don't store duplicates for the same pair in the same scan
    __table_args__ = (db.UniqueConstraint('rule_id', 'similar_rule_id', name='_rule_pair_uc'),)

    def to_json(self):
        return {
            "rule_id": self.rule_id,
            "similar_rule_id": self.similar_rule_id,
            "score": self.score
        }




########################################
#   Background Job Queue               #
########################################
 
class BackgroundJob(db.Model):
    """Persistent background job — any long-running task goes through this."""
    __tablename__ = 'background_job'
 
    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid        = db.Column(db.String(36), unique=True, nullable=False, index=True)
    created_by  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
 
    # job type e.g. 'bulk_add_tag_to_rules', 'bulk_remove_tag_from_rules'
    job_type    = db.Column(db.String(64), nullable=False, index=True)
 
    # status: pending | running | done | failed | cancelled | paused
    status      = db.Column(db.String(16), nullable=False, default='pending', index=True)
 
    total       = db.Column(db.Integer, default=0)
    done        = db.Column(db.Integer, default=0)
 
    # arbitrary JSON payload — filters, tag ids, resume offset, etc.
    payload     = db.Column(db.JSON, nullable=True)
 
    # human-readable label shown in the UI
    label       = db.Column(db.String(255), nullable=True)
 
    error       = db.Column(db.Text, nullable=True)
 
    created_at  = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    started_at  = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
 
    user = db.relationship('User', backref=db.backref('background_jobs', lazy='dynamic',
                                                       cascade='all, delete-orphan'))
    logs = db.relationship('BackgroundJobLog', backref='job',
                           lazy='dynamic', cascade='all, delete-orphan',
                           order_by='BackgroundJobLog.created_at')
 
    @property
    def progress_pct(self):
        if not self.total:
            # a finished job with no countable items is still 100% complete
            return 100 if self.status == 'done' else 0
        return round((self.done / self.total) * 100)
 
    def to_json(self):
        return {
            "id":           self.id,
            "uuid":         self.uuid,
            "job_type":     self.job_type,
            "status":       self.status,
            "total":        self.total,
            "done":         self.done,
            "progress_pct": self.progress_pct,
            "label":        self.label,
            "error":        self.error,
            "created_by":   self.created_by,
            "created_at":   self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "started_at":   self.started_at.strftime('%Y-%m-%d %H:%M:%S') if self.started_at else None,
            "finished_at":  self.finished_at.strftime('%Y-%m-%d %H:%M:%S') if self.finished_at else None,
        }
 
 
class BackgroundJobLog(db.Model):
    """
    Structured log lines for a background job.
    Each significant event (start, pause, resume, batch progress, done, error)
    writes one row here so the UI can display a real-time activity feed.
    """
    __tablename__ = 'background_job_log'
 
    id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    job_id     = db.Column(db.Integer, db.ForeignKey('background_job.id', ondelete='CASCADE'),
                           nullable=False, index=True)
 
    # level: info | success | warning | error
    level      = db.Column(db.String(16), nullable=False, default='info')
 
    # short machine-readable event key e.g. 'started', 'paused', 'batch', 'done', 'cancelled'
    event      = db.Column(db.String(64), nullable=True)
 
    message    = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.datetime.now(datetime.timezone.utc))
 
    def to_json(self):
        return {
            "id":         self.id,
            "level":      self.level,
            "event":      self.event,
            "message":    self.message,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        }


########################################
#   Activity Log                       #
########################################

class ActivityLog(db.Model):
    """Records every significant user action across the platform."""
    __tablename__ = 'activity_log'

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid        = db.Column(db.String(36), unique=True, nullable=False, index=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True, index=True)

    # e.g. "rule.create", "rule.delete", "user.login", "bundle.edit", "admin.promote_user"
    action      = db.Column(db.String(64), nullable=False, index=True)
    title       = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    category    = db.Column(db.String(32), nullable=True, index=True)
    level       = db.Column(db.String(16), nullable=True, index=True)

    ip_address  = db.Column(db.String(45), nullable=True)   # IPv4 or IPv6
    url         = db.Column(db.String(512), nullable=True)
    method      = db.Column(db.String(8), nullable=True)
    user_agent  = db.Column(db.String(256), nullable=True)

    # What entity was acted on
    target_type = db.Column(db.String(32), nullable=True, index=True)  # "rule" | "bundle" | "user" | "tag" | "job"
    target_id   = db.Column(db.Integer, nullable=True)
    target_uuid = db.Column(db.String(36), nullable=True)

    extra       = db.Column(db.JSON, nullable=True)

    # Visibility & display
    is_public   = db.Column(db.Boolean, nullable=False, default=False, index=True)
    icon        = db.Column(db.String(64), nullable=True)   # FontAwesome class e.g. "fa-solid fa-file-shield"
    created_at  = db.Column(db.DateTime, nullable=False,
                            default=lambda: datetime.datetime.now(datetime.timezone.utc),
                            index=True)

    user = db.relationship('User', backref=db.backref('activity_logs', lazy='dynamic'))

    def to_json(self):
        username = "System"
        try:
            if self.user:
                username = self.user.get_username()
        except Exception:
            pass
        return {
            "id":          self.id,
            "uuid":        self.uuid,
            "user_id":     self.user_id,
            "username":    username,
            "actor_name":  username,
            "action":      self.action,
            "title":       self.title or '',
            "category":    self.category or 'system',
            "level":       self.level or 'info',
            "description": self.description,
            "ip_address":  self.ip_address,
            "user_agent":  self.user_agent,
            "url":         self.url,
            "method":      self.method,
            "target_type": self.target_type,
            "target_id":   self.target_id,
            "target_uuid": self.target_uuid,
            "extra":       self.extra,
            "is_public":   self.is_public,
            "icon":        self.icon,
            "created_at":  self.created_at.strftime('%Y-%m-%dT%H:%M:%S') + 'Z',
        }
    
    def to_json_public(self):
        username = "System"
        try:
            if self.user:
                username = self.user.get_username()
        except Exception:
            pass
        return {
            "id":          self.id,
            "uuid":        self.uuid,
            "user_id":     self.user_id,
            "username":    username,
            "action":      self.action,
            "description": self.description,
            "url":         self.url,
            "method":      self.method,
            "target_type": self.target_type,
            "target_id":   self.target_id,
            "target_uuid": self.target_uuid,
            "extra":       self.extra,
            "is_public":   self.is_public,
            "icon":        self.icon,
            "created_at":  self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        }


class LogActionDefinition(db.Model):
    """Admin-editable display overrides for activity-log action keys.

    Presence of a row for an action_key means "admin has customized this action's
    display"; any column left NULL falls back to the hardcoded default in
    app/features/admin/log_action_defaults.py (see log_definitions_core.py).
    """
    __tablename__ = 'log_action_definition'

    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    action_key    = db.Column(db.String(64), unique=True, nullable=False, index=True)
    icon          = db.Column(db.String(64), nullable=True)
    title         = db.Column(db.String(255), nullable=True)
    is_public     = db.Column(db.Boolean, nullable=True)  # NULL = inherit default
    category      = db.Column(db.String(32), nullable=True)
    updated_at    = db.Column(db.DateTime, nullable=False,
                              default=lambda: datetime.datetime.now(datetime.timezone.utc),
                              onupdate=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)

    updated_by = db.relationship('User', foreign_keys=[updated_by_id])

    def to_json(self):
        return {
            "id":         self.id,
            "action_key": self.action_key,
            "icon":       self.icon,
            "title":      self.title,
            "is_public":  self.is_public,
            "category":   self.category,
            "updated_at": self.updated_at.strftime('%Y-%m-%dT%H:%M:%S') + 'Z' if self.updated_at else None,
        }


class PivotickBackground(db.Model):
    """Admin-uploaded background image for PivoTick graph canvases.

    Uploaded by an admin, but selectable by ANY user on /settings as their
    personal PivoTick canvas background (choice stored client-side, see
    rz-pivotick-bg-image in localStorage — this table is just the shared gallery).
    """
    __tablename__ = 'pivotick_background'

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid        = db.Column(db.String(36), unique=True, nullable=False, index=True)
    filename    = db.Column(db.String(256), nullable=False)
    name        = db.Column(db.String(128), nullable=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    created_at  = db.Column(db.DateTime, nullable=False,
                            default=lambda: datetime.datetime.now(datetime.timezone.utc))

    def get_url(self):
        return "/static/uploads/pivotick_backgrounds/" + self.filename

    def to_json(self):
        return {
            "id":         self.id,
            "uuid":       self.uuid,
            "name":       self.name or self.filename,
            "url":        self.get_url(),
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M'),
        }


class RuleScope(db.Model):
    """One scope declaration per user per rule — captures the environment where a rule works (or not)."""
    __tablename__ = 'rule_scope'

    id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid       = db.Column(db.String(36), unique=True, nullable=False, index=True)
    rule_id    = db.Column(db.Integer, db.ForeignKey('rule.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id',  ondelete='CASCADE'), nullable=False)

    works      = db.Column(db.Boolean, nullable=False, default=True)   # True = "works for me"
    entries    = db.Column(db.JSON,    nullable=False, default=list)    # [{"key": "os", "value": "linux"}, …]
    comment    = db.Column(db.Text,    nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))
    updated_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc),
                           onupdate=datetime.datetime.now(tz=datetime.timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('rule_id', 'user_id', name='uq_rule_scope_user'),
    )

    rule = db.relationship('Rule', backref=db.backref('scope_declarations', lazy='dynamic',
                                                       cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('scope_declarations', lazy='dynamic'))

    def to_json(self):
        return {
            'id':         self.id,
            'uuid':       self.uuid,
            'user_id':    self.user_id,
            'username':   self.user.get_username() if self.user else 'Unknown',
            'works':      self.works,
            'entries':    self.entries or [],
            'comment':    self.comment or '',
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M') if self.updated_at else None,
        }


####################
#    Connector     #
####################

class Connector(db.Model):
    """
    Generic connector between this Rulezet instance and any external source.

    The connector_type field determines the protocol adapter to use.
    Currently implemented: 'rulezet'.
    Planned: 'misp', 'opencti', 'github_advisory', …

    Every user can create their own connectors — this is not admin-only.
    A shadow_user is auto-created when the connector is first saved so that
    imported content always has a valid local user_id without breaking the
    ownership model.
    """
    __tablename__ = 'connector'

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid        = db.Column(db.String(36), unique=True, nullable=False, index=True)

    # Human-readable identity
    name        = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    icon        = db.Column(db.String(64), nullable=True)   # FontAwesome class e.g. 'fa-solid fa-plug'

    # Protocol adapter — keep extensible
    connector_type = db.Column(db.String(64), nullable=False, default='rulezet', index=True)

    # Remote connection
    instance_url     = db.Column(db.String(512), nullable=False)
    api_key_outbound = db.Column(db.String(512), nullable=True)   # key used to auth TO the remote

    # Ownership: per user (not admin-only)
    owner_id       = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shadow_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # What to sync
    sync_rules   = db.Column(db.Boolean, nullable=False, default=True)
    sync_bundles = db.Column(db.Boolean, nullable=False, default=False)

    # Who owns imported content: 'shadow' = ghost user | 'self' = connector owner
    owner_mode = db.Column(db.String(16), nullable=False, default='shadow')

    # System connectors (e.g. official Rulezet) are read-only and visible to all users
    is_system = db.Column(db.Boolean, nullable=False, default=False, index=True)

    # Status
    is_active   = db.Column(db.Boolean, nullable=False, default=True)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)  # True after first successful pull
    last_error  = db.Column(db.Text, nullable=True)

    # Sync tracking
    last_sync_at    = db.Column(db.DateTime, nullable=True)
    rules_synced    = db.Column(db.Integer, nullable=False, default=0)
    bundles_synced  = db.Column(db.Integer, nullable=False, default=0)

    # Remote instance totals — updated on each successful connection test
    remote_rules_count   = db.Column(db.Integer, nullable=True)
    remote_bundles_count = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc),
                           onupdate=lambda: datetime.datetime.now(datetime.timezone.utc))

    owner       = db.relationship('User', foreign_keys=[owner_id],
                                  backref=db.backref('connectors', lazy='dynamic'))
    shadow_user = db.relationship('User', foreign_keys=[shadow_user_id])

    def to_json(self):
        local_rules_count   = Rule.query.filter_by(connector_id=self.id, is_deleted=False).count()
        local_bundles_count = Bundle.query.filter_by(connector_id=self.id).count()
        return {
            'id':             self.id,
            'uuid':           self.uuid,
            'name':           self.name,
            'description':    self.description or '',
            'icon':           self.icon or 'fa-solid fa-plug',
            'connector_type': self.connector_type,
            'instance_url':   self.instance_url,
            'sync_rules':     self.sync_rules,
            'sync_bundles':   self.sync_bundles,
            'owner_mode':     self.owner_mode,
            'is_system':      self.is_system,
            'is_active':      self.is_active,
            'is_verified':    self.is_verified,
            'last_error':     self.last_error,
            'last_sync_at':   self.last_sync_at.strftime('%Y-%m-%d %H:%M') if self.last_sync_at else None,
            'rules_count':    self.remote_rules_count,
            'bundles_count':  self.remote_bundles_count,
            'local_rules_count':    local_rules_count,
            'local_bundles_count':  local_bundles_count,
            'rules_synced':   self.rules_synced,
            'bundles_synced': self.bundles_synced,
            'owner_id':       self.owner_id,
            'created_at':     self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
        }


##########################
#   Instance Registry    #
##########################

class InstanceConfig(db.Model):
    """Single-row: this instance's persistent UUID and telemetry settings."""
    __tablename__ = 'instance_config'
    id                = db.Column(db.Integer, primary_key=True)
    uuid              = db.Column(db.String(36), unique=True, nullable=False)
    telemetry_enabled = db.Column(db.Boolean, default=True, nullable=False)
    public_url        = db.Column(db.String(512), nullable=True)
    version           = db.Column(db.String(64), nullable=True)
    last_started_at   = db.Column(db.DateTime, nullable=True)
    created_at        = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_json(self):
        return {
            'uuid':              self.uuid,
            'telemetry_enabled': self.telemetry_enabled,
            'public_url':        self.public_url,
            'version':           self.version,
            'last_started_at':   self.last_started_at.strftime('%Y-%m-%d %H:%M') if self.last_started_at else None,
            'created_at':        self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
        }


class RegisteredInstance(db.Model):
    """Remote Rulezet instances that have phoned home to this instance."""
    __tablename__ = 'registered_instance'
    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid          = db.Column(db.String(36), unique=True, nullable=False, index=True)
    public_url    = db.Column(db.String(512), nullable=True)
    ip_address    = db.Column(db.String(45),  nullable=True)
    version       = db.Column(db.String(64),  nullable=True)
    rules_count   = db.Column(db.Integer,     nullable=True)
    bundles_count = db.Column(db.Integer,     nullable=True)
    ping_count    = db.Column(db.Integer,     default=1, nullable=False)
    first_seen    = db.Column(db.DateTime,    nullable=False)
    last_seen     = db.Column(db.DateTime,    nullable=False, index=True)

    def to_json(self):
        return {
            'uuid':          self.uuid,
            'public_url':    self.public_url,
            'ip_address':    self.ip_address,
            'version':       self.version,
            'rules_count':   self.rules_count,
            'bundles_count': self.bundles_count,
            'ping_count':    self.ping_count,
            'first_seen':    self.first_seen.strftime('%Y-%m-%d %H:%M'),
            'last_seen':     self.last_seen.strftime('%Y-%m-%d %H:%M'),
        }


class RemotePullLog(db.Model):
    """One row per pull session initiated by a remote instance against this instance's sync API.
    Logged when a remote connector fetches page 1 of /api/sync/rules."""
    __tablename__ = 'remote_pull_log'
    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    instance_uuid = db.Column(db.String(36),  nullable=True, index=True)
    instance_url  = db.Column(db.String(512), nullable=True)
    ip_address    = db.Column(db.String(64),  nullable=True)
    rules_total   = db.Column(db.Integer,     nullable=True)
    created_at    = db.Column(db.DateTime,    nullable=False,
                              default=datetime.datetime.utcnow, index=True)

    def to_json(self):
        return {
            'id':            self.id,
            'instance_uuid': self.instance_uuid,
            'instance_url':  self.instance_url,
            'ip_address':    self.ip_address,
            'rules_total':   self.rules_total,
            'created_at':    self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        }


########################################
#   User Follow                        #
########################################

class UserFollow(db.Model):
    """One row per follower → followed relationship."""
    __tablename__ = 'user_follow'
    __table_args__ = (db.UniqueConstraint('follower_id', 'followed_id', name='uq_user_follow'),)

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'),
                            nullable=False, index=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'),
                            nullable=False, index=True)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)

    follower = db.relationship('User', foreign_keys=[follower_id],
                               backref=db.backref('following', lazy='dynamic', cascade='all, delete-orphan'))
    followed = db.relationship('User', foreign_keys=[followed_id],
                               backref=db.backref('followers', lazy='dynamic', cascade='all, delete-orphan'))


########################################
#   Notification                       #
########################################

class Notification(db.Model):
    """
    Persistent notification for a user.

    Types:
      new_rule          — a followed user created a new rule
      rule_update_found — GitHub update scan found pending updates
      job_created       — a background job was queued (linked to job_uuid)
      job_finished      — same job completed (updates the existing row)
    """
    __tablename__ = 'notification'

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'),
                            nullable=False, index=True)

    # Discriminator
    notif_type  = db.Column(db.String(32), nullable=False, index=True)

    # Display
    title       = db.Column(db.String(255), nullable=False)
    body        = db.Column(db.String(500), nullable=True)
    link        = db.Column(db.String(512), nullable=True)
    icon        = db.Column(db.String(64),  nullable=True)   # FA class e.g. 'fa-solid fa-shield-halved'

    # Job tracking — only for job_created / job_finished
    job_uuid    = db.Column(db.String(36),  nullable=True, index=True)
    job_status  = db.Column(db.String(16),  nullable=True)   # mirrors BackgroundJob.status
    job_progress = db.Column(db.Integer,    nullable=True)   # 0-100

    # State
    is_read     = db.Column(db.Boolean, nullable=False, default=False, index=True)
    created_at  = db.Column(db.DateTime, nullable=False,
                            default=datetime.datetime.utcnow, index=True)
    read_at     = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', backref=db.backref('notifications', lazy='dynamic',
                                                      cascade='all, delete-orphan'))

    def is_job_active(self):
        return self.notif_type in ('job_created', 'job_finished') and \
               self.job_status not in ('done', 'failed', 'cancelled')

    def to_json(self):
        return {
            'id':           self.id,
            'notif_type':   self.notif_type,
            'title':        self.title,
            'body':         self.body,
            'link':         self.link,
            'icon':         self.icon,
            'job_uuid':     self.job_uuid,
            'job_status':   self.job_status,
            'job_progress': self.job_progress,
            'is_read':      self.is_read,
            'is_job_active': self.is_job_active(),
            'created_at':   self.created_at.strftime('%Y-%m-%dT%H:%M:%SZ'),
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Unified comment system
# ─────────────────────────────────────────────────────────────────────────────

import uuid as _uuid_mod


def _gen_comment_uuid():
    return str(_uuid_mod.uuid4())


class UnifiedComment(db.Model):
    """Single polymorphic comment table for rules, bundles, and edit proposals."""
    __tablename__ = 'comment_v2'

    id               = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid             = db.Column(db.String(36), unique=True, nullable=False, index=True, default=_gen_comment_uuid)
    content          = db.Column(db.Text, nullable=False)
    content_original = db.Column(db.Text, nullable=True)

    # Thread structure
    parent_id = db.Column(db.Integer, db.ForeignKey('comment_v2.id', ondelete='SET NULL'), nullable=True, index=True)
    depth     = db.Column(db.Integer, default=0, nullable=False)
    root_id   = db.Column(db.Integer, nullable=True, index=True)

    # Polymorphic target — object_type: 'rule' | 'bundle' | 'proposal'
    object_type = db.Column(db.String(64), nullable=False, index=True)
    object_id   = db.Column(db.Integer,    nullable=False, index=True)

    is_public   = db.Column(db.Boolean, default=True,  nullable=False)
    is_active   = db.Column(db.Boolean, default=True,  nullable=False)
    deleted_at  = db.Column(db.DateTime, nullable=True)
    deleted_by  = db.Column(db.Integer, nullable=True)

    # Set when an admin turns this comment into an issue on the official
    # rulezet-core GitHub repo — keeps the button from filing duplicates.
    github_issue_url    = db.Column(db.String(500), nullable=True)
    github_issue_number = db.Column(db.Integer, nullable=True)

    created_at  = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    updated_at  = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), onupdate=lambda: datetime.datetime.now(datetime.timezone.utc))
    created_by  = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True, index=True)

    author = db.relationship(
        'User',
        foreign_keys=[created_by],
        lazy='joined',
        primaryjoin='UnifiedComment.created_by == User.id',
    )
    reactions = db.relationship(
        'UnifiedCommentReaction',
        backref='comment',
        lazy='dynamic',
        cascade='all, delete-orphan',
    )
    replies = db.relationship(
        'UnifiedComment',
        backref=db.backref('parent_comment', remote_side='UnifiedComment.id'),
        lazy='dynamic',
        foreign_keys=[parent_id],
        cascade='all, delete-orphan',
    )

    @property
    def reply_count(self):
        return UnifiedComment.query.filter_by(parent_id=self.id, is_active=True).count()

    @property
    def like_count(self):
        return self.reactions.filter_by(reaction='like').count()

    @property
    def dislike_count(self):
        return self.reactions.filter_by(reaction='dislike').count()

    def to_json(self, current_user_id=None, counts=None):
        """counts: optional {'reply_count', 'like_count', 'dislike_count', 'user_reaction'}
        pre-computed by the caller (see comment_api.py's _batch_comment_counts) to avoid
        the 3-4 extra per-instance queries below when serializing a whole page of comments.
        Falls back to the lazy per-instance computation when not provided."""
        author = self.author
        if author:
            initials = ''
            if author.first_name:
                initials += author.first_name[0].upper()
            if author.last_name:
                initials += author.last_name[0].upper()
            author_dict = {
                'id':       author.id,
                'name':     author.get_username(),
                'avatar':   author.profile_picture,
                'initials': initials or '?',
                'handle':   author.username,
            }
        else:
            author_dict = {'id': None, 'name': 'Deleted user', 'avatar': None, 'initials': '?', 'handle': None}

        if counts is not None:
            reply_count   = counts.get('reply_count', 0)
            like_count    = counts.get('like_count', 0)
            dislike_count = counts.get('dislike_count', 0)
            user_reaction = counts.get('user_reaction')
        else:
            reply_count   = self.reply_count
            like_count    = self.like_count
            dislike_count = self.dislike_count
            user_reaction = None
            if current_user_id:
                rxn = self.reactions.filter_by(user_id=current_user_id).first()
                if rxn:
                    user_reaction = rxn.reaction

        return {
            'id':            self.id,
            'uuid':          self.uuid,
            'content':       self.content if self.is_active else '[deleted]',
            'parent_id':     self.parent_id,
            'depth':         self.depth,
            'root_id':       self.root_id,
            'object_type':   self.object_type,
            'object_id':     self.object_id,
            'is_public':     self.is_public,
            'created_at':    self.created_at.isoformat() if self.created_at else None,
            'updated_at':    self.updated_at.isoformat() if self.updated_at else None,
            'created_by':    self.created_by,
            'is_active':     self.is_active,
            'is_deleted':    not self.is_active,
            'deleted_at':    self.deleted_at.isoformat() if self.deleted_at else None,
            'reply_count':   reply_count,
            'like_count':    like_count,
            'dislike_count': dislike_count,
            'user_reaction': user_reaction,
            'author':        author_dict,
            'is_admin':      author.is_admin() if author else False,
            'github_issue_url':    self.github_issue_url,
            'github_issue_number': self.github_issue_number,
        }


class UnifiedCommentReaction(db.Model):
    __tablename__ = 'comment_reaction'
    __table_args__ = (
        db.UniqueConstraint('comment_id', 'user_id', name='uq_comment_reaction_user'),
    )

    id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment_v2.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id',       ondelete='CASCADE'), nullable=False, index=True)
    reaction   = db.Column(db.String(16), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    user = db.relationship('User', backref=db.backref('unified_comment_reactions', lazy='dynamic'))


# ─────────────────────────────────────────────────────────────────────────────
#  User Config & Custom Themes
# ─────────────────────────────────────────────────────────────────────────────

import uuid as _uuid_mod
import re as _re


def _gen_uuid():
    return str(_uuid_mod.uuid4())


def _slugify(name):
    s = name.lower().strip()
    s = _re.sub(r'[^a-z0-9]+', '-', s)
    return s.strip('-')[:48]


THEME_CHOICES = ('system', 'light', 'dark')


class UserConfig(db.Model):
    __tablename__ = 'user_config'

    id         = db.Column(db.Integer, primary_key=True)
    uuid       = db.Column(db.String(36), unique=True, nullable=False, default=_gen_uuid)

    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    is_active  = db.Column(db.Boolean, default=True)
    deleted_at = db.Column(db.DateTime, nullable=True)
    meta       = db.Column(db.JSON, nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    theme   = db.Column(db.String(64), default='system')

    def to_json(self):
        return {
            'id':      self.id,
            'uuid':    self.uuid,
            'user_id': self.user_id,
            'theme':   self.theme,
        }


class NotificationPreference(db.Model):
    """Per-user opt-in/out for each notification category."""
    __tablename__ = 'notification_preference'

    id      = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'),
                        nullable=False, unique=True, index=True)

    # Follow-based (someone I follow does something)
    pref_follow_new_rule    = db.Column(db.Boolean, nullable=False, default=True)
    pref_follow_new_bundle  = db.Column(db.Boolean, nullable=False, default=True)
    pref_follow_new_comment = db.Column(db.Boolean, nullable=False, default=False)

    # Ownership-based (someone interacts with my content)
    pref_rule_comment   = db.Column(db.Boolean, nullable=False, default=True)
    pref_bundle_comment = db.Column(db.Boolean, nullable=False, default=True)

    # System
    pref_job_done  = db.Column(db.Boolean, nullable=False, default=True)
    pref_proposal  = db.Column(db.Boolean, nullable=False, default=True)

    # Proposals & replies
    pref_proposal_comment  = db.Column(db.Boolean, nullable=False, default=True)
    pref_proposal_accepted = db.Column(db.Boolean, nullable=False, default=True)
    pref_comment_reply     = db.Column(db.Boolean, nullable=False, default=True)

    # Platform content
    pref_blog_published = db.Column(db.Boolean, nullable=False, default=True)

    user = db.relationship('User', backref=db.backref(
        'notification_preference', uselist=False, cascade='all, delete-orphan'))

    def to_json(self):
        return {
            'follow_new_rule':    self.pref_follow_new_rule,
            'follow_new_bundle':  self.pref_follow_new_bundle,
            'follow_new_comment': self.pref_follow_new_comment,
            'rule_comment':       self.pref_rule_comment,
            'bundle_comment':     self.pref_bundle_comment,
            'job_done':           self.pref_job_done,
            'proposal':           self.pref_proposal,
            'proposal_comment':   self.pref_proposal_comment,
            'proposal_accepted':  self.pref_proposal_accepted,
            'comment_reply':      self.pref_comment_reply,
            'blog_published':     self.pref_blog_published,
        }


class CustomTheme(db.Model):
    __tablename__ = 'custom_theme'

    id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid       = db.Column(db.String(36), unique=True, nullable=False, default=_gen_uuid)
    name       = db.Column(db.String(64), nullable=False)
    css_key    = db.Column(db.String(64), unique=True, nullable=False)
    icon       = db.Column(db.String(64), nullable=False, default='fa-palette')
    is_dark    = db.Column(db.Boolean, default=False, nullable=False)
    is_builtin = db.Column(db.Boolean, default=False, nullable=False)
    is_public  = db.Column(db.Boolean, default=False, nullable=False)
    css_vars   = db.Column(db.JSON, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    is_active  = db.Column(db.Boolean, default=True, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by = db.Column(db.Integer, nullable=True)
    meta       = db.Column(db.JSON, nullable=True)

    def to_json(self):
        return {
            'id':         self.id,
            'uuid':       self.uuid,
            'name':       self.name,
            'css_key':    self.css_key,
            'icon':       self.icon,
            'is_dark':    self.is_dark,
            'is_builtin': self.is_builtin,
            'css_vars':   self.css_vars or {},
            'is_public':  self.is_public,
            'is_active':  self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  MITRE ATT&CK
# ─────────────────────────────────────────────────────────────────────────────

class AttackTechnique(db.Model):
    __tablename__ = 'attack_technique'

    id                  = db.Column(db.Integer, primary_key=True, autoincrement=True)
    technique_id        = db.Column(db.String(20), unique=True, nullable=False, index=True)  # T1059 / T1059.001
    name                = db.Column(db.String(300), nullable=False)
    tactic_keys         = db.Column(db.JSON, nullable=True)   # ["execution", "defense-evasion"]
    description         = db.Column(db.Text, nullable=True)
    url                 = db.Column(db.String(500), nullable=True)
    is_subtechnique     = db.Column(db.Boolean, default=False)
    parent_technique_id = db.Column(db.String(20), nullable=True)   # T1059 for T1059.001
    deprecated          = db.Column(db.Boolean, default=False)
    updated_at          = db.Column(db.DateTime, nullable=True)

    def to_json(self):
        return {
            'id':                  self.id,
            'technique_id':        self.technique_id,
            'name':                self.name,
            'tactic_keys':         self.tactic_keys or [],
            'description':         self.description,
            'url':                 self.url,
            'is_subtechnique':     self.is_subtechnique,
            'parent_technique_id': self.parent_technique_id,
            'deprecated':          self.deprecated,
            'updated_at':          self.updated_at.isoformat() if self.updated_at else None,
        }


class RuleAttackAssociation(db.Model):
    __tablename__ = 'rule_attack_association'

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid        = db.Column(db.String(36), unique=True, nullable=False, index=True)
    rule_id     = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    technique_id = db.Column(db.String(20), db.ForeignKey('attack_technique.technique_id'), nullable=False)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)   # null = auto-parsed
    added_at    = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))
    source      = db.Column(db.String(20), default='manual')   # 'manual' | 'auto'

    rule      = db.relationship('Rule', backref=db.backref('attack_assocs', lazy='dynamic', cascade='all, delete-orphan'))
    technique = db.relationship('AttackTechnique', backref=db.backref('rule_assocs', lazy='dynamic'))
    user      = db.relationship('User', backref=db.backref('user_attack_assocs', lazy='dynamic'))

    __table_args__ = (
        db.UniqueConstraint('rule_id', 'technique_id', name='uq_rule_attack_technique'),
    )

    def to_json(self):
        t = self.technique
        return {
            'id':           self.id,
            'uuid':         self.uuid,
            'rule_id':      self.rule_id,
            'technique_id': self.technique_id,
            'name':         t.name if t else None,
            'tactic_keys':  t.tactic_keys if t else [],
            'url':          t.url if t else None,
            'is_subtechnique': t.is_subtechnique if t else False,
            'parent_technique_id': t.parent_technique_id if t else None,
            'user_id':      self.user_id,
            'added_at':     self.added_at.strftime('%Y-%m-%d %H:%M') if self.added_at else None,
            'source':       self.source,
        }


class FieldParserConfig(db.Model):
    """Saved configurations for the bulk field parser admin tool."""
    __tablename__ = 'field_parser_config'

    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(100), nullable=False)
    config     = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(tz=datetime.timezone.utc))
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)

    user = db.relationship('User', backref=db.backref('field_parser_configs', lazy='dynamic'))

    def to_json(self):
        return {
            'id':         self.id,
            'name':       self.name,
            'config':     self.config,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            'user_id':    self.user_id,
        }



########################################
#   Workspace                          #
########################################

class WorkspaceTagAssociation(db.Model):
    __tablename__ = 'workspace_tag_association'
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id', ondelete='CASCADE'), nullable=False)
    tag_id       = db.Column(db.Integer, db.ForeignKey('tag.id', ondelete='CASCADE'), nullable=False)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at   = db.Column(db.DateTime, default=lambda: datetime.datetime.now(tz=datetime.timezone.utc))
    tag          = db.relationship('Tag', foreign_keys=[tag_id], lazy='joined')
    __table_args__ = (db.UniqueConstraint('workspace_id', 'tag_id'),)


class WorkspaceAttackAssociation(db.Model):
    __tablename__ = 'workspace_attack_association'
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id', ondelete='CASCADE'), nullable=False)
    technique_id = db.Column(db.String(20), db.ForeignKey('attack_technique.technique_id', ondelete='CASCADE'), nullable=False)
    technique    = db.relationship('AttackTechnique', foreign_keys=[technique_id], lazy='joined')
    __table_args__ = (db.UniqueConstraint('workspace_id', 'technique_id'),)


class Workspace(db.Model):
    """Personal rule workspace — grouping owned rules by context."""
    __tablename__ = 'workspace'
    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid        = db.Column(db.String(36), unique=True, nullable=False, index=True)
    name        = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    icon        = db.Column(db.String(50), nullable=False, default='fa-folder')
    color       = db.Column(db.String(20), nullable=False, default='#0d6efd')
    url         = db.Column(db.Text, nullable=True)
    cve_id      = db.Column(db.Text, nullable=True)
    other       = db.Column(db.Text, nullable=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.datetime.now(tz=datetime.timezone.utc))
    updated_at  = db.Column(db.DateTime,
                             default=lambda: datetime.datetime.now(tz=datetime.timezone.utc),
                             onupdate=lambda: datetime.datetime.now(tz=datetime.timezone.utc))

    owner       = db.relationship('User', backref=db.backref('workspaces', lazy='dynamic'))
    rules_assoc = db.relationship('WorkspaceRule', backref='workspace', lazy='dynamic',
                                   cascade='all, delete-orphan')
    tag_assocs  = db.relationship('WorkspaceTagAssociation', backref='workspace',
                                   cascade='all, delete-orphan', foreign_keys='WorkspaceTagAssociation.workspace_id')
    attack_assocs = db.relationship('WorkspaceAttackAssociation', backref='workspace',
                                     cascade='all, delete-orphan', foreign_keys='WorkspaceAttackAssociation.workspace_id')

    def rule_count(self):
        return self.rules_assoc.count()

    @property
    def cves_list(self):
        import json as _json
        return _json.loads(self.cve_id) if self.cve_id else []

    def to_json(self):
        return {
            'id':          self.id,
            'uuid':        self.uuid,
            'name':        self.name,
            'description': self.description,
            'icon':        self.icon,
            'color':       self.color,
            'url':         self.url,
            'cves':        self.cves_list,
            'user_id':     self.user_id,
            'owner_name':  self.owner.get_username() if self.owner else None,
            'rule_count':  self.rule_count(),
            'created_at':  self.created_at.strftime('%Y-%m-%d') if self.created_at else None,
            'updated_at':  self.updated_at.strftime('%Y-%m-%d %H:%M') if self.updated_at else None,
        }


class WorkspaceRule(db.Model):
    """Association table between Workspace and Rule."""
    __tablename__ = 'workspace_rule'
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id', ondelete='CASCADE'), nullable=False)
    rule_id      = db.Column(db.Integer, db.ForeignKey('rule.id',      ondelete='CASCADE'), nullable=False)
    added_at     = db.Column(db.DateTime, default=lambda: datetime.datetime.now(tz=datetime.timezone.utc))
    note         = db.Column(db.Text, nullable=True)
    __table_args__ = (db.UniqueConstraint('workspace_id', 'rule_id'),)

    def to_json(self):
        return {
            'id':           self.id,
            'workspace_id': self.workspace_id,
            'rule_id':      self.rule_id,
            'note':         self.note,
            'added_at':     self.added_at.strftime('%Y-%m-%d %H:%M') if self.added_at else None,
        }


class WorkspaceDocument(db.Model):
    __tablename__ = 'workspace_document'
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id', ondelete='CASCADE'), nullable=False)
    title        = db.Column(db.String(200), nullable=False, default='Untitled')
    content      = db.Column(db.Text, nullable=False, default='')
    created_at   = db.Column(db.DateTime, default=lambda: datetime.datetime.now(tz=datetime.timezone.utc))
    updated_at   = db.Column(db.DateTime, default=lambda: datetime.datetime.now(tz=datetime.timezone.utc),
                              onupdate=lambda: datetime.datetime.now(tz=datetime.timezone.utc))

    def to_json(self):
        return {
            'id':         self.id,
            'title':      self.title,
            'content':    self.content,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M') if self.updated_at else None,
        }


class WorkspaceLink(db.Model):
    __tablename__ = 'workspace_link'
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id', ondelete='CASCADE'), nullable=False)
    title        = db.Column(db.String(200), nullable=False)
    url          = db.Column(db.String(1000), nullable=False)
    description  = db.Column(db.String(500), nullable=True)
    created_at   = db.Column(db.DateTime, default=lambda: datetime.datetime.now(tz=datetime.timezone.utc))

    def to_json(self):
        return {
            'id':          self.id,
            'title':       self.title,
            'url':         self.url,
            'description': self.description,
            'created_at':  self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
        }


##############
#    Blog    #
##############

class BlogPost(db.Model):
    __tablename__ = 'blog_post'
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid         = db.Column(db.String(36), unique=True, nullable=False, index=True)
    slug         = db.Column(db.String(255), unique=True, nullable=False, index=True)
    title        = db.Column(db.String(255), nullable=False)
    excerpt      = db.Column(db.Text, nullable=True)
    content      = db.Column(db.Text, nullable=False, default='')
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True, index=True)
    is_public    = db.Column(db.Boolean, nullable=False, default=False, index=True)
    is_draft     = db.Column(db.Boolean, nullable=False, default=True,  index=True)
    share_key    = db.Column(db.String(64), nullable=True, index=True)
    view_count   = db.Column(db.Integer, nullable=False, default=0)
    cve_ids          = db.Column(db.JSON, nullable=True)
    cover_image_url  = db.Column(db.String(500), nullable=True)
    external_links   = db.Column(db.JSON, nullable=True)
    created_at   = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    updated_at   = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    published_at = db.Column(db.DateTime, nullable=True)

    author  = db.relationship('User', foreign_keys=[user_id], lazy='joined')
    tags    = db.relationship('BlogPostTagAssociation', backref='post', cascade='all, delete-orphan', lazy='joined')
    rules   = db.relationship('BlogPostRuleAssociation', backref='post', cascade='all, delete-orphan', order_by='BlogPostRuleAssociation.position')
    bundles = db.relationship('BlogPostBundleAssociation', backref='post', cascade='all, delete-orphan', order_by='BlogPostBundleAssociation.position')
    files   = db.relationship('BlogPostFile', backref='post', cascade='all, delete-orphan', order_by='BlogPostFile.created_at')
    attacks = db.relationship('BlogPostAttackAssociation', backref='post', cascade='all, delete-orphan')

    def to_json(self):
        return {
            'id':            self.id,
            'uuid':          self.uuid,
            'slug':          self.slug,
            'title':         self.title,
            'excerpt':       self.excerpt,
            'content':       self.content,
            'user_id':       self.user_id,
            'is_public':     self.is_public,
            'is_draft':      self.is_draft,
            'has_share_key':    bool(self.share_key),
            'cover_image_url':  self.cover_image_url,
            'external_links':   self.external_links or [],
            'files':            [f.to_json() for f in self.files],
            'view_count':    self.view_count,
            'cve_ids':       self.cve_ids or [],
            'created_at':    self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            'updated_at':    self.updated_at.strftime('%Y-%m-%d %H:%M') if self.updated_at else None,
            'published_at':  self.published_at.strftime('%Y-%m-%d') if self.published_at else None,
            'author_name':   ((self.author.first_name or '') + ' ' + (self.author.last_name or '')).strip() if self.author else 'Unknown',
            'author_username': self.author.get_username() if self.author else None,
            'author_id':     self.user_id,
            'author_avatar': self.author.get_avatar_url() if self.author else None,
            'tag_names':     [a.tag.name for a in self.tags if a.tag],
            'technique_ids': [a.technique_id for a in self.attacks],
            'rule_ids':      [r.rule_id for r in self.rules],
            'bundle_ids':    [b.bundle_id for b in self.bundles],
        }


class BlogPostTagAssociation(db.Model):
    __tablename__ = 'blog_post_tag'
    id      = db.Column(db.Integer, primary_key=True, autoincrement=True)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id', ondelete='CASCADE'), nullable=False, index=True)
    tag_id  = db.Column(db.Integer, db.ForeignKey('tag.id', ondelete='CASCADE'), nullable=False)
    tag     = db.relationship('Tag', lazy='joined')


class BlogPostRuleAssociation(db.Model):
    __tablename__ = 'blog_post_rule'
    id       = db.Column(db.Integer, primary_key=True, autoincrement=True)
    post_id  = db.Column(db.Integer, db.ForeignKey('blog_post.id', ondelete='CASCADE'), nullable=False, index=True)
    rule_id  = db.Column(db.Integer, db.ForeignKey('rule.id', ondelete='CASCADE'), nullable=False)
    position = db.Column(db.Integer, nullable=False, default=0)


class BlogPostBundleAssociation(db.Model):
    __tablename__ = 'blog_post_bundle'
    id        = db.Column(db.Integer, primary_key=True, autoincrement=True)
    post_id   = db.Column(db.Integer, db.ForeignKey('blog_post.id', ondelete='CASCADE'), nullable=False, index=True)
    bundle_id = db.Column(db.Integer, db.ForeignKey('bundle.id', ondelete='CASCADE'), nullable=False)
    position  = db.Column(db.Integer, nullable=False, default=0)


class BlogPostAttackAssociation(db.Model):
    __tablename__ = 'blog_post_attack'
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    post_id      = db.Column(db.Integer, db.ForeignKey('blog_post.id', ondelete='CASCADE'), nullable=False, index=True)
    technique_id = db.Column(db.String(16), nullable=False)


class BlogPostFile(db.Model):
    __tablename__ = 'blog_post_file'
    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid          = db.Column(db.String(36), unique=True, nullable=False, index=True)
    post_id       = db.Column(db.Integer, db.ForeignKey('blog_post.id', ondelete='CASCADE'), nullable=False, index=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name   = db.Column(db.String(255), nullable=False)
    mime_type     = db.Column(db.String(128), nullable=False)
    size_bytes    = db.Column(db.Integer, nullable=False)
    uploaded_by   = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    created_at    = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    def to_json(self):
        return {
            'id':            self.id,
            'uuid':          self.uuid,
            'original_name': self.original_name,
            'mime_type':     self.mime_type,
            'size_bytes':    self.size_bytes,
            'created_at':    self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            'download_url':  f'/blog/admin/file/{self.uuid}',
        }


########################################
#   Rule Tester                        #
########################################

class RuleTest(db.Model):
    """A single test session: one input tested against one or many rules."""
    __tablename__ = 'rule_test'

    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid         = db.Column(db.String(36), unique=True, nullable=False, index=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)

    # single-rule tests set this; bulk tests leave it null
    rule_id      = db.Column(db.Integer, db.ForeignKey('rule.id', ondelete='SET NULL'),
                             nullable=True, index=True)

    test_type    = db.Column(db.String(16), nullable=False)   # 'single' | 'bulk'
    format       = db.Column(db.String(32), nullable=False)   # yara | sigma | suricata | …

    input_type   = db.Column(db.String(32), nullable=False)   # string | hex | file_b64 | json | http
    input_data   = db.Column(db.Text, nullable=True)
    input_label  = db.Column(db.String(255), nullable=True)

    # Flags the sample under test as a real malicious/dangerous artifact, so
    # anyone viewing this test later is warned before handling it.
    is_dangerous       = db.Column(db.Boolean, nullable=False, default=False, index=True)
    danger_description = db.Column(db.Text, nullable=True)

    bulk_filters = db.Column(db.JSON, nullable=True)

    job_id       = db.Column(db.Integer, db.ForeignKey('background_job.id', ondelete='SET NULL'),
                             nullable=True)

    # pending | running | done | failed
    status       = db.Column(db.String(16), nullable=False, default='pending', index=True)
    matched_count = db.Column(db.Integer, nullable=True)
    total_rules   = db.Column(db.Integer, nullable=True)
    error         = db.Column(db.Text, nullable=True)

    is_public    = db.Column(db.Boolean, nullable=False, default=False, index=True)
    label        = db.Column(db.String(255), nullable=True)
    notes        = db.Column(db.Text, nullable=True)

    created_at   = db.Column(db.DateTime, nullable=False,
                             default=lambda: datetime.datetime.now(datetime.timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)

    user    = db.relationship('User', backref=db.backref('rule_tests', lazy='dynamic'))
    rule    = db.relationship('Rule', backref=db.backref('tests', lazy='dynamic'),
                              foreign_keys=[rule_id])
    job     = db.relationship('BackgroundJob', foreign_keys=[job_id])
    results = db.relationship('RuleTestResult', backref='test', lazy='dynamic',
                              cascade='all, delete-orphan')

    def to_json(self):
        user_obj = User.query.get(self.user_id)
        return {
            'id':            self.id,
            'uuid':          self.uuid,
            'user_id':       self.user_id,
            'user':          {'id': user_obj.id, 'username': user_obj.get_username(),
                              'avatar': user_obj.get_avatar_url()} if user_obj else None,
            'rule_id':       self.rule_id,
            'test_type':     self.test_type,
            'format':        self.format,
            'input_type':    self.input_type,
            'input_label':   self.input_label,
            'is_dangerous':       self.is_dangerous,
            'danger_description': self.danger_description,
            'status':        self.status,
            'matched_count': self.matched_count,
            'total_rules':   self.total_rules,
            'is_public':     self.is_public,
            'label':         self.label,
            'notes':         self.notes,
            'job_uuid':      self.job.uuid if self.job else None,
            'created_at':    self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'completed_at':  self.completed_at.strftime('%Y-%m-%d %H:%M:%S') if self.completed_at else None,
        }

    def to_json_summary(self):
        """Compact representation for list views (no input_data)."""
        return {
            'uuid':          self.uuid,
            'user_id':       self.user_id,
            'rule_id':       self.rule_id,
            'test_type':     self.test_type,
            'format':        self.format,
            'input_type':    self.input_type,
            'input_label':   self.input_label,
            'is_dangerous':  self.is_dangerous,
            'status':        self.status,
            'matched_count': self.matched_count,
            'total_rules':   self.total_rules,
            'is_public':     self.is_public,
            'label':         self.label,
            'created_at':    self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'completed_at':  self.completed_at.strftime('%Y-%m-%d %H:%M:%S') if self.completed_at else None,
        }


class RuleTestResult(db.Model):
    """One rule's outcome inside a RuleTest session."""
    __tablename__ = 'rule_test_result'

    id      = db.Column(db.Integer, primary_key=True, autoincrement=True)
    test_id = db.Column(db.Integer, db.ForeignKey('rule_test.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id', ondelete='SET NULL'),
                        nullable=True, index=True)

    matched           = db.Column(db.Boolean, nullable=False, default=False)
    score             = db.Column(db.Float, nullable=True)
    details           = db.Column(db.JSON, nullable=True)
    quality_hints     = db.Column(db.JSON, nullable=True)
    error             = db.Column(db.Text, nullable=True)
    execution_time_ms = db.Column(db.Integer, nullable=True)

    # snapshot so history stays stable even when rule is edited later
    rule_title  = db.Column(db.String(255), nullable=True)
    rule_uuid   = db.Column(db.String(36), nullable=True)
    rule_format = db.Column(db.String(32), nullable=True)

    rule = db.relationship('Rule', foreign_keys=[rule_id])

    def to_json(self):
        return {
            'id':               self.id,
            'test_id':          self.test_id,
            'rule_id':          self.rule_id,
            'rule_uuid':        self.rule_uuid,
            'rule_title':       self.rule_title,
            'rule_format':      self.rule_format,
            'matched':          self.matched,
            'score':            self.score,
            'details':          self.details,
            'quality_hints':    self.quality_hints,
            'error':            self.error,
            'execution_time_ms': self.execution_time_ms,
        }
