import datetime
import json

from sqlalchemy import String, TypeDecorator, func
from .. import db, login_manager
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin, AnonymousUserMixin, current_user


#############
#   User    #
#############

@login_manager.user_loader
def load_user(user_id):
    """Loads the user from the session."""
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    """User model for authentication and authorization."""
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(64), index=True)
    last_name = db.Column(db.String(64), index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    admin = db.Column(db.Boolean, default=False, index=True)
    password_hash = db.Column(db.String(165))
    api_key = db.Column(db.String(60), index=True)
    is_connected = db.Column(db.Boolean, default=False, index=True)

    # confirmed = db.Column(db.Boolean, default=False)
    # confirmed_at = db.Column(db.DateTime, nullable=True)

    def is_admin(self):
        """Check if the user has admin privileges."""
        return self.admin
    
    
    def get_first_name(self):
        return self.first_name 

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
            "is_connected": self.is_connected
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

    #taxonomie_misp = db.Column(db) 

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
            "cve_id": self.cve_id,
            "editor": self.get_rule_user_first_name_by_id()
        }
    
    def to_dict(self):
        is_favorited = False
        if not current_user.is_anonymous:
            is_favorited = RuleFavoriteUser.query.filter_by(user_id=current_user.id, rule_id=self.id).first() is not None

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
            "cve_id": self.cve_id
        }  # Format the datetime to a string


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
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_name = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, index=True)
    updated_at = db.Column(db.DateTime, index=True)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)

    # Relations
    user = db.relationship('User', backref=db.backref('comments_user', lazy='dynamic' , cascade='all, delete-orphan'))
    rule = db.relationship('Rule', backref=db.backref('comments_rule', lazy='dynamic', cascade='all, delete-orphan'))

    def to_json(self):
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "user_id": self.user_id,
            "content": self.content,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M'),
            "updated_at": self.updated_at.strftime('%Y-%m-%d %H:%M'),
            "likes": self.likes,
            "user_name": self.user_name,
            "dislikes": self.dislikes
        }


class RequestOwnerRule(db.Model):
    """Model for user-submitted requests visible by admins or rule owners."""
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), index=True)

    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=True)
    rule_source = db.Column(db.String, nullable=True)

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
            "title": self.title,
            "content": self.content,
            "status": self.status,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M'),
            "updated_at": self.updated_at.strftime('%Y-%m-%d %H:%M'),
            "rule_id": self.rule_id,
            "rule_source": self.rule_source,
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
            "license": self.license
        }
    


class RuleEditProposal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # the user who made the request
    proposed_content = db.Column(db.Text, nullable=False)
    old_content = db.Column(db.String)
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))
    status = db.Column(db.String, default="pending")

    rule = db.relationship('Rule', backref=db.backref('edit_proposals', lazy='dynamic',  cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('proposed_edits', lazy='dynamic', cascade='all, delete-orphan'))

    def get_rule_title(self):
        rule = Rule.query.get(self.rule_id)  
        return rule.title if rule else None


    def to_json(self):
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'rule_name': self.get_rule_title(),
            'user_id': self.user_id,
            'user_name': self.user.first_name if self.user else None,
            'proposed_content': self.proposed_content,
            'old_content': self.old_content,
            'message': self.message,
            'status': self.status,
            'timestamp': self.timestamp.isoformat(),      #2021-07-27#16:01:12.090202        DateTime_in_ISOFormat.isoformat("#", "auto")
            'comments': [comment.to_json() for comment in self.comments.order_by(RuleEditComment.created_at.asc())]  # take all the message which was concerne by this pull request with date order
        }
    def to_dict(self):
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'rule_name': self.get_rule_title(),
            'user_id': self.user_id,
            'user_name': self.user.first_name if self.user else None,
            'proposed_content': self.proposed_content,
            'old_content': self.old_content,
            'message': self.message,
            'status': self.status,
            'timestamp': self.timestamp.isoformat(),      #2021-07-27#16:01:12.090202        DateTime_in_ISOFormat.isoformat("#", "auto")
            'comments': [comment.to_json() for comment in self.comments.order_by(RuleEditComment.created_at.asc())]  # take all the message which was concerne by this pull request with date order
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
            'created_at': self.created_at.isoformat()
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
                "message": self.message,
                'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
                "reason": self.reason,
                "content": self.rule.to_string if self.rule else None
            }
    




class RuleUpdateHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, nullable=False)
    rule_title = db.Column(db.String(255), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    message = db.Column(db.Text, nullable=True)
    new_content = db.Column(db.Text, nullable=True)
    old_content = db.Column(db.Text, nullable=True)
    analyzed_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    analyzed_at = db.Column(db.DateTime, index=True)

    analyzed_by = db.relationship("User", backref=db.backref("rule_updates", lazy='dynamic', cascade='all, delete-orphan'))

    def get_rule_format(self):
        """
        Returns the format of the rule with rule_id
        """
        rule = Rule.query.get(self.rule_id)
        if rule:
            return rule.format
        return None
    def to_dict(self):
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
        }
    
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
            "rule_format": self.get_rule_format()
        }

#############
#   Bundle  #
#############

class Bundle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))
    updated_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vote_up = db.Column(db.Integer, nullable=False, default=0)
    vote_down = db.Column(db.Integer, nullable=False, default=0)
    access = db.Column(db.Boolean, nullable=False, default=True) # if true all user can see the bundle, if false only the creator can see it



    user = db.relationship('User', backref=db.backref('user who create bundle', lazy='dynamic', cascade='all, delete-orphan'))

    def get_username_by_id(self):
        user = User.query.get(self.user_id)  
        return user.first_name if user else None
    def get_rule_user_first_name_by_id(self):
        user = User.query.get(self.user_id)  
        return user.first_name + " " + user.last_name if user else None

    def to_json(self):
        return {
            "id": self.id,
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
            "number_of_rules": len(self.rules_assoc.all())
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

class AutoUpdateSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text , nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hour = db.Column(db.Integer, nullable=False)
    minute = db.Column(db.Integer, nullable=False)
    #days = db.Column(db.ARRAY(db.String), nullable=False)  # exemple: ["monday", "wednesday"]
    days = db.Column(JSONEncodedList, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc))
    active = db.Column(db.Boolean, default=True)

    user = db.relationship(
        'User',
        backref=db.backref('auto_update_schedules', lazy='dynamic', cascade='all, delete-orphan')
    )

    rules = db.relationship(
        'Rule',
        secondary='auto_update_schedule_rule_association',
        lazy='dynamic',
        backref=db.backref('linked_auto_updates', lazy='dynamic', overlaps="auto_update_links,rule"),
        overlaps="auto_update_links,rule"
    )

    def to_json(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'hour': self.hour,
            'minute': self.minute,
            'days': self.days,
            "name": self.name,
            "description": self.description,
            'created_at': self.created_at.isoformat(),
            'active': self.active,
            'rules': [
                {'id': rule.id, 'title': rule.title} for rule in self.rules.all()
            ]
        }

class AutoUpdateScheduleRuleAssociation(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    schedule_id = db.Column(db.Integer, db.ForeignKey('auto_update_schedule.id'), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)

    rule = db.relationship(
        'Rule',
        backref=db.backref('auto_update_links', lazy='dynamic', cascade='all, delete-orphan', overlaps="linked_auto_updates,rules"),
        overlaps="linked_auto_updates,rules"
    )

    def to_json(self):
        return {
            'id': self.id,
            'schedule_id': self.schedule_id,
            'rule_id': self.rule_id,
            'rule_title': self.rule.title if self.rule else None,
            'rule_format': self.rule.format if self.rule else None,
            'rule_source': self.rule.source if self.rule else None
        }
    

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
          return {
            "id": self.id,
            "uuid": self.uuid,
            "user_id": self.user_id,
            "mode": self.mode,
            "info": json.loads(self.info) if self.info else None,
            "repo_sources": json.loads(self.repo_sources) if self.repo_sources else None,
            "rule_name_by_rule_mode": self._get_rule_name_by_mode(),
            "not_found": self.not_found,
            "found": self.found,
            "updated": self.updated,
            "skipped": self.skipped,
            "total": self.total,
            "thread_count": self.thread_count,
            "query_date": self.query_date.strftime('%Y-%m-%d %H:%M') if self.query_date else None,
            "new_rules": len(self.new_rules) if self.new_rules else 0
        }
    

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
    def get_format(self):
        """Return the format of the rule associated with this RuleStatus."""
        if not self.rule_id:
            return None

        rule = Rule.query.get(self.rule_id)
        return rule.format if rule else None

         

    def to_json(self):
        return {
            "id": self.id,
            "uuid": self.uuid,
            "update_result_id": self.update_result_id,
            "date": self.date.strftime('%Y-%m-%d %H:%M') if self.date else None,
            "name_rule": self.name_rule,
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
        }
