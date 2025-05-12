import datetime

from .. import db, login_manager
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin, AnonymousUserMixin, current_user

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
    password_hash = db.Column(db.String(128))
    api_key = db.Column(db.String(60), index=True)

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

    def to_json(self):
        """Serialize the user object to JSON."""
        return {
            "id": self.id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "admin": self.admin
        }

class AnonymousUser(AnonymousUserMixin):
    """Defines behavior for anonymous users (not logged in)."""
    
    def is_admin(self):
        return False

    def is_read_only(self):
        return True

# Register AnonymousUser as the default for anonymous visitors
login_manager.anonymous_user = AnonymousUser


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
    source = db.Column(db.String)
    author = db.Column(db.String) # the reel author of the rule
    creation_date = db.Column(db.DateTime, index=True)
    last_modif = db.Column(db.DateTime, index=True)
    vote_up = db.Column(db.Integer)
    vote_down = db.Column(db.Integer)
    to_string = db.Column(db.String)

    #edit
    def get_rule_user_first_name_by_id(self):
        user = User.query.get(self.user_id)  
        return user.first_name if user else None


    def to_json(self):
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
            "source": self.source,
            "author": self.author,
            "creation_date": self.creation_date.strftime('%Y-%m-%d %H:%M'),
            "last_modif": self.last_modif.strftime('%Y-%m-%d %H:%M'),
            "vote_up": self.vote_up,
            "vote_down": self.vote_down,
            "user_id": self.user_id,
            "version": self.version,
            "to_string": self.to_string,
            "is_favorited": is_favorited
        }

class RuleFavoriteUser(db.Model):
    """Association table for User and Rule favorites."""
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime)

    # Define the relationships with cascade option
    user = db.relationship('User', backref=db.backref('favorites', lazy='dynamic' , cascade='all, delete-orphan'))
    rule = db.relationship('Rule', backref=db.backref('favorited_by', lazy='dynamic', cascade='all, delete-orphan'))

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
    user = db.relationship('User', backref=db.backref('comments', lazy='dynamic' , cascade='all, delete-orphan'))
    rule = db.relationship('Rule', backref=db.backref('comments', lazy='dynamic', cascade='all, delete-orphan'))

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
    """Model for user-submitted requests visible by admins."""

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    user_id_owner_rule = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    title = db.Column(db.String(128), nullable=False)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(32), default="pending")  # Ex: pending, reviewed, closed
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=datetime.timezone.utc), onupdate=datetime.datetime.now(tz=datetime.timezone.utc), index=True)

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('requests', lazy='dynamic',  cascade='all, delete-orphan'))
    user_owner_rule = db.relationship('User', foreign_keys=[user_id_owner_rule], backref=db.backref('owned_requests', lazy='dynamic' , cascade='all, delete-orphan'))

    rule = db.relationship('Rule', backref=db.backref('requests', lazy='dynamic', cascade='all, delete-orphan'))

    def to_json(self):
        """Serialize the request to JSON."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "content": self.content,
            "status": self.status,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M'),
            "updated_at": self.updated_at.strftime('%Y-%m-%d %H:%M'),
            "rule_id": self.rule_id,
            "user_id_owner_rule": self.user_id_owner_rule
        }



class RuleEditProposal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
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
            'old_content': self.old_content,
            'user_id': self.user_id,
            'proposed_content': self.proposed_content,
            'message': self.message,
            "status": self.status,
            'timestamp': self.timestamp.isoformat(),
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