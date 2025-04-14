from flask import url_for, flash
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import  ValidationError
from wtforms.fields import (
    BooleanField,
    PasswordField,
    StringField,
    SubmitField,
    TextAreaField,
    EmailField
)
from wtforms.validators import Email, InputRequired, Length

from ..db_class.db import Rule

class AddNewRuleForm(FlaskForm):
    
    format = StringField('Format', validators=[InputRequired(), Length(1, 64)])
    title = StringField('Title', validators=[InputRequired(), Length(1, 64)])
    license = StringField('License', validators=[InputRequired(), Length(1, 64)])
    description = TextAreaField('Description', validators=[InputRequired(), Length(1, 64)])
    source = StringField('Source', validators=[InputRequired(), Length(1, 64)])
    author = StringField('Author', validators=[InputRequired(), Length(1, 64)])
    version = StringField('Version', validators=[InputRequired(), Length(1, 64)])

    def validate_title(self, field):
        if not field.data == Rule.title:
            if Rule.query.filter_by(title=field.data).first():
                raise ValidationError('Rule already registered.')


    submit = SubmitField('Register')