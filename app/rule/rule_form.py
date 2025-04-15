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
    
    format = StringField('Format', validators=[InputRequired()])
    title = StringField('Title', validators=[InputRequired()])
    license = StringField('License', validators=[InputRequired()])
    description = TextAreaField('Description', validators=[InputRequired()])
    source = StringField('Source', validators=[InputRequired()])
    author = StringField('Author', validators=[InputRequired()])
    version = StringField('Version', validators=[InputRequired()])

    def validate_title(self, field):
        if not field.data == Rule.title:
            if Rule.query.filter_by(title=field.data).first():
                raise ValidationError('Rule already registered.')


    submit = SubmitField('Register')



class EditRuleFrom(FlaskForm):
    format = StringField('Format', validators=[InputRequired()])
    title = StringField('Title', validators=[InputRequired()])
    license = StringField('License', validators=[InputRequired()])  
    description = TextAreaField('Description', validators=[InputRequired()])
    source = StringField('Source', validators=[InputRequired()])
    version = StringField('Version', validators=[InputRequired()])

    submit = SubmitField('Register')
    
    
