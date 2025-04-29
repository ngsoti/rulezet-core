from flask import url_for, flash
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import  ValidationError, SelectField
from wtforms.fields import (
    BooleanField,
    PasswordField,
    StringField,
    SubmitField,
    TextAreaField,
    EmailField
)
from wtforms.validators import Email, InputRequired, DataRequired

from ..db_class.db import Rule

class AddNewRuleForm(FlaskForm):
    
    format = StringField('Format', validators=[InputRequired()])
    title = StringField('Title', validators=[InputRequired()])
    license = SelectField("License", choices=[], validators=[DataRequired()])
    description = TextAreaField('Description')
    source = StringField('Source')
    #author = current_user.get_first_name()  StringField('Author', validators=[InputRequired()])
    version = StringField('Version', validators=[InputRequired()])
    to_string = TextAreaField('Content rule', validators=[InputRequired()])

    def validate_title(self, field):
        if not field.data == Rule.title:
            if Rule.query.filter_by(title=field.data).first():
                raise ValidationError('Rule already registered.')


    submit = SubmitField('Register')



class EditRuleForm(FlaskForm):
    format = StringField('Format', validators=[InputRequired()])
    title = StringField('Title', validators=[InputRequired()])
    license = SelectField('License', choices=[], validators=[InputRequired()])
    description = TextAreaField('Description')
    source = StringField('Source')
    version = StringField('Version', validators=[InputRequired()])
    to_string = TextAreaField('Content rule', validators=[InputRequired()])

    submit = SubmitField('Register')
    
    
