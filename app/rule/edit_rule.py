
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, ValidationError
from wtforms import  ValidationError
from app.db_class.db import Rule
from wtforms.validators import InputRequired, Length


class EditRuleFrom(FlaskForm):
    format = StringField('Format', validators=[InputRequired()])
    title = StringField('Title', validators=[InputRequired()])
    license = StringField('License', validators=[InputRequired()])  
    description = TextAreaField('Description', validators=[InputRequired()])
    source = StringField('Source', validators=[InputRequired()])
    version = StringField('Version', validators=[InputRequired()])

    submit = SubmitField('Register')
    
    


