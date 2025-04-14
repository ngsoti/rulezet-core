
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, ValidationError
from wtforms import  ValidationError
from app.db_class.db import Rule
from wtforms.validators import InputRequired, Length


class EditRuleFrom(FlaskForm):
    format = StringField('Format', validators=[InputRequired(), Length(1, 64)])
    title = StringField('Title', validators=[InputRequired(), Length(1, 64)])
    license = StringField('License', validators=[InputRequired(), Length(1, 64)])
    description = TextAreaField('Description', validators=[InputRequired(), Length(1, 64)])
    source = StringField('Source', validators=[InputRequired(), Length(1, 64)])
    version = StringField('Version', validators=[InputRequired(), Length(1, 64)])

    submit = SubmitField('Register')
    
    


