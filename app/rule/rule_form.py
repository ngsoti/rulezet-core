from flask_wtf import FlaskForm
from wtforms import  ValidationError, SelectField
from wtforms.fields import StringField, SubmitField, TextAreaField
from wtforms.validators import  InputRequired, DataRequired
from ..db_class.db import Rule

class AddNewRuleForm(FlaskForm):
    """Form to add a new rule"""
    format = SelectField('Format',choices=[('yara', 'YARA rule'), ('sigma', 'SIGMA rule'),  ('zeek', 'ZEEK rule')],validators=[InputRequired()])
    title = StringField('Title', validators=[InputRequired()])
    license = SelectField("License", choices=[], validators=[DataRequired()])
    description = TextAreaField('Description')
    source = StringField('Source')
    version = StringField('Version', validators=[InputRequired()])
    to_string = TextAreaField('Content rule', validators=[InputRequired()])

    def validate_title(self, field):
        if not field.data == Rule.title:
            if Rule.query.filter_by(title=field.data).first():
                raise ValidationError('Rule already registered.')

    submit = SubmitField('Register')

class EditRuleForm(FlaskForm):
    """Form to edit an existing rule"""
    title = StringField('Title', validators=[InputRequired()])
    format = SelectField('Format',choices=[('yara', 'YARA rule'), ('sigma', 'SIGMA rule'), ('zeek', 'ZEEK rule')],validators=[InputRequired()])
    
    license = SelectField('License', choices=[], validators=[InputRequired()])
    description = TextAreaField('Description')
    source = StringField('Source')
    version = StringField('Version', validators=[InputRequired()])
    to_string = TextAreaField('Content rule', validators=[InputRequired()])

    submit = SubmitField('Register')
    
    
