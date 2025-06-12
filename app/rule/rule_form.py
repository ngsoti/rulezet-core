from flask_wtf import FlaskForm
from wtforms import  ValidationError, SelectField
from wtforms.fields import StringField, SubmitField, TextAreaField
from wtforms.validators import  InputRequired, DataRequired

from app.utils.utils import detect_cve
from ..db_class.db import Rule

class AddNewRuleForm(FlaskForm):
    """Form to add a new rule"""

    format = SelectField(
        'Format',
        choices=[('yara', 'Yara'), ('sigma', 'Sigma'), ('zeek', 'Zeek'), ('suricata', 'Suricata')],
        validators=[InputRequired()]
    )

    title = StringField('Title', validators=[InputRequired()])
    license = SelectField('License', choices=[], validators=[DataRequired()])
    description = TextAreaField('Description')
    source = StringField('Source')
    version = StringField('Version', validators=[InputRequired()])
    to_string = TextAreaField('Content rule', validators=[InputRequired()])
    cve_id = StringField('CVE vulnerability')

    submit = SubmitField('Register')

    def validate_title(self, field):
        if Rule.query.filter_by(title=field.data).first():
            raise ValidationError('Rule already registered.')

    def validate_cve_id(self, field):
        if field.data:
            valid, matches = detect_cve(field.data)
            if not valid:
                raise ValidationError('CVE ID not recognized or invalid format.')
            

class EditRuleForm(FlaskForm):
    """Form to edit an existing rule"""
    title = StringField('Title', validators=[InputRequired()])
    format = SelectField('Format',choices=[('yara', 'Yara'), ('sigma', 'Sigma'), ('zeek', 'Zeek'), ('suricata', 'Suricata')],validators=[InputRequired()])
    
    license = SelectField('License', choices=[], validators=[InputRequired()])
    description = TextAreaField('Description')
    source = StringField('Source')
    version = StringField('Version', validators=[InputRequired()])
    to_string = TextAreaField('Content rule', validators=[InputRequired()])
    cve_id = StringField('CVE vulnerability')


    submit = SubmitField('Register')
    
    
