from flask_wtf import FlaskForm
from wtforms import  BooleanField, IntegerField, SelectMultipleField, ValidationError, SelectField
from wtforms.fields import StringField, SubmitField, TextAreaField
from wtforms.validators import  InputRequired, DataRequired, NumberRange


from app.utils.utils import detect_cve

from . import rule_core as RuleModel
from ..db_class.db import Rule

class AddNewRuleForm(FlaskForm):
    format = SelectField('Format', choices=[], validators=[InputRequired()])
    # autres champs ...
    title = StringField('Title', validators=[InputRequired()])
    license = SelectField('License', choices=[], validators=[DataRequired()])
    description = TextAreaField('Description')
    source = StringField('Source')
    version = StringField('Version', validators=[InputRequired()])
    to_string = TextAreaField('Content rule', validators=[InputRequired()])
    cve_id = StringField('CVE vulnerability')
    submit = SubmitField('Register')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        formats_rules_list = RuleModel.get_all_rule_format()
        self.format.choices = [(f.name, f.name) for f in formats_rules_list]

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
    format = SelectField('Format', choices=[], validators=[InputRequired()])
    license = SelectField('License', choices=[], validators=[InputRequired()])
    description = TextAreaField('Description')
    source = StringField('Source')
    version = StringField('Version', validators=[InputRequired()])
    to_string = TextAreaField('Content rule', validators=[InputRequired()])
    cve_id = StringField('CVE vulnerability')
    submit = SubmitField('Register')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        formats_rules_list = RuleModel.get_all_rule_format()
        self.format.choices = [(f.name, f.name) for f in formats_rules_list]

    
    

class EditScheduleForm(FlaskForm):
    """Form to edit an existing schedule"""

    name = StringField('Name', validators=[InputRequired()])
    description = TextAreaField('Description')

    hour = IntegerField('Hour', validators=[
        InputRequired(),
        NumberRange(min=0, max=23, message="Hour must be between 0 and 23")
    ])

    minute = IntegerField('Minute', validators=[
        InputRequired(),
        NumberRange(min=0, max=59, message="Minute must be between 0 and 59")
    ])

    days = SelectMultipleField(
        'Days',
        choices=[
            ('monday', 'Monday'),
            ('tuesday', 'Tuesday'),
            ('wednesday', 'Wednesday'),
            ('thursday', 'Thursday'),
            ('friday', 'Friday'),
            ('saturday', 'Saturday'),
            ('sunday', 'Sunday')
        ],
        validators=[InputRequired()]
    )

    active = BooleanField('Active')
    submit = SubmitField('Save')