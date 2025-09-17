from flask import url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import  BooleanField, IntegerField, SelectMultipleField, ValidationError, SelectField
from wtforms.fields import StringField, SubmitField, TextAreaField
from wtforms.validators import  InputRequired, DataRequired, NumberRange


from app.utils.utils import detect_cve

from . import rule_core as RuleModel
from ..db_class.db import FormatRule, Rule

class AddNewRuleForm(FlaskForm):
    format = SelectField('Format', choices=[], validators=[InputRequired()])
    # autres champs ...
    original_uuid =  StringField('Original_uuid')
    title = StringField('Title', validators=[InputRequired()])
    license = SelectField('License', choices=[], validators=[DataRequired()])
    description = TextAreaField('Description')
    source = StringField('Source')
    version = StringField('Version')
    to_string = TextAreaField('Content rule', validators=[InputRequired()])
    cve_id = StringField('CVE vulnerability')
    submit = SubmitField('Register')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        formats_rules_list = RuleModel.get_all_rule_format()
        self.format.choices = [(f.name, f.name) for f in formats_rules_list]

    def validate_title(self, field):
        existing_rule = Rule.query.filter_by(title=field.data).first()
        if existing_rule:
            if current_user.id == existing_rule.user_id or current_user.is_admin():
                # raise ValidationError('Rule already registered.')
                edit_url = url_for("rule.edit_rule", rule_id=existing_rule.id)
                raise ValidationError(
                    f'Rule already registered. '
                    f'Do you want to <a href="{edit_url}">edit this rule (ID: {existing_rule.title})</a> instead?'
                )
            else:
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
    original_uuid =  StringField('Original_uuid')
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



class CreateFormatRuleForm(FlaskForm):
    """Form to create a new rule format"""

    name = StringField('Format Name', validators=[InputRequired()])
    can_be_execute = BooleanField('Can be executed')  # checkbox
    submit = SubmitField('Create')

    def validate_name(self, field):
        if FormatRule.query.filter_by(name=field.data).first():
            raise ValidationError('This format name already exists.')