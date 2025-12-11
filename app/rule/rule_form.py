import re
from flask import url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import  BooleanField, ValidationError, SelectField
from wtforms.fields import StringField, SubmitField, TextAreaField
from wtforms.validators import  InputRequired, DataRequired


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
    cve_id = StringField('Vulnerability id (comma, space, or newline separated)')
    submit = SubmitField('Create rule')

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
        """Validate multiple CVE-like IDs entered in the form."""
        if not field.data:
            return

        entries = re.split(r'[\s,;]+', field.data.strip())
        entries = [e for e in entries if e]  

        if not entries:
            return

        invalid_entries = []
        valid_entries = []

        cve_pattern = re.compile(
            r"\b(CVE[-\s]?\d{4}[-\s]?\d{4,7})\b"
            r"|\b(GCVE-\d+-\d{4}-\d+)\b"
            r"|\b(GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4})\b"
            r"|\b(PYSEC-\d{4}-\d{2,5})\b"
            r"|\b(GSD-\d{4}-\d{4,5})\b"
            r"|\b(wid-sec-w-\d{4}-\d{4})\b"
            r"|\b(cisco-sa-\d{8}-[a-zA-Z0-9]+)\b"
            r"|\b(RHSA-\d{4}:\d{4})\b"
            r"|\b(msrc_CVE-\d{4}-\d{4,})\b"
            r"|\b(CERTFR-\d{4}-[A-Z]{3}-\d{3})\b",
            re.IGNORECASE
        )

        for e in entries:
            if re.fullmatch(cve_pattern, e):
                valid_entries.append(e.upper())
            else:
                invalid_entries.append(e)

        if invalid_entries:
            raise ValidationError(
                f"Invalid vulnerability ID(s): {', '.join(invalid_entries)}.<br>"
                f"Accepted formats: CVE, GCVE, GHSA, PYSEC, GSD, CERT-Bund, Cisco, RedHat, MSRC CVE, CERT-FR."
            )

        field.data = ",".join(valid_entries)



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
    cve_id = StringField('Vulnerability id')
    submit = SubmitField('Save')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        formats_rules_list = RuleModel.get_all_rule_format()
        self.format.choices = [(f.name, f.name) for f in formats_rules_list]

class CreateFormatRuleForm(FlaskForm):
    """Form to create a new rule format"""

    name = StringField('Format Name', validators=[InputRequired()])
    can_be_execute = BooleanField('Can be executed')  # checkbox
    submit = SubmitField('Create')

    def validate_name(self, field):
        if FormatRule.query.filter_by(name=field.data).first():
            raise ValidationError('This format name already exists.')
        

