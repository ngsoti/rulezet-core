from flask_wtf import FlaskForm
from wtforms.validators import ValidationError
from wtforms import StringField, SubmitField, TextAreaField, BooleanField
from wtforms.validators import InputRequired, DataRequired

from app.db_class.db import Bundle

class AddNewBundleForm(FlaskForm):
    """Form to create a new bundle."""

    name = StringField('Bundle Name', validators=[InputRequired(message="Bundle name is required")])
    description = TextAreaField('Description',  validators=[InputRequired(message="Bundle description is required")])
    public = BooleanField('Public', default=True) 
    
    submit = SubmitField('Create Bundle')

    def validate_name(self, field):
        if Bundle.query.filter_by(name=field.data).first():
            raise ValidationError('Bundle already registered.')
        

class EditBundleForm(FlaskForm):
    """Form to edit a bundle."""

    name = StringField('Bundle Name', validators=[InputRequired(message="Bundle name is required")])
    description = TextAreaField('Description', validators=[InputRequired(message="Bundle description is required")])
    public = BooleanField('Public', default=True)

    submit = SubmitField('Save')

    def __init__(self, bundle_id=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bundle_id = bundle_id

    def validate_name(self, field):
        existing_bundle = Bundle.query.filter_by(name=field.data).first()
        if existing_bundle and existing_bundle.id != self.bundle_id:
            raise ValidationError('Bundle already registered.')