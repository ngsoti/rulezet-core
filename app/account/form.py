import re
from flask import url_for, flash
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import ValidationError
from wtforms.fields import (
    BooleanField,
    PasswordField,
    StringField,
    SubmitField,
    EmailField
)
from wtforms.validators import Email, InputRequired, Length

from ..db_class.db import User


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log in')


class EditUserForm(FlaskForm):
    first_name = StringField('First name', validators=[InputRequired()])
    last_name = StringField('Last name', validators=[InputRequired()])
    email = EmailField('Email', validators=[InputRequired(), Email()])

    submit = SubmitField('Register')

    def validate_email(self, field):
        if not field.data == current_user.email:
            if User.query.filter_by(email=field.data).first():
                raise ValidationError('Email already registered. (Did you mean to '
                                    '<a href="{}">log in</a> instead?)'.format(
                                        url_for('account.index')))






class AddNewUserForm(FlaskForm):
    
    first_name = StringField('First name', validators=[InputRequired()])
    last_name = StringField('Last name', validators=[InputRequired()])
    email = EmailField('Email', validators=[InputRequired(), Email(message="Please enter a valid email address.")])
    password = PasswordField('Password', validators=[InputRequired()])

    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():                
            raise ValidationError('Email already registered. (Did you mean to '
                                    '<a href="{}">log in</a> instead?)'.format(
                                        url_for('account.index')))
    #raise ValidationError('Invalid email format. Please enter a valid email address.')
    
    