from flask_mail import Message
from flask import render_template, url_for
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
from app import mail, app

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def send_confirmation_email(user):
    token = s.dumps(user.email, salt='email-confirm')
    confirm_url = url_for('confirm_email', token=token, _external=True)

    msg = Message('Please confirm your email address', recipients=[user.email])
    msg.body = render_template('email/confirm.txt', user=user, confirm_url=confirm_url)
    msg.html = render_template('email/confirm.html', user=user, confirm_url=confirm_url, current_year=datetime.now().year)

    mail.send(msg)
