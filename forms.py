"""
WTForms for the application.
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp


class LoginForm(FlaskForm):
    """Login form for email/password authentication."""
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class SignupForm(FlaskForm):
    """Signup form for local email/password accounts."""
    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Length(min=4, max=25),
            Regexp(
                r'^[A-Za-z0-9_]+$',
                message='Username can only contain letters, numbers, and underscores.'
            )
        ]
    )
    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Length(max=255),
            Regexp(
                r'^[^@\s]+@[^@\s]+\.[^@\s]+$',
                message='Enter a valid email address.'
            )
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=8, message='Password must be at least 8 characters long.')
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match.')
        ]
    )
    submit = SubmitField('Create Account')
