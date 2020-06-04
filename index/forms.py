
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
#importing the user from the index in the models Object
from index.models import User

#Registration  form using wtf flask
class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    #Custom validator for the username field
    def validate_username(self, username):
         #retrieving the username from the User table
             user = User.query.filter_by(username=username.data).first()
             if user:
                 raise ValidationError('username exist. Choose anther one.')

    #Custom validator for the email field
    def validate_email(self, email):
        #retrieving the email from the User table
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('email exist. Choose anther one.')

#Login form using wtf flask
class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


#Account form using wtf flask
class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Photo', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    #Custom validator for the username field
def validate_username(self, username):
                 #retrieving the username from the User table
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('username exist. Choose anther one.')
    #Custom validator for the email field
def validate_email(self, email):
      #retrieving the email from the User table
         if email.data != current_user.email:
           user = User.query.filter_by(email=email.data).first()
           if user:
               raise ValidationError('email exist. Choose anther one.')

#APosts  form using wtf flask
class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')

#Form for reseting password and email
class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')
