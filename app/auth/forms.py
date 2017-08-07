# -*- coding:utf-8 -*-

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from wtforms import ValidationError
from ..models import User


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    remeber_me = BooleanField('Keep me logged in')
    submit = SubmitField('Login In')


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 60), Email()])
    username = StringField('User', validators=[DataRequired(), Length(1, 60), Regexp(
        '^[A-Za-z0-9_.]*$', 0, u'用户名只能是数字字母或者下划线点'
    )])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('password2', message=u'两次密码必须相同')])
    password2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField(u'注册')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError(u'邮箱地址已经被注册')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError(u'用户名已经被注册')


class ChangePassword(FlaskForm):
    oldpasswd = PasswordField('Old password', validators=[DataRequired()])
    newpasswd = PasswordField('New password', validators=[DataRequired(), EqualTo('newpasswd2', message=u'两次密码必须相同')])
    newpasswd2 = PasswordField('New password', validators=[DataRequired()])
    submit = SubmitField(u'确认更改')


class FindPassword(FlaskForm):
    email = StringField(u'邮箱', validators=[DataRequired(), Email()])
    submit = SubmitField(u'确认')


class ResetPassword(FlaskForm):
    # email = StringField(u'邮箱', validators=[DataRequired(), Email()])
    newpasswd = PasswordField('New password', validators=[DataRequired(), EqualTo('newpasswd2', message=u'两次密码必须相同')])
    newpasswd2 = PasswordField('New password', validators=[DataRequired()])
    submit = SubmitField(u'确认更改')
