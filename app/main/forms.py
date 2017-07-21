# -*- coding:utf-8 -*-
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, Email, Regexp
from wtforms import ValidationError
from ..models import Role, User


#
# class NameForm(FlaskForm):
#     name = StringField('What is your name?', validators=[Required()])
#     submit = SubmitField('Submit')


class EditProfileForm(FlaskForm):
    name = StringField(u'姓名', validators=[DataRequired(), Length(0, 64)])
    location = StringField(u'地址', validators=[DataRequired(), Length(0, 64)])
    about_me = TextAreaField(u'自我介绍')
    submit = SubmitField(u'确认')


class EditProfileAdminForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(0, 64), Email()])
    username = StringField('Username', validators=[
        DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                              'Username must have only letters, '
                                              'numbers, dots or underscores')])
    confirmed = BooleanField('confirmed')
    role = SelectField('Role', coerce=int)
    name = StringField(u'姓名', validators=[DataRequired(), Length(0, 64)])
    location = StringField(u'地址', validators=[DataRequired(), Length(0, 64)])
    about_me = TextAreaField(u'自我介绍')
    submit = SubmitField(u'确认')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and User.query.filter_by(email=field.data).first():
            raise ValidationError(u'邮箱已经注册')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')
