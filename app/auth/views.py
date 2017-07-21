# -*- coding:utf-8 -*-

from . import auth
from .. import db
from flask import render_template, redirect, url_for, flash, request,current_app
from forms import LoginForm, RegisterForm, ChangePassword, FindPassword, ResetPassword
from ..models import User
from flask_login import login_user, logout_user, login_required, current_user
from ..email import send_email
from itsdangerous import TimedJSONWebSignatureSerializer as seris


@auth.route('/login', methods=['GET', 'POST'])
def login():
    """
    登录
    :return:
    """
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remeber_me.data)
            return redirect(url_for('main.index') or request.args.get('next'))
        flash(u'错误的用户或密码')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    """
    登出
    :return:
    """
    logout_user()
    flash(u'退出登录')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    """
    注册
    :return:
    """
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_token()
        send_email(user.email, u'确认你的账户信息', 'auth/email/confirm', user=user, token=token)

        flash(u'验证邮件已经发出')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """
    修改密码
    :return:
    """
    form = ChangePassword()
    if form.validate_on_submit():
        current_user.password = form.newpasswd.data
        db.session.add(current_user)
        flash(u'密码已经修改，请重新登陆')
        return redirect(url_for('auth.logout'))
    return render_template('auth/change_password.html', form=form)


@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """
    重设密码时填写邮箱页面
    :return:
    """
    form = FindPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_token()
            send_email(user.email, u'重置密码', 'auth/email/reset_password', user=user, token=token)
            flash(u'邮件发出')
            return redirect(url_for('auth.login'))
        flash(u'请填写正确的邮箱地址')
    return render_template('auth/reset_password_mail.html', form=form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])
def reset_find_password(token):
    """
    找回密码时 确认邮件返回
    :param token:
    :return:
    """
    form = ResetPassword()
    if form.validate_on_submit():
        s = seris(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            raise False
        user_id = data.get('confirm')
        user = User.query.filter_by(id=user_id).first()
        # if user is None:
        #     return redirect(url_for('main.index'))
        if user.reset_password(form.newpasswd.data):
            flash(u'你的密码已经重置成功')
            return redirect(url_for('auth.login'))
        else:
            flash(u'密码重置失败')
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    """
    注册时 邮件中的验证url指向方法
    :param token:
    :return:
    """
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash(u'你已经完成账户验证，谢谢')
    else:
        flash(u'验证过期')
    return redirect(url_for('main.index'))


@auth.before_app_request
def before_request():
    """
    每次请求前运行
    :return:
    """
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed and request.endpoint[:5] != 'auth.' and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    """
    未验证用户登陆后显示页面
    :return:
    """
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/confirm')
@login_required
def resend_confirmation():
    """
    重新发送验证邮件
    :return:
    """
    token = current_user.generate_token()
    send_email(current_user.email, u'确认你的账户信息', 'auth/email/confirm', user=current_user, token=token)
    flash(u'新的验证邮件已经发出')
    return redirect(url_for('main.index'))
