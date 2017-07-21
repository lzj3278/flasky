# coding=utf-8
from . import db
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin
from . import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as seris
from datetime import datetime


class Permission:
    def __init__(self):
        pass

    FOLLOW = 0x01
    COMMIT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMITS = 0x08
    ADMINISTER = 0x80


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permission = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW | Permission.COMMIT | Permission.WRITE_ARTICLES, True),
            'Moderator': (
                Permission.FOLLOW | Permission.COMMIT | Permission.WRITE_ARTICLES | Permission.MODERATE_COMMITS, False),
            'Administrator': (0xff, False)
        }
        for u in roles:
            role = Role.query.filter_by(name=u).first()
            if role is None:
                role = Role(name=u)
            role.permission = roles[u][0]
            role.default = roles[u][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permission=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    @property
    def password(self):
        """
        把password 变成类属性
        :return: 
        """
        raise AttributeError('password is not readable attribute')

    @password.setter
    def password(self, password):
        """
        把password 变成类属性进行赋值，生成密码散列值，存入数据库
        :param password: 
        :return: 
        """
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        """
        登录密码验证方法
        :param password: 
        :return: 
        """
        return check_password_hash(self.password_hash, password)

    def generate_token(self, expiration=3600):
        """
        生成token
        :param expiration: 
        :return: 
        """
        s = seris(current_app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        """
        用户账户验证，邮件中的url调用
        :param token: 
        :return: 
        """
        s = seris(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            raise False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def reset_password(self, new_password):
        """
        重设密码
        :param new_password: 
        :return: 
        """
        self.password = new_password
        db.session.add(self)
        return True

    def can(self, permissions):
        return self.role is not None and (self.role.permission & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def __repr__(self):
        return '<User %r>' % self.username

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
