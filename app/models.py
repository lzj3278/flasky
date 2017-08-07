# -*- coding=utf-8 -*-
from . import db
from flask import current_app, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin
from . import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as seris
from datetime import datetime
import hashlib
from markdown import markdown
import bleach


class Permission:
    """
    权限对应
    """

    def __init__(self):
        pass

    FOLLOW = 0x01
    COMMENT = 0x02
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
        """
        数据库角色添加
        :return: 
        """
        roles = {
            'User': (Permission.FOLLOW | Permission.COMMENT | Permission.WRITE_ARTICLES, True),
            'Moderator': (
                Permission.FOLLOW | Permission.COMMENT | Permission.WRITE_ARTICLES | Permission.MODERATE_COMMITS, False),
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


class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
    """
    用户类
    """
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))
    followed = db.relationship(
        'Follow', foreign_keys=[Follow.follower_id], backref=db.backref('follower', lazy='joined'),
        lazy='dynamic', cascade='all, delete-orphan')
    followers = db.relationship(
        'Follow', foreign_keys=[Follow.followed_id], backref=db.backref('followed', lazy='joined'),
        lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')

    def __init__(self, **kwargs):
        """
        初始化 角色跟头像hash串
        :param kwargs: 
        """
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permission=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
        self.follow(self)

    @property
    def password(self):
        """
        把password 变成类属性
        :return: 不能直接访问属性
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
        用户账户验证
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
        """
        验证权限
        :param permissions: 待验证权限
        :return: 
        """
        return self.role is not None and (self.role.permission & permissions) == permissions

    def is_administrator(self):
        """
        验证管理员
        :return: 
        """
        return self.can(Permission.ADMINISTER)

    def __repr__(self):
        return '<User %r>' % self.username

    def ping(self):
        """
        最后登录时间记录
        :return: 
        """
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def gravatar(self, size=100, default='identicon', rating='g'):
        """
        生成图片url
        :param size: 
        :param default: 
        :param rating: 
        :return: 
        """
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(url=url, hash=hash, size=size, default=default,
                                                                     rating=rating)

    @staticmethod
    def generate_fake_data(count=100):
        """
        制作数据方法
        :param count: 
        :return: 
        """
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(),
                     # password=forgery_py.lorem_ipsum.word(),
                     password=u'123',
                     confirmed=True,
                     name=forgery_py.name.full_name(),
                     location=forgery_py.address.city(),
                     about_me=forgery_py.lorem_ipsum.sentence(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    def is_following(self, user):
        """
        判断是否关注这个用户
        :param user: 
        :return: 
        """
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        """
        判断是否有此追随者
        :param user: 
        :return: 
        """
        return self.followers.filter_by(follower_id=user.id).first() is not None

    def follow(self, user):
        """
        关注
        :param user: 
        :return: 
        """
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):
        """
        取关
        :param user: 
        :return: 
        """
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def followed_posts(self):
        """
        查找关注者的所有文章
        :return: 
        """
        return Post.query.join(Follow, Follow.followed_id == Post.author_id).filter(Follow.follower_id == self.id)

    @staticmethod
    def add_self_follow():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    body_html = db.Column(db.Text)
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    @staticmethod
    def generate_fake_data(count=100):
        from random import seed, randint
        import forgery_py
        seed()
        user_count = User.query.count()
        for i in range(count):
            u = User.query.offset(randint(0, user_count - 1)).first()
            p = Post(body=forgery_py.lorem_ipsum.sentences(randint(1, 3)),
                     timestamp=forgery_py.date.date(True),
                     author=u)
            db.session.add(p)
            db.session.commit()

    @staticmethod
    def on_change_body(target, value, oldvalue, initiator):
        """
        将markdown转成html
        :param target: 
        :param value: 
        :param oldvalue: 
        :param initiator: 
        :return: 
        """
        allowed_tags = [
            'a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
            'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
            'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'), tags=allowed_tags, strip=True)
        )


# 监听post 有数据变化 调用on_change_body
db.event.listen(Post.body, 'set', Post.on_change_body)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    disabled = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    @staticmethod
    def on_change_body(target, value, oldvalue, initiator):
        """
        将markdown转成html
        :param target: 
        :param value: 
        :param oldvalue: 
        :param initiator: 
        :return: 
        """
        allowed_tags = [
            'a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
            'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
            'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'), tags=allowed_tags, strip=True)
        )


db.event.listen(Comment.body, 'set', Comment.on_change_body)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
