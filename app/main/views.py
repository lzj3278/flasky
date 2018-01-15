# -*- coding:utf-8 -*-
from flask import render_template, session, redirect, url_for, current_app, abort, flash, request, make_response
from .. import db
from ..models import User, Role, Permission, Post, Comment
from ..email import send_email
from . import main
from .forms import EditProfileForm, EditProfileAdminForm, PostForm, CommentForm
from flask_login import login_required, current_user
from ..decorators import admin_required, permission_required


@main.route('/', methods=['POST', 'GET'])
def index():
    """
    首页（发布，文章列表）
    :return:
    """
    form = PostForm()
    if current_user.can(Permission.WRITE_ARTICLES) and form.validate_on_submit():
        post = Post(body=form.body.data, author=current_user._get_current_object())
        db.session.add(post)
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    show_followed = False
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get('show_followed', ''))
    if show_followed:
        query = current_user.followed_posts()
    else:
        query = Post.query
    pagination = query.order_by(Post.timestamp.desc()).paginate(page,
                                                                per_page=current_app.config['FLASKY_POSTS_PAGE'],
                                                                error_out=False)
    posts = pagination.items
    return render_template('index.html', posts=posts, form=form, pagination=pagination, show_followed=show_followed)


@main.route('/user/<username>')
def user(username):
    """
    用户信息页，自己文章页
    :param username:
    :return:
    """
    user = User.query.filter_by(username=username).first_or_404()
    if user is None:
        abort(404)
    page = request.args.get('page', 1, type=int)
    pagination = user.posts.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PAGE']
    )
    posts = pagination.items
    return render_template('user.html', user=user, posts=posts, pagination=pagination)


@main.route('/user/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """
    修改自己用户信息
    :return:
    """
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash(u'用户信息已经更改')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)


@main.route('/user/edit_profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    """
    管理员修改信息(包含其他用户信息)
    :param id:
    :return:
    """
    user = User.query.filter_by(id=id).first_or_404()
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash('The profile has been updated.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)


@main.route('/posts/<int:id>', methods=['GET', 'POST'])
def post(id):
    """
    单独文章页
    :param id:
    :return:
    """
    post = Post.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data, post=post, author=current_user._get_current_object())
        db.session.add(comment)
        flash(u'评论成功')
        return redirect(url_for('.post', id=post.id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments.count() - 1) / current_app.config['FLASKY_POSTS_PAGE'] + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PAGE'], error_out=False
    )
    comments = pagination.items
    return render_template('post.html', posts=[post], comments=comments, form=form, pagination=pagination)


@main.route('/edit/<int:id>', methods=['POST', 'GET'])
@login_required
def edit_post(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        flash(u'更新成功')
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form)


@main.route('/delete/<int:id>')
@login_required
def delete_post(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and not current_user.can(Permission.ADMINISTER):
        abort(403)
    comments = post.comments.all()
    db.session.delete(post)
    for comment in comments:
        db.session.delete(comment)
    return redirect(url_for('.user', username=post.author.username))


@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash(u'无此用户')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        flash(u'已经关注')
        return redirect(url_for('.user', username=username))
    current_user.follow(user)
    return redirect(url_for('.user', username=username))


@main.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash(u'无此用户')
        return redirect(url_for('.index'))
    if not current_user.is_following(user):
        flash(u'没有关注')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    return redirect(url_for('.user', username=username))


@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash(u'没有此用户')
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PAGE']
    )
    followers = [{'user': item.follower, 'timestamp': item.timestamp} for item in pagination.items]
    return render_template('followers.html', followers=followers, user=user, pagination=pagination,
                           title=u'的粉丝 ')


@main.route('/followed/<username>')
def follow_to_other(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash(u'没有此用户')
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PAGE']
    )
    followed = [{'user': item.followed, 'timestamp': item.timestamp} for item in pagination.items]
    return render_template('followed.html', followed=followed, user=user, pagination=pagination,
                           title=u'关注 ')


@main.route('/all')
# @login_required
def show_all():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '', max_age=30 * 24 * 60 * 60)
    return resp


@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '1', max_age=30 * 24 * 60 * 60)
    return resp


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMITS)
def moderate():
    pass
