# -*- coding:utf-8 -*-

from functools import wraps
from .models import Permission
from flask_login import current_user
from flask import abort


def permission_required(permissions):
    def decorator(func):
        @wraps(func)
        def decorator_function(*args, **kwargs):
            if not current_user.can(permissions):
                abort(403)
            return func(*args, **kwargs)

        return decorator_function

    return decorator


def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)
