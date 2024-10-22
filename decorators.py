# decorators.py

from functools import wraps
from flask import redirect, url_for, flash, session
from data_utils import get_db_connection
from logger import logger

def basic_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('subscription_tier') not in ['basic', 'premium']:
            flash("You must have a basic subscription to access this page.")
            return redirect(url_for('subscribe_basic'))
        return f(*args, **kwargs)
    return decorated_function

def premium_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('subscription_tier') != 'premium':
            flash("You must have a premium subscription to access this page.")
            return redirect(url_for('subscribe_premium'))
        return f(*args, **kwargs)
    return decorated_function
