from flask import Blueprint

sender = Blueprint('sender_pages', __name__, static_folder='static')
@sender.route('/')
def sender_index():
    return 'sender index'

@sender.route('/signup')
def sender_signup():
    return 'sender signup'

@sender.route('/login')
def sender_login():
    return 'sender login'