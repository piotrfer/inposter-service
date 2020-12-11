from flask import Blueprint

courier = Blueprint('courier_pages', __name__, static_folder='static')

@courier.route('/')
def courier_index():
    return 'courier index'

@courier.route('/login')
def courer_login():
    return 'courier login'

@courier.route('/signup')
def courier_signup():
    return 'courier signup'

@courier.route('/logout')
def courier_logout():
    return 'courier logout'