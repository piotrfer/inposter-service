import re
from flask import Blueprint, url_for
from flask import request, make_response, jsonify, redirect
from http import HTTPStatus
from bcrypt import gensalt, hashpw, checkpw
from flask_jwt_extended import create_access_token
from exceptions.InvalidUserError import InvalidUserError
from flask_hal.document import Document
from flask_hal.link import Link


def construct(db):
    sender_bp = Blueprint('sender_pages', __name__, static_folder='static')

    @sender_bp.route('/')
    def sender_index():
        links = []
        links.append(Link('signup', '/sender/signup'))
        links.append(Link('login', '/sender/login'))
        links.append(Link('courier', '/courier'))
        return Document(data={}, links=links).to_json()

    @sender_bp.route('/signup', methods=['POST'])
    def sender_signup():
        data = request.json
        user = {
            "firstname": data.get('firstname'),
            "lastname": data.get('lastname'),
            "login": data.get('login'),
            "email": data.get('email'),
            "password": data.get('password'),
            "address": data.get('address')
        }
        try:
            user = validate_signup_user(user)
            user = save_user(user)
            return Document(data=user).to_json(), HTTPStatus.CREATED
        except InvalidUserError as e:
            return make_response(jsonify({'error': str(e)}), HTTPStatus.BAD_REQUEST)

    @sender_bp.route('/login', methods=['POST'])
    def sender_login():
        data = request.json
        credentials = {
            "login": data.get('login'),
            "password": data.get('password')
        }
        try:
            authenticate_user(credentials)
            access_token = get_access_token(credentials)
            return Document(data={'token': access_token}).to_json()
        except InvalidUserError:
            return make_response({"error": "Invalid login or password"}, HTTPStatus.BAD_REQUEST)

    @sender_bp.route('/check/<login>')
    def sender_check(login):
        status = 'available'
        if is_user(login):
            status = 'taken'
        return make_response(jsonify({login: status}))

    @sender_bp.route('/auth0')
    def process_auth0():
        
        auth0user = {
            "email" : request.json.get('email'),
            "firstname" : request.json.get('name'),
            "lastname" : '',
            "login" : 'auth0'+request.json.get('email'),
            "password" : request.json.get('sub'),
            "address" : '',
        }
        
        # validate all fields here

        if is_user(auth0user.get('login')):
            """ Try to authenticate existing auth0user """
            try:
                authenticate_user(auth0user)
                access_token = get_access_token({"login": auth0user.get("login")})
                return Document(data={'token': access_token}).to_json()
            except InvalidUserError as e:
                return make_response(jsonify({'error': str(e)}), HTTPStatus.BAD_REQUEST)
        else:
            """ Register and login auth0user """
            register_auth0(auth0user)
            try:
                authenticate_user(auth0user)
                access_token = get_access_token({"login": auth0user.get("login")})
                return Document(data={'token': access_token}).to_json()
            except InvalidUserError as e:
                return make_response(jsonify({'error': str(e)}), HTTPStatus.BAD_REQUEST)


    def register_auth0(auth0user):
        db.hset(f"user:{auth0user['login']}", "firstname", auth0user["firstname"])
        db.hset(f"user:{auth0user['login']}", "lastname", auth0user["lastname"])
        db.hset(f"user:{auth0user['login']}", "address", auth0user["address"])
        db.hset(f"user:{auth0user['login']}", "email", auth0user["email"])

        hashed = hashpw(auth0user["password"].encode('utf-8'), gensalt(5))
        db.hset(f"user:{auth0user['login']}", "password", hashed)

        return auth0user

    def validate_signup_user(user):
        PL = 'ĄĆĘŁŃÓŚŹŻ'
        pl = 'ąćęłńóśźż'

        if not user["firstname"]:
            raise InvalidUserError("No firstname provided")
        elif not re.compile(f'[A-Z{PL}][a-z{pl}]+').match(user["firstname"]):
            raise InvalidUserError("Invalid firstname provided")

        if not user["lastname"]:
            raise InvalidUserError("No lastname provided")
        elif not re.compile(f'[A-Z{PL}][a-z{pl}]+').match(user["lastname"]):
            raise InvalidUserError("Invalid lastname provided")

        if not user["login"]:
            raise InvalidUserError("No login provided")
        elif not re.compile('[a-z]{3,12}').match(user["login"]):
            raise InvalidUserError("Invalid lastname provided")
        elif is_user(user["login"]):
            raise InvalidUserError("User already exists")

        if not user["email"]:
            raise InvalidUserError("No email provided")
        elif not re.compile('^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$').match(user["email"]):
            raise InvalidUserError("Invalid email provided")

        if not user["password"]:
            raise InvalidUserError("No password provided")
        elif not re.compile('.{8,}').match(user["password"].strip()):
            raise InvalidUserError("Invalid password provided")

        if not user["address"]:
            raise InvalidUserError("No address provided")
            # regex should be added later

        return user

    def is_user(login):
        return db.hexists(f"user:{login}", "password")

    def save_user(user):
        db.hset(f"user:{user['login']}", "firstname", user["firstname"])
        db.hset(f"user:{user['login']}", "lastname", user["lastname"])
        db.hset(f"user:{user['login']}", "address", user["address"])
        db.hset(f"user:{user['login']}", "email", user["email"])

        hashed = hashpw(user["password"].encode('utf-8'), gensalt(5))
        db.hset(f"user:{user['login']}", "password", hashed)

        return user

    def authenticate_user(credentials):
        if not credentials.get('login') or not credentials.get('password'):
            raise InvalidUserError('No login or password provided.')
        else:
            given_password = credentials['password'].encode('utf-8')
            if not db.exists(f"user:{credentials['login']}"):
                raise InvalidUserError("No user with given username")
            real_password = db.hget(f"user:{credentials['login']}", "password")

            if not real_password:
                raise InvalidUserError(
                    f"No password for user {credentials['login']}")
            if not checkpw(given_password, real_password):
                raise InvalidUserError("Wrong password")

    def get_access_token(credentials):
        return create_access_token(identity=f"user:{credentials['login']}")

    return sender_bp