import http
from os import access
import re
from flask import Blueprint
from flask import request, make_response, jsonify
from http import HTTPStatus
from bcrypt import gensalt, hashpw, checkpw
from flask_jwt_extended import create_access_token
from flask_hal.document import Document
from flask_hal.link import Link
from exceptions.InvalidCourierError import InvalidCourierError


def construct(db):

    courier_bp = Blueprint('courier_pages', __name__, static_folder='static')

    @courier_bp.route('/')
    def courier_index():
        links = []
        links.append(Link('signup', '/courier/signup'))
        links.append(Link('login', '/courier/login'))
        links.append(Link('sender', '/sender'))
        return Document(data={}, links=links).to_json()


    @courier_bp.route('/signup', methods=['POST'])
    def courier_signup():
        data = request.json
        courier = {
            "firstname" : data.get('firstname'),
            "lastname" : data.get('lastname'),
            "login" : data.get('login'),
            "email" : data.get('email'),
            "password" : data.get('password'),
            "licence" : data.get('licence')
        }
        try:
            courier = validate_courier(courier)
            courier = save_courier(courier)
            return Document(data=courier).to_json(), HTTPStatus.CREATED
        except InvalidCourierError as e:
            return make_response(jsonify({'error' : str(e)}), HTTPStatus.BAD_REQUEST)

    @courier_bp.route('/login', methods=['POST'])
    def courer_login():
        data = request.json
        credentials = {
            "login" : data.get('login'),
            "password" : data.get('password')
        }
        try:
            authenticate_courier(credentials)
            access_token = get_access_token(credentials)
            return Document(data={'token' : access_token}).to_json()
        except InvalidCourierError:
            return make_response(jsonify({'error' : 'Invalid login or password'}), HTTPStatus.BAD_REQUEST)

    @courier_bp.route('/check/<login>')
    def courier_check(login):
        status = 'available'
        if is_courier(login): status = 'taken'
        return make_response(jsonify({login : status}))


    @sender_bp.route('/auth0', methods=['POST'])
    def process_auth0():
        
        auth0user = {
            "email" : request.json.get('email'),
            "firstname" : request.json.get('name'),
            "lastname" : '',
            "login" : 'auth0'+request.json.get('email'),
            "password" : request.json.get('sub'),
            "licence" : '',
        }
        
        # validate all fields here

        if is_courier(auth0user.get('login')):
            """ Try to authenticate existing auth0user """
            try:
                authenticate_courier(auth0user)
                access_token = get_access_token({"login": auth0user.get("login")})
                return Document(data={'token': access_token}).to_json()
            except InvalidCourierError as e:
                return make_response(jsonify({'error': str(e)}), HTTPStatus.BAD_REQUEST)
        else:
            """ Register and login auth0user """
            register_auth0(auth0user)
            try:
                authenticate_courier(auth0user)
                access_token = get_access_token({"login": auth0user.get("login")})
                return Document(data={'token': access_token}).to_json()
            except InvalidCourierError as e:
                return make_response(jsonify({'error': str(e)}), HTTPStatus.BAD_REQUEST)


    def register_auth0(auth0user):
        db.hset(f"courier:{auth0user['login']}", "firstname", auth0user["firstname"])
        db.hset(f"courier:{auth0user['login']}", "lastname", auth0user["lastname"])
        db.hset(f"courier:{auth0user['login']}", "licence", auth0user["licence"])
        db.hset(f"courier:{auth0user['login']}", "email", auth0user["email"])

        hashed = hashpw(auth0user["password"].encode('utf-8'), gensalt(5))
        db.hset(f"courier:{auth0user['login']}", "password", hashed)

        return auth0user


    def validate_courier(courier):
        PL = 'ĄĆĘŁŃÓŚŹŻ'
        pl = 'ąćęłńóśźż'
        
        if not courier["firstname"]:
            raise InvalidCourierError("No firstname provided")
        elif not re.compile(f'[A-Z{PL}][a-z{pl}]+').match(courier["firstname"]):
            raise InvalidCourierError("Invalid firstname provided")

        if not courier["lastname"]:
            raise InvalidCourierError("No lastname provided")
        elif not re.compile(f'[A-Z{PL}][a-z{pl}]+').match(courier["lastname"]):
            raise InvalidCourierError("Invalid lastname provided")

        if not courier["login"]:
            raise InvalidCourierError("No login provided")
        elif not re.compile('[a-z]{3,12}').match(courier["login"]):
            raise InvalidCourierError("Invalid lastname provided")
        elif is_courier(courier["login"]):
            raise InvalidCourierError("courier already exists")

        if not courier["email"]:
            raise InvalidCourierError("No email provided")
        elif not re.compile('^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$').match(courier["email"]):
            raise InvalidCourierError("Invalid email provided")

        if not courier["password"]:
            raise InvalidCourierError("No password provided")
        elif not re.compile('.{8,}').match(courier["password"].strip()):
            raise InvalidCourierError("Invalid password provided")

        if not courier["licence"]:
            raise InvalidCourierError("No licence provided")
            # regex should be added later
        
        return courier


    def save_courier(courier):
        db.hset(f"courier:{courier['login']}", "firstname", courier["firstname"])
        db.hset(f"courier:{courier['login']}", "lastname", courier["lastname"])
        db.hset(f"courier:{courier['login']}", "licence", courier["licence"])
        db.hset(f"courier:{courier['login']}", "email", courier["email"])

        hashed = hashpw(courier["password"].encode('utf-8'), gensalt(5))
        db.hset(f"courier:{courier['login']}", "password", hashed)
        
        return courier


    def is_courier(login):
        return db.hexists(f"courier:{login}", "password")

    def authenticate_courier(credentials):
        if not credentials.get('login') or not credentials.get('password'):
            raise InvalidCourierError('No login or password provided.')
        else:
            given_password = credentials['password'].encode('utf-8')
            if not db.exists(f"courier:{credentials['login']}"):
                raise InvalidCourierError("No user with given username")
            real_password = db.hget(f"courier:{credentials['login']}", "password")


            if not real_password:
                raise InvalidCourierError(f"No password for user {credentials['login']}")
            if not checkpw(given_password, real_password):
                raise InvalidCourierError("Wrong password")
        
    def get_access_token(credentials):
            access_token = create_access_token(identity=f"courier:{credentials['login']}")
            return access_token
    return courier_bp