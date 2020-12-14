import http
from os import access
import re
from flask import Blueprint
from flask import request, make_response, jsonify
from http import HTTPStatus
from bcrypt import gensalt, hashpw, checkpw
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from exceptions.InvalidCourierError import InvalidCourierError


def construct(db):

    courier_bp = Blueprint('courier_pages', __name__, static_folder='static')

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
            return make_response(jsonify(courier), HTTPStatus.CREATED)
        except InvalidCourierError as e:
            return make_response(jsonify({'msg' : str(e)}), HTTPStatus.BAD_REQUEST)

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
            return make_response(jsonify(access_token), HTTPStatus.OK)
        except InvalidCourierError:
            return make_response(jsonify({'msg' : 'Invalid login or password'}), HTTPStatus.BAD_REQUEST)

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