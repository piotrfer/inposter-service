import http
from os import access
import re
from flask import Blueprint
from flask import request, make_response, jsonify
from http import HTTPStatus
from bcrypt import gensalt, hashpw, checkpw
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity

def construct(db):

    courier_bp = Blueprint('courier_pages', __name__, static_folder='static')

    @courier_bp.route('/signup', methods=['POST'])
    def courier_signup():
        data = request.json
        courier = {}
        courier["firstname"] = data.get('firstname')
        courier["lastname"] = data.get('lastname')
        courier["login"] = data.get('login')
        courier["email"] = data.get('email')
        courier["password"] = data.get('password')
        courier["licence"] = data.get('licence')
        return validate_courier(courier)

    @courier_bp.route('/login', methods=['POST'])
    def courer_login():
        data = request.json
        credentials = {}
        credentials["login"] = data.get('login')
        credentials["password"] = data.get('password')
        return authenticate_courier(credentials)

    @courier_bp.route('/logout')
    def courier_logout():
        return 'courier logout'

    def validate_courier(courier):
        errors = []
        valid = True
        
        PL = 'ĄĆĘŁŃÓŚŹŻ'
        pl = 'ąćęłńóśźż'
        
        if not courier["firstname"]:
            valid = False
            errors.append("No firstname provided")
        elif not re.compile(f'[A-Z{PL}][a-z{pl}]+').match(courier["firstname"]):
            valid = False
            errors.append("Invalid firstname provided")

        if not courier["lastname"]:
            valid = False
            errors.append("No lastname provided")
        elif not re.compile(f'[A-Z{PL}][a-z{pl}]+').match(courier["lastname"]):
            valid = False
            errors.append("Invalid lastname provided")

        if not courier["login"]:
            valid = False
            errors.append("No login provided")
        elif not re.compile('[a-z]{3,12}').match(courier["login"]):
            valid = False
            errors.append("Invalid lastname provided")
        elif is_courier(courier["login"]):
            valid = False
            errors.append("courier already exists")

        if not courier["email"]:
            valid = False
            errors.append("No email provided")
        elif not re.compile('^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$').match(courier["email"]):
            valid = False
            errors.append("Invalid email provided")

        if not courier["password"]:
            valid = False
            errors.append("No password provided")
        elif not re.compile('.{8,}').match(courier["password"].strip()):
            valid = False
            errors.append("Invalid password provided")

        if not courier["licence"]:
            valid = False
            errors.append("No licence provided")
            # regex should be added later
        
        if not valid:
            return make_response({"errors" : errors}, HTTPStatus.BAD_REQUEST)

        db.hset(f"courier:{courier['login']}", "firstname", courier["firstname"])
        db.hset(f"courier:{courier['login']}", "lastname", courier["lastname"])
        db.hset(f"courier:{courier['login']}", "licence", courier["licence"])
        db.hset(f"courier:{courier['login']}", "email", courier["email"])

        hashed = hashpw(courier["password"].encode('utf-8'), gensalt(5))
        db.hset(f"courier:{courier['login']}", "password", hashed)
        
        return make_response(jsonify(courier), HTTPStatus.CREATED)


    def is_courier(login):
        return db.hexists(f"courier:{login}", "password")

    def authenticate_courier(credentials):
        errors = []
        valid = True
        if not credentials.get('login') or not credentials.get('password'):
            errors.append('No login or password provided.')
            valid = False
        else:
            given_password = credentials['password'].encode('utf-8')
            if not db.exists(f"courier:{credentials['login']}"):
                errors.append("No user with given username")
                return make_response({"errors" : errors}, HTTPStatus.NOT_FOUND)
            real_password = db.hget(f"courier:{credentials['login']}", "password")


            if not real_password:
                errors.append(f"No password for user {credentials['login']}")
                valid = False
            if not checkpw(given_password, real_password):
                errors.append("Wrong password")
                valid = False
        if not valid:
            return make_response({"errors" : errors}, HTTPStatus.BAD_REQUEST)
        else:
            access_token = create_access_token(identity=f"courier:{credentials['login']}")
            return make_response(jsonify(access_token), HTTPStatus.OK)

    return courier_bp