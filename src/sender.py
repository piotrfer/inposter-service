import re
from flask import Blueprint
from flask import request, make_response, jsonify
from http import HTTPStatus
from bcrypt import gensalt, hashpw, checkpw
from flask_jwt_extended import create_access_token
from exceptions.InvalidUserError import InvalidUserError
from flask_hal import document 

def construct(db):
    sender = Blueprint('sender_pages', __name__, static_folder='static')

    @sender.route('/signup', methods=['POST'])
    def sender_signup():
        data = request.json
        user = {
            "firstname" : data.get('firstname'),
            "lastname" : data.get('lastname'),
            "login" : data.get('login'),
            "email" : data.get('email'),
            "password" : data.get('password'),
            "address" : data.get('address')
        }
        try:
            user = validate_signup_user(user)
            user = save_user(user)
            #return make_response(jsonify(user), HTTPStatus.CREATED)
            return document.Document(data=user, status=HTTPStatus.CREATED).to_json()
        except InvalidUserError as e:
            return make_response(jsonify({'msg' : str(e)}), HTTPStatus.BAD_REQUEST)


    @sender.route('/login', methods=['POST'])
    def sender_login():
        data = request.json
        credentials = {
            "login" : data.get('login'),
            "password" : data.get('password')
        }
        try:
            authenticate_user(credentials)
            access_token = get_access_token(credentials)
            return make_response(jsonify(access_token), HTTPStatus.OK)
        except InvalidUserError:
            return make_response({"msg" : "Invalid login or password"}, HTTPStatus.BAD_REQUEST)

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
                raise InvalidUserError(f"No password for user {credentials['login']}")
            if not checkpw(given_password, real_password):
                raise InvalidUserError("Wrong password")
    
    def get_access_token(credentials):
            return create_access_token(identity=f"user:{credentials['login']}")

    return sender