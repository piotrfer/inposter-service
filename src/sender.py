import http
from os import access
import re
from flask import Blueprint
from flask import request, make_response, jsonify
from http import HTTPStatus
from bcrypt import gensalt, hashpw, checkpw
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity

def construct(db):
    sender = Blueprint('sender_pages', __name__, static_folder='static')

    @sender.route('/signup', methods=['POST'])
    def sender_signup():
        data = request.json
        user = {}
        user["firstname"] = data.get('firstname')
        user["lastname"] = data.get('lastname')
        user["login"] = data.get('login')
        user["email"] = data.get('email')
        user["password"] = data.get('password')
        user["address"] = data.get('address')
        return validate_signup_user(user)


    @sender.route('/login', methods=['POST'])
    def sender_login():
        data = request.json
        credentials = {}
        credentials["login"] = data.get('login')
        credentials["password"] = data.get('password')
        return authenticate_user(credentials)

    @sender.route('/logout')    
    def sender_logout():
        return 'sender logout'

    def validate_signup_user(user):
        PL = 'ĄĆĘŁŃÓŚŹŻ'
        pl = 'ąćęłńóśźż'
        errors = []

        valid = True
        if not user["firstname"]:
            valid = False
            errors.append("No firstname provided")
        elif not re.compile(f'[A-Z{PL}][a-z{pl}]+').match(user["firstname"]):
            valid = False
            errors.append("Invalid firstname provided")
        
        if not user["lastname"]:
            valid = False
            errors.append("No lastname provided")
        elif not re.compile(f'[A-Z{PL}][a-z{pl}]+').match(user["lastname"]):
            valid = False
            errors.append("Invalid lastname provided")
        
        if not user["login"]:
            valid = False
            errors.append("No login provided")
        elif not re.compile('[a-z]{3,12}').match(user["login"]):
            valid = False
            errors.append("Invalid lastname provided")
        elif is_user(user["login"]):
            valid = False
            errors.append("User already exists")
        
        if not user["email"]:
            valid = False
            errors.append("No email provided")
        elif not re.compile('^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$').match(user["email"]):
            valid = False
            errors.append("Invalid email provided")
        
        if not user["password"]:
            valid = False
            errors.append("No password provided")
        elif not re.compile('.{8,}').match(user["password"].strip()):
            valid = False
            errors.append("Invalid password provided")
        
        if not user["address"]:
            valid = False
            errors.append("No address provided")
            # regex should be added later

        if valid:
            return register_user(user)
            
        else:
            return make_response({"errors" : errors}, HTTPStatus.BAD_REQUEST)


    def is_user(login):
        return db.hexists(f"user:{login}", "password")

    def register_user(user):
        db.hset(f"user:{user['login']}", "firstname", user["firstname"])
        db.hset(f"user:{user['login']}", "lastname", user["lastname"])
        db.hset(f"user:{user['login']}", "address", user["address"])
        db.hset(f"user:{user['login']}", "email", user["email"])
        db.hset(f"user:{user['login']}", "role", "sender")

        hashed = hashpw(user["password"].encode('utf-8'), gensalt(5))
        db.hset(f"user:{user['login']}", "password", hashed)

        return make_response(user, HTTPStatus.CREATED)

    def authenticate_user(credentials):
        errors = []
        valid = True
        if not credentials.get('login') or not credentials.get('password'):
            errors.append('No login or password provided.')
            valid = False
        else:
            given_password = credentials['password'].encode('utf-8')
            if not db.exists(f"user:{credentials['login']}"):
                errors.append("No user with given username")
                return make_response({"errors" : errors}, HTTPStatus.NOT_FOUND)
            real_password = db.hget(f"user:{credentials['login']}", "password")


            if not real_password:
                errors.append(f"No password for user {credentials['login']}")
                valid = False
            if not checkpw(given_password, real_password):
                errors.append("Wrong password")
                valid = False
        if not valid:
            return make_response({"errors" : errors}, HTTPStatus.BAD_REQUEST)
        else:
            access_token = create_access_token(identity=credentials['login'])
            return make_response(jsonify(access_token), HTTPStatus.OK)

    @sender.route('/protected', methods=['GET'])
    @jwt_required
    def sender_protected():
        current_user = get_jwt_identity()
        return make_response(jsonify(logged_in_as=current_user), HTTPStatus.OK)


    return sender
