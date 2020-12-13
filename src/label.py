from http import HTTPStatus
from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity
import uuid, util


def construct(db):
    label_bp = Blueprint('label_pages', __name__, static_folder='static')

    @label_bp.route('/create', methods=['POST'])
    @jwt_required
    def label_create():
        current_user, role = util.get_current_user(get_jwt_identity())
        role = 'no role'
        if db.hexists(f"user:{current_user}", "role"):
            role = db.hget(f"user:{current_user}", "role").decode()
        if role == 'sender':
            label = {}
            label["user"] = current_user
            label["name"] = request.json.get("name")
            label["address"] = request.json.get("address")
            label["box"] = request.json.get("box")
            label["dimensions"] = request.json.get("dimensions")
            return validate_label(label)
        else:
            return make_response({'msg': 'you have to be a sender to create labels'},
                                 HTTPStatus.UNAUTHORIZED)

    @label_bp.route('/<label_id>', methods=['GET', 'PUT', 'DELETE'])
    @jwt_required
    def label_single(label_id):
        current_user, role = util.get_current_user(get_jwt_identity())
        if request.method == 'GET':
            return get_single_label(label_id, current_user, role)
        elif request.method == 'PUT':
            # update label to be added
            pass
        else:
            # delete label to be added
            pass

    @label_bp.route('/list', methods=['GET'])
    @jwt_required
    def label_index():
        current_user, role = util.get_current_user(get_jwt_identity())
        if role == 'sender':
            labels = get_user_labels(current_user)
            return make_response(jsonify(labels), HTTPStatus.OK)
        elif role == 'courier':
            labels = get_all_labels()
            return make_response(jsonify(labels), HTTPStatus.OK)
        else:
            return make_response(
                {'msg': 'you have to be a sender or a courier to see labels'},
                HTTPStatus.UNAUTHORIZED)

    def validate_label(label):
        errors = []
        valid = True
        if not label.get("name"):
            valid = False
            errors.append("No recipient name provided")
        if not label.get("address"):
            valid = False
            errors.append("No recipient address provided")
        if not label.get("box"):
            valid = False
            errors.append("No mailbox id provided")
        if not label.get("dimensions"):
            valid = False
            errors.append("No dimensions provided")
        if not valid:
            return make_response(jsonify(errors), HTTPStatus.BAD_REQUEST)

        label["id"] = uuid.uuid4()
        db.hset(f"label:{label['id']}", "user", label.get('user'))
        db.hset(f"label:{label['id']}", "name", label.get('name'))
        db.hset(f"label:{label['id']}", "address", label.get('address'))
        db.hset(f"label:{label['id']}", "box", label.get('box'))
        db.hset(f"label:{label['id']}", "dimensions", label.get('dimensions'))
        return make_response(jsonify(label), HTTPStatus.CREATED)

    def get_user_labels(user):
        labels = []
        for key in db.scan_iter("label:*"):
            key = key.decode()
            if db.hget(key, "user").decode() == user:
                label = {
                    "id": key.split(':')[1],
                    "name": db.hget(key, "name").decode(),
                    "address": db.hget(key, "address").decode(),
                    "box": db.hget(key, "box").decode(),
                    "dimensions": db.hget(key, "dimensions").decode()
                }
                labels.append(label)
        return labels

    def get_all_labels():
        labels = []
        for key in db.scan_iter("label:*"):
            key = key.decode()
            label = {
                "id": key.split(':')[1],
                "name": db.hget(key, "name").decode(),
                "address": db.hget(key, "address").decode(),
                "box": db.hget(key, "box").decode(),
                "dimensions": db.hget(key, "dimensions").decode(),
                "user": db.hget(key, "user").decode()
            }
            labels.append(label)
        return labels

    def get_single_label(id, user, role):
        key = f"label:{id}"
        if not db.exists(key):
            return make_response("No label with given id", HTTPStatus.NOT_FOUND)
        label = {
            "id": key.split(':')[1],
            "name": db.hget(key, "name").decode(),
            "address": db.hget(key, "address").decode(),
            "box": db.hget(key, "box").decode(),
            "dimensions": db.hget(key, "dimensions").decode(),
            "user": db.hget(key, "user").decode()
        }
        if label['user'] == user or role == 'courier':
            return make_response(jsonify(label), HTTPStatus.OK)
        else:
            return make_response({"msg" : "You are not authorized to see this label"}, HTTPStatus.UNAUTHORIZED)

    return label_bp
