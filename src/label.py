from http import HTTPStatus
from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity
import uuid, util
from exceptions.InvalidLabelError import InvalidLabelError
from exceptions.LabelNotFoundError import LabelNotFoundError
from exceptions.UserNotAuthorizedError import UserNotAuthorizedError

def construct(db):
    label_bp = Blueprint('label_pages', __name__, static_folder='static')

    @label_bp.route('/create', methods=['POST'])
    @jwt_required
    def label_create():
        current_user, role = util.get_current_user(get_jwt_identity())
        if db.hexists(f"user:{current_user}", "role"):
            role = db.hget(f"user:{current_user}", "role").decode()
        if role == 'user':
            label = {}
            label["user"] = current_user
            label["name"] = request.json.get("name")
            label["address"] = request.json.get("address")
            label["box"] = request.json.get("box")
            label["dimensions"] = request.json.get("dimensions")
            try: 
                label = validate_label(label)
                label = save_label(label)
                return make_response(jsonify(label), HTTPStatus.CREATED)
            except InvalidLabelError as e:
                return make_response(jsonify({'msg' : str(e)}), HTTPStatus.BAD_REQUEST)

        else:
            return make_response({'msg': 'you have to be a sender to create labels'},
                                 HTTPStatus.UNAUTHORIZED)

    @label_bp.route('/<label_id>', methods=['GET', 'PATCH', 'DELETE'])
    @jwt_required
    def label_single(label_id):
        current_user, role = util.get_current_user(get_jwt_identity())
        if request.method == 'GET':
            try:
                label = get_single_label(label_id, current_user, role)
                return make_response(jsonify(label), HTTPStatus.OK)
            except LabelNotFoundError as e:
                return make_response(jsonify({'msg' : str(e)}), HTTPStatus.NOT_FOUND)
            except UserNotAuthorizedError as e:
                return make_response(jsonify({'msg' : str(e)}), HTTPStatus.UNAUTHORIZED)

        elif request.method == 'PATCH':
            if role == 'user':
                #update label while it's still not sent
                #label = update_label(label_id, request.data, current_user)
                pass
        else:
            # delete label while it's still not sent
            pass

    @label_bp.route('/list', methods=['GET'])
    @jwt_required
    def label_index():
        current_user, role = util.get_current_user(get_jwt_identity())
        if role == 'user':
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
        if not label.get("name"):
            raise InvalidLabelError("No recipient name provided")
        if not label.get("address"):
            raise InvalidLabelError("No recipient address provided")
        if not label.get("box"):
            raise InvalidLabelError("No mailbox id provided")
        if not label.get("dimensions"):
            raise InvalidLabelError("No dimensions provided")
        
        return label

    def save_label(label):
        label["id"] = uuid.uuid4()
        db.hset(f"label:{label['id']}", "user", label.get('user'))
        db.hset(f"label:{label['id']}", "name", label.get('name'))
        db.hset(f"label:{label['id']}", "address", label.get('address'))
        db.hset(f"label:{label['id']}", "box", label.get('box'))
        db.hset(f"label:{label['id']}", "dimensions", label.get('dimensions'))
        db.hset(f"label:{label['id']}", "sent", "false")
        return label

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
            raise LabelNotFoundError("No label with given id")
        label = {
            "id": key.split(':')[1],
            "name": db.hget(key, "name").decode(),
            "address": db.hget(key, "address").decode(),
            "box": db.hget(key, "box").decode(),
            "dimensions": db.hget(key, "dimensions").decode(),
            "user": db.hget(key, "user").decode()
        }
        if label['user'] != user and role != 'courier':
            raise UserNotAuthorizedError("You can only see your own labels or be a courier")
        
        return label


    def update_label(label_id, data, current_user):        
        pass

    return label_bp