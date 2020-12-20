from http import HTTPStatus
from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity
import uuid, util
from flask_hal.document import Document, Embedded
from flask_hal.link import Link
from exceptions.InvalidLabelError import InvalidLabelError
from exceptions.LabelNotFoundError import LabelNotFoundError
from exceptions.UserNotAuthorizedError import UserNotAuthorizedError

def construct(db):
    label_bp = Blueprint('label_pages', __name__, static_folder='static')

    @label_bp.route('/')
    def label_index():
        links = []
        links.append('list', '/labels/list')
        links.append('find', '/labels/<id>')
        document = Document(data={}, links=links)
        return document.to_json()



    @label_bp.route('/<label_id>', methods=['GET', 'PATCH', 'DELETE'])
    @jwt_required
    def label_single(label_id):
        current_user, role = util.get_current_user(get_jwt_identity())
        if request.method == 'GET':
            try:
                if is_authorized(label_id, current_user, role):
                    links = []
                    links.append(Link('labels:list', '/labels/list'))
                    label = get_single_label(label_id)
                    if (label["sent"]) == False:
                        if role == 'user':
                            links.append(Link('label:patch', f'/labels/{label["id"]}'))
                            links.append(Link('label:delete', f'/labels/{label["id"]}'))
                        if role == 'courier':
                            links.append(Link('label:generate', '/parcels'))
                    return Document(data=label, links=links).to_json()
                else:
                    return make_response(jsonify({'error' : 'You have to be an owner or a courier to see this label'}), HTTPStatus.UNAUTHORIZED)
            except LabelNotFoundError as e:
                return make_response(jsonify({'error' : str(e)}), HTTPStatus.NOT_FOUND)
            except UserNotAuthorizedError as e:
                return make_response(jsonify({'error' : str(e)}), HTTPStatus.UNAUTHORIZED)

        if request.method == 'PATCH':
            if role == 'user':
                try:
                    if is_authorized(label_id, current_user, role):
                        links = []
                        links.append(Link('labels:list', '/labels/list'))
                        label = update_label(label_id,request.json)
                        if label['sent' == False]:
                            links.append(Link('label:patch', f'/labels/{label["id"]}'))
                            links.append(Link('label:delete', f'/labels/{label["id"]}'))
                        return Document(data=label, links=links).to_json(), HTTPStatus.OK
                    return make_response(jsonify({'error' : 'You can only edit labels that you own'}), HTTPStatus.UNAUTHORIZED)
                except LabelNotFoundError as e:
                    return make_response(jsonify({'error' : str(e)}), HTTPStatus.NOT_FOUND)
                except InvalidLabelError as e:
                    return make_response(jsonify({'error' : str(e)}), HTTPStatus.BAD_REQUEST)

        if request.method == 'DELETE':
            if role == 'user':
                try:
                    if is_authorized(label_id, current_user, role):
                        delete_label(label_id)
                        return make_response(''),HTTPStatus.NO_CONTENT
                    return make_response(jsonify({'error' : 'You can only delete labels that you own'}), HTTPStatus.UNAUTHORIZED)
                except LabelNotFoundError as e:
                    return make_response(jsonify({'error' : str(e)}), HTTPStatus.NOT_FOUND)
                except InvalidLabelError as e:
                    return make_response(jsonify({'error' : str(e)}), HTTPStatus.BAD_REQUEST)

    @label_bp.route('/list', methods=['GET', 'POST'])
    @jwt_required
    def label_list():
        current_user, role = util.get_current_user(get_jwt_identity())
        if request.method == 'GET':
            if role == 'user':
                links = []
                links.append('find', '/labels/<id>')
                labels = get_user_labels(current_user)
                return Document(embedded={'items' : Embedded(data=labels)}, links=links).to_json()
            elif role == 'courier':
                links = []
                links.append('find', '/labels/<id>')
                labels = get_all_labels()
                return Document(embedded={'items' : Embedded(data=labels)}, links=links).to_json()
            else:
                return make_response({'error': 'you have to be a sender or a courier to see labels'},HTTPStatus.UNAUTHORIZED)
        if request.method == 'POST':
            if db.hexists(f"user:{current_user}", "role"):
                role = db.hget(f"user:{current_user}", "role").decode()
            if role == 'user':
                label = {
                    "user" : current_user,
                    "name" : request.json.get("name"),
                    "address" : request.json.get("address"),
                    "box" : request.json.get("box"),
                    "dimensions" : request.json.get("dimensions")
                }
                try: 
                    links = []
                    label = validate_label(label)
                    label = save_label(label)
                    links.append(Link('labels:list', '/labels/list'))
                    links.append(Link('label:patch', f'/labels/{label["id"]}'))
                    links.append(Link('label:delete', f'/labels/{label["id"]}'))
                    return Document(data=label, links=links).to_json(), HTTPStatus.CREATED
                except InvalidLabelError as e:
                    return make_response(jsonify({'error' : str(e)}), HTTPStatus.BAD_REQUEST)

            else:
                return make_response({'error': 'you have to be a sender to create labels'}, HTTPStatus.UNAUTHORIZED)


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
        db.hset(f"label:{label['id']}", "sent", "False")
        return label

    def get_user_labels(user):
        items = []
        for key in db.scan_iter("label:*"):
            key = key.decode()
            if db.hget(key, "user").decode() == user:
                id = key.split(':')[1]
                label = get_single_label(id)
                link = Link('self', f'/labels/{id}')
                items.append(Embedded(data=label, links=[link]))
        return items

    def get_all_labels():
        items = []
        for key in db.scan_iter("label:*"):
            key = key.decode()
            id = key.split(':')[1]
            label = get_single_label(id)
            link = Link('self',f'/labels/{id}')
            items.append(Embedded(data=label, links=[link]))
        return items

    def get_single_label(id):
        if not is_label(id):
            raise LabelNotFoundError("No label with given id")
        
        key = f"label:{id}"
        label = {
            "id": key.split(':')[1],
            "name": db.hget(key, "name").decode(),
            "address": db.hget(key, "address").decode(),
            "box": db.hget(key, "box").decode(),
            "dimensions": db.hget(key, "dimensions").decode(),
            "user": db.hget(key, "user").decode(),
            "sent": db.hget(key, "sent").decode()
        }
        return label

    def is_authorized(id, current_user, role):
        if role == 'courier':
            return True
        if not is_label(id):
            raise LabelNotFoundError("No label with given id")
        user = db.hget(f"label:{id}", "user").decode()
        return user == current_user
    
    def is_label(id):
        return db.exists(f"label:{id}")

    def is_sent(label_id):
        return db.hget(f"label:{label_id}", "sent").decode() == 'True'

    def update_label(label_id, data):    
        if is_sent(label_id):
            raise InvalidLabelError("You can't edit label that is already sent")
        
        if not data:
            raise InvalidLabelError("No data to patch")
        
        updated_label = {
                "name" : data.get("name"),
                "address" : data.get("address"),
                "box" : data.get("box"),
                "dimensions" : data.get("dimensions")
            }
        for key, value in updated_label.items():
            if value:
                db.hset(f"label:{label_id}", key, value)
        return get_single_label(label_id)

    def delete_label(label_id):
        if is_sent(label_id):
            raise InvalidLabelError("You can't edit label that is already sent")
        if not is_label(label_id):
            raise LabelNotFoundError("No label with given id")
        db.delete(f"label:{label_id}")

    return label_bp