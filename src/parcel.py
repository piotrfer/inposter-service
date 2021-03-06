from flask import Blueprint, make_response, request
from flask.json import jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from http import HTTPStatus
import util, uuid
from exceptions.LabelNotFoundError import LabelNotFoundError
from exceptions.ParcelNotFoundError import ParcelNotFoundError
from time import time
from flask_hal.document import Document, Embedded
from flask_hal.link import Link


def construct(db, rabbit):
    parcel_bp = Blueprint('parcel_pages', __name__, static_folder='static')
    
    @parcel_bp.route('/')
    def parcel_index():
        links = []
        links.append(Link('list', '/parcels/list'))
        links.append(Link('find', '/parcels/<id>'))
        return Document(data={}, links=links).to_json()


    #get single parcel, update its status
    @parcel_bp.route('/<id>', methods=['GET','PATCH'])
    @jwt_required
    def parcel_single(id):
        current_user, role = util.get_current_user(get_jwt_identity())
        if request.method=='PATCH':
            if role != 'courier':
                rabbit.send_message("Parcel - unathorized patch request")
                return make_response(jsonify({'error' : 'You have to be a courier to update parcels'}), HTTPStatus.BAD_REQUEST)     
            try:
                links = []
                parcel = update_parcel(id, request.json)
                links.append(Link('parcel:patch', f'/parcels/{id}'))
                links.append(Link('parcel:label', f'/labels/{parcel["label"]}'))
                return Document(data=parcel, links=links).to_json()
            except ParcelNotFoundError as e:
                return make_response(jsonify({'error' : str(e)}), HTTPStatus.NOT_FOUND)
        if request.method=='GET':
            try:
                if is_authorized(id, current_user, role):
                    parcel = get_single_parcel(id)
                    return make_response(jsonify(parcel), HTTPStatus.OK)
                else:
                    rabbit.send_message("Parcel - unathorized get request")
                    return make_response(jsonify({'error' : 'You have to be a courier or an owner of the parcel'}), HTTPStatus.UNAUTHORIZED)
            except ParcelNotFoundError as e:
                return make_response(jsonify({'error' : str(e)}), HTTPStatus.NOT_FOUND)

    #get all your packages as a sender or courier
    @parcel_bp.route('/list', methods=['GET', 'POST'])
    @jwt_required    
    def parcel_list():
        current_user, role = util.get_current_user(get_jwt_identity())
        if request.method == 'GET':
            links = []
            links.append(Link('find', '/parcels/<id>'))
            if role == 'courier':
                parcels = get_all_courier_parcels(current_user)
                return Document(embedded={'items' : Embedded(data=parcels)}, links=links).to_json()
            elif role == 'user':
                parcels = get_all_sender_parcels(current_user)
                return Document(embedded={'items' : Embedded(data=parcels)}, links=links).to_json()
            else:
                rabbit.send_message("Parcel - unathorized get list request")
                return make_response(jsonify({'error' : 'You have to be either a courier or a sender to see your parcels'}), HTTPStatus.UNAUTHORIZED)
        if request.method == 'POST':
            if role != 'courier':
                rabbit.send_message("Parcel - unathorized post request")
                return make_response(jsonify({'error' : 'You have to be a courier to create a package'}), HTTPStatus.UNAUTHORIZED)
            try:
                links = []
                parcel = generate_parcel(request.json, current_user)
                parcel = save_parcel(parcel)
                update_label(request.json)
                links.append(Link('self', f'/parcels/{parcel["id"]}'))
                links.append(Link('parcel:patch', f'/parcels/{id}'))
                links.append(Link('parcel:label', f'/labels/{parcel["label"]}'))
                return Document(data=parcel, links=links).to_json(), HTTPStatus.CREATED 
            except LabelNotFoundError as e:
                return make_response(jsonify({'error' : str(e)}), HTTPStatus.BAD_REQUEST)

    def generate_parcel(data, current_user):
        if not is_label(data.get('label')):
            raise LabelNotFoundError("No label with given id")
        parcel = {
            "label" : data.get('label'),
            "courier" : current_user,
            "status" : "received",
            "received" : time(),
            "delivered" : ""
        }
        return parcel
    
    def save_parcel(parcel):
        parcel['id'] = str(uuid.uuid4())
        db.hset(f"parcel:{parcel['id']}", "id", parcel.get('id'))
        db.hset(f"parcel:{parcel['id']}", "label", parcel.get('label'))
        db.hset(f"parcel:{parcel['id']}", "courier", parcel.get('courier'))
        db.hset(f"parcel:{parcel['id']}", " ", parcel.get('status'))
        db.hset(f"parcel:{parcel['id']}", "received", parcel.get('received'))
        db.hset(f"parcel:{parcel['id']}", "delivered", parcel.get('delivered'))
        rabbit.send_message(f"parcel id:{parcel.get('id')} created for courier: {parcel.get('courier')}", "inposter-packages")
        return parcel
    
    def update_label(data):
        if not is_label(data.get('label')):
            raise LabelNotFoundError("No label with given id")
        db.hset(f"label:{data.get('label')}", "sent", "True")

    def is_label(label_id):
        return db.exists(f"label:{label_id}")

    def is_parcel(parcel_id):
        return db.exists(f"parcel:{parcel_id}")

    def update_parcel(id, data):
        if not is_parcel(id):
            raise ParcelNotFoundError("No parcel with given id")
        updated_status = data.get("status")
        status_list = ["received", "in progress", "delivered"]
        if updated_status in status_list:
            
            db.hset(f"parcel:{id}", "status", updated_status)
            if updated_status == 'delivered':
                db.hset(f"parcel:{id}", "delivered", time())
                rabbit.send_message(f"parcel id:{id} was delivered")
            else:
                rabbit.send_message(f"parcel id:{id} updated to status: {updated_status}", "inposter-packages")
        return get_single_parcel(id)

    def get_single_parcel(id):
        if not is_parcel(id):
            raise ParcelNotFoundError("No parcel with given id")
        parcel = {
            "id" : id,
            "label" : db.hget(f"parcel:{id}", "label").decode(),
            "courier" : db.hget(f"parcel:{id}", "courier").decode(),
            "status" : db.hget(f"parcel:{id}", "status").decode(),
            "received" : db.hget(f"parcel:{id}", "received").decode(),
            "delivered" : db.hget(f"parcel:{id}", "delivered").decode()
        }
        return parcel

    def is_authorized(id, current_user, role):
        if role == 'courier':
            return True
        if not is_parcel(id):
            raise ParcelNotFoundError("No parcel with given id")
        label = db.hget(f"parcel:{id}", "label").decode()
        user = db.hget(f"label:{label}", "user").decode()
        return user == current_user
    
    def get_all_courier_parcels(current_user):
        items = []
        for key in db.scan_iter("parcel:*"):
            key = key.decode()
            if db.hget(key, "courier").decode() == current_user:
                id =  key.split(':')[1]
                parcel = get_single_parcel(id)
                link = Link('self', f'/parcels/{id}')
                items.append(Embedded(data=parcel, links=[link]))
        return items

    def get_all_sender_parcels(current_user):
        items = []
        for key in db.scan_iter("parcel:*"):
            key = key.decode()
            if db.hget(f"label:{db.hget(key, 'label').decode()}", "user").decode() == current_user:
                id =  key.split(':')[1]
                parcel = get_single_parcel(id)
                link = Link('self', f'/parcels/{id}')
                items.append(Embedded(data=parcel, links=[link]))
        return items

    return parcel_bp