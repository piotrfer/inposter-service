from flask import Blueprint, make_response, request
from flask.json import jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from http import HTTPStatus
import util, uuid
from exceptions.LabelNotFoundError import LabelNotFoundError
from exceptions.ParcelNotFoundError import ParcelNotFoundError
from time import time


def construct(db):
    parcel_bp = Blueprint('parcel_pages', __name__, static_folder='static')
    
    #generate parcel with label
    @parcel_bp.route('/create', methods=['POST'])
    @jwt_required
    def parcel_create():
        current_user, role = util.get_current_user(get_jwt_identity())
        if role != 'courier':
            return make_response(jsonify({'msg' : 'You have to be a courier to create a package'}), HTTPStatus.UNAUTHORIZED)
        try:
            parcel = generate_parcel(request.data, current_user)
            parcel = save_parcel(parcel)
            update_label(request.data)
            return make_response(jsonify(parcel), HTTPStatus.CREATED)
        except LabelNotFoundError as e:
            return make_response(jsonify({'msg' : str(e)}), HTTPStatus.BAD_REQUEST)

    #get single parcel, update its status
    @parcel_bp.route('/<id>', methods=['PATCH'])
    @jwt_required
    def parcel_single(id):
        current_user, role = get_jwt_identity()
        if request.method=='PATCH':
            if role != 'courier':
                return make_response(jsonify({'msg' : 'You have to be a courier to update parcels'}), HTTPStatus.BAD_REQUEST)
            try:
                parcel = update_parcel(id, request.data)
                return make_response(jsonify(parcel), HTTPStatus.OK)
            except ParcelNotFoundError as e:
                return make_response(jsonify({'msg' : str(e)}), HTTPStatus.NOT_FOUND)
        if request.method=='GET':
            try:
                if is_authorized(id, current_user, role):
                    parcel = get_single_parcel(id)
                    return make_response(jsonify(parcel), HTTPStatus.OK)
                else:
                    return make_response(jsonify({'msg' : 'You have to be a courier or an owner of the parcel'}), HTTPStatus.UNAUTHORIZED)
            except ParcelNotFoundError as e:
                return make_response(jsonify({'msg' : str(e)}), HTTPStatus.NOT_FOUND)

    #get all your packages as a sender or courier
    @parcel_bp.route('/list', methods=['GET'])
    @jwt_required    
    def parcel_list():
        current_user, role = get_jwt_identity()
        if role == 'courier':
            parcels = get_all_courier_parcels(current_user)
            return make_response(jsonify(parcels), HTTPStatus.OK)
        elif role == 'user':
            parcels = get_all_sender_parcels(current_user)
            return make_response(jsonify(parcels), HTTPStatus.OK)
        else:
            return make_response(jsonify({'msg' : 'You have to be either a courier or a sender to see your parcels'}), HTTPStatus.UNAUTHORIZED)

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
        parcel['id'] = uuid.uuid4()
        db.hset(f"parcel:{parcel['id']}", "id", parcel.get('id'))
        db.hset(f"parcel:{parcel['id']}", "label", parcel.get('label'))
        db.hset(f"parcel:{parcel['id']}", "courier", parcel.get('courier'))
        db.hset(f"parcel:{parcel['id']}", "status", parcel.get('status'))
        db.hset(f"parcel:{parcel['id']}", "received", parcel.get('received'))
        db.hset(f"parcel:{parcel['id']}", "delivered", parcel.get('delivered'))
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
        if updated_status:
           db.hset(f"parcel:{id}", "status", updated_status)
           if updated_status == 'delivered':
               db.hset(f"parcel{id}", "delivered", time())
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
        parcels = []
        for key in db.scan_iter("parcel:*"):
            key = key.decode()
            if db.hget(key, "courier").decode() == current_user:
                id =  key.split(':')[1]
                parcel = get_single_parcel(id)
                parcels.append(parcel)
        return parcels

    def get_all_sender_parcels(current_user):
        parcels = []
        for key in db.scan_iter("parcel:*"):
            key = key.decode()
            if db.hget(f"label:{db.hget(key, 'label').decode()}", "user").decode() == current_user:
                id =  key.split(':')[1]
                parcel = get_single_parcel(id)
                parcels.append(parcel)
        return parcels

    return parcel_bp