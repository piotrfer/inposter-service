from flask import Blueprint, make_response, request
from flask.json import jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from http import HTTPStatus
import util, uuid
from exceptions.LabelNotFoundError import LabelNotFoundError
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
            parcel = validate_parcel(request.data, current_user)
            parcel = save_parcel(parcel)
            update_label(request.data)
            return make_response(jsonify(parcel), HTTPStatus.CREATED)
        except LabelNotFoundError as e:
            return make_response(jsonify({'msg' : str(e)}), HTTPStatus.BAD_REQUEST)

    #get single parcel, update its status
    @parcel_bp.route('/<id>', methods=['PATCH'])
    @jwt_required
    def parcel_single(id):
        if request.method=='PATCH':
            #update parcel's status
            pass

    #get all your packages as a sender or courier
    @parcel_bp.route('/list', methods=['GET'])
    @jwt_required    
    def parcel_list():
        pass

    def validate_parcel(data, current_user):
        if not is_label(data.get('label')):
            raise LabelNotFoundError("No label with given id")
        parcel = {}
        parcel["label"] = data.get('label')
        parcel["courier"] = current_user
        parcel["status"] = "received"
        parcel["received"] = time()
        parcel["delivered"] = ""
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
        db.hset(f"label:{data.get('label')}", "sent", "true")

    def is_label(label_id):
        return db.exist(f"label:{label_id}")

    return parcel_bp