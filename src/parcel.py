from flask import Blueprint, make_response, request
from flask.json import jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from http import HTTPStatus
import util



def construct(db):
    parcel_bp = Blueprint('parcel_pages', __name__, static_folder='static')
    
    #generate parcel with label
    @parcel_bp.route('/create')
    @jwt_required
    def parcel_create():
        current_user, role = util.get_current_user(get_jwt_identity())
        if role != 'courier':
            return make_response(jsonify({'msg' : 'You have to be a courier to create a package'}), HTTPStatus.UNAUTHORIZED)
        return create_parcel(request.data, current_user)
        

    #get single parcel, update its status
    @parcel_bp.route('/<id>')
    @jwt_required
    def parcel_single(id):
        return 'parcel single'

    def create_parcel(data, current_user):
        pass
    

    return parcel_bp