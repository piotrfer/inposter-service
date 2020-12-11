from flask import Blueprint

parcel = Blueprint('parcel_pages', __name__, static_folder='static')

@parcel.route('/')
def parcel_index():
    return 'parcel_index'

#generate parcel with label
@parcel.route('/create')
def parcel_create():
    return 'parcel create'

#get single parcel, update its status
@parcel.route('/<id>')
def parcel_single(id):
    return 'parcel single'