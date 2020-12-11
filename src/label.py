from flask import Blueprint

label = Blueprint('label_pages', __name__, static_folder='static')

@label.route('/create')
def label_create():
    return 'label create'

#get single label, update and delete
@label.route('/<label_id>')
def label_single(label_id):
    return 'label single'

#get all labels with given user id
@label.route('/list/<user_id>')
def label_index(user_id):
    return 'label index'

#return list of all labels for courier
@label.route('/list')
def label_list():
    return 'label list'