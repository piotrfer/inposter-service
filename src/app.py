import sys
from flask import Flask
import sender, label, courier, parcel
from os import getenv
from dotenv import load_dotenv
from redis import Redis
from flask_jwt_extended import JWTManager
from flask_hal import HAL
from flask_hal.link import Link
from flask_hal.document import Document, Embedded

app = Flask(__name__)
HAL(app)

load_dotenv()
SECRET_KEY = getenv("SECRET_KEY")
#SESSION_COOKIE_HTTPONLY = True
REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
JWT_SECRET_KEY = getenv("JWT_SECRET_KEY")

db = Redis(host=REDIS_HOST, port=6379, db=0)

try:
    db.info()
except ConnectionError:
    print('Couldn\'t establish connection with database. Process will terminate.')
    sys.exit(-1)

SESSION_TYPE = "redis"
SESSION_REDIS = db

app.config.from_object(__name__)

jwt = JWTManager(app)

app.register_blueprint(sender.construct(db), url_prefix='/sender')
app.register_blueprint(courier.construct(db), url_prefix='/courier')
app.register_blueprint(label.construct(db), url_prefix='/labels')
app.register_blueprint(parcel.construct(db), url_prefix='/parcels')

@app.route('/')
def index():
    links = []
    links.append(Link('sender', '/sender'))
    links.append(Link('courier', '/courier'))
    links.append(Link('labels', '/labels'))
    links.append(Link('parcels', '/parcels'))
    document = Document(data={}, links=links)
    return document.to_json()

if __name__ == '__main__':
    app.run(debug=True)