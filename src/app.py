import sys
from flask import Flask
import sender, label, courier, parcel
from os import getenv
from dotenv import load_dotenv
from redis import from_url
from flask_jwt_extended import JWTManager
from flask_hal import HAL
from flask_hal.link import Link
from flask_hal.document import Document
from redis import Redis
from rabbit import Rabbit

app = Flask(__name__)
HAL(app)

load_dotenv()
SECRET_KEY = getenv("SECRET_KEY")
#SESSION_COOKIE_HTTPONLY = True
JWT_SECRET_KEY = getenv("JWT_SECRET_KEY")
REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
JWT_SECRET_KEY = getenv("JWT_SECRET_KEY")
RABBIT_HOST = getenv("RABBIT_HOST")
RABBIT_VH = getenv("RABBIT_VH")
RABBIT_USERNAME = getenv("RABBIT_USERNAME")
RABBIT_PASSWORD = getenv("RABBIT_PASSWORD")
RABBIT_QUEUE = getenv("RABBIT_QUEUE")

db = Redis(host=REDIS_HOST, port=6379, db=0)
rabbit = Rabbit(
    host=RABBIT_HOST,
    virtual_host=RABBIT_VH,
    username=RABBIT_USERNAME,
    password=RABBIT_PASSWORD, 
    queues = [
        "inposter-messages",
        "inposter-packages"
    ])

try:
    db.info()
except ConnectionError:
    rabbit.send_message("The connection with database couldn't be established.")
    print('Couldn\'t establish connection with database. Process will terminate.')
    sys.exit(-1)

SESSION_TYPE = "redis"
SESSION_REDIS = db

app.config.from_object(__name__)

jwt = JWTManager(app)

app.register_blueprint(sender.construct(db, rabbit), url_prefix='/sender')
app.register_blueprint(courier.construct(db, rabbit), url_prefix='/courier')
app.register_blueprint(label.construct(db, rabbit), url_prefix='/labels')
app.register_blueprint(parcel.construct(db, rabbit), url_prefix='/parcels')

@app.after_request
def disable_cors(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "*")
    response.headers.add("Access-Control-Allow-Methods", "*")
    return response

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