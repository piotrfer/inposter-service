import sys
from flask import Flask
import sender, label, courier, parcel
from os import getenv
from dotenv import load_dotenv
from redis import Redis
from flask_jwt_extended import JWTManager


app = Flask(__name__)

load_dotenv()
SECRET_KEY = getenv("SECRET_KEY")
#SESSION_COOKIE_HTTPONLY = True
REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
JWT_SECRET_KEY = getenv("JWT_SECRET_KEY")

db = Redis(host='redis', port=6379, db=0)

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
#app.register_blueprint(parcel, url_prefix='/parcels')

@app.route('/')
def index():
    return 'index'

if __name__ == '__main__':
    app.run(debug=True)