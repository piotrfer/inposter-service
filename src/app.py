import sys

from flask import Flask
from sender import sender
from courier import courier
from parcel import parcel
from label import label
from os import getenv
from dotenv import load_dotenv
from redis import Redis



app = Flask(__name__)

load_dotenv()
SECRET_KEY = getenv("SECRET_KEY")
#SESSION_COOKIE_HTTPONLY = True
REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")

db = Redis(host='redis', port=6379, db=0)

try:
    db.info()
except ConnectionError:
    print('Couldn\'t establish connection with database. Process will terminate.')
    sys.exit(-1)

SESSION_TYPE = "redis"
SESSION_REDIS = db

#app.config.from_object(__name__)
app.secret_key = getenv('SECRET_KEY')
app.register_blueprint(sender, url_prefix='/sender')
app.register_blueprint(courier, url_prefix='/courier')
app.register_blueprint(label, url_prefix='/label')
app.register_blueprint(parcel, url_prefix='/parcel')

@app.route('/')
def index():
    return 'index'

@app.route('/sender/singup')
def sender_signup():
    return 'sender signup'

@app.route('/sender/login')
def sender_login():
    return 'sender login'

@app.route('/sender/logout')
def sender_logout():
    return 'sender logout'

if __name__ == '__main__':
    app.run(debug=True)