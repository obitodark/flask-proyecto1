from os import getenv
from flask import Flask
from flask_restx import Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from config import config_env
from flask_cors import CORS

app = Flask(__name__)
app.config.from_object(config_env[getenv('FLASK_ENV')])

authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}

api = Api(
    app,
    title='Boilerplate Flask',
    version='0.0.1',
    description='Endpoints de nuestro boilerplate',
    authorizations=authorizations,
    doc='/swagger-ui'
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

jwt = JWTManager(app)
mail = Mail(app)
CORS(app)