from flask import Flask
from app.database import db
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

from app.models import User, Schedule, Payment
from app.api import api_bp
app.register_blueprint(api_bp)

if __name__ == '__main__':
    app.run()
