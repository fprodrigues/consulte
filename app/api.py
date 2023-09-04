from datetime import datetime
from flask import Blueprint, jsonify, request, abort, make_response
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from app.models import User, Schedule, Payment
from app.database import db
import bcrypt

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')
jwt = JWTManager()

@jwt.user_loader_callback_loader
def user_loader_callback(identity):
    return User.query.get(identity)

@api_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        access_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))

        return jsonify({
            'access_token': access_token,
            'user_id': user.id,
        }), 200
    return jsonify({'message': 'Invalid credentials'}), 401


# Rota para criar um usuário (administrador/dentista)
@api_bp.route('/users', methods=['POST'])
@jwt_required()
def create_user():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    if not current_user:
        return jsonify({'message': 'User not found'}), 404
    if current_user.role != 'dentista':
        return jsonify({'message': 'Access denied. Only dentists can create users.'}), 403

    data = request.get_json()
    new_username = data.get('username')
    new_password = data.get('password')
    new_role = data.get('role')

    if not new_username or not new_password or not new_role:
        return jsonify({'message': 'Username, password, and role are required fields'}), 400

    existing_user = User.query.filter_by(username=new_username).first()
    if existing_user:
        return jsonify({'message': 'Username already exists'}), 409

    new_user = User(username=new_username, role=new_role)
    new_user.set_password(new_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@api_bp.route('/schedule', methods=['POST'])
@jwt_required()
def create_schedule():
    user_id = get_jwt_identity()
    data = request.get_json()
    date_time_str = data.get('date_time')
    try:
        date_time = datetime.strptime(date_time_str, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return jsonify({'message': 'Invalid date format'}), 400
    if date_time < datetime.now() or date_time.time() < datetime.strptime('08:00:00', '%H:%M:%S').time():
        return jsonify({'message': 'Invalid date or time'}), 400
    existing_schedule = Schedule.query.filter_by(user_id=user_id, date_time=date_time).first()
    if existing_schedule:
        return jsonify({'message': 'Schedule already exists'}), 409
    schedule = Schedule(user_id=user_id, date_time=date_time)
    db.session.add(schedule)
    db.session.commit()
    return jsonify({'message': 'Schedule created'}), 201

@api_bp.route('/schedules', methods=['GET'])
@jwt_required()
def get_schedules():
    user_id = get_jwt_identity()
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)
    schedules = Schedule.query.filter_by(user_id=user_id).paginate(page, per_page, False)
    if not schedules.items:
        return jsonify({'message': 'No schedules found'}), 404
    schedules_data = [{'id': schedule.id, 'date_time': schedule.date_time} for schedule in schedules.items]
    return jsonify({'schedules': schedules_data, 'total': schedules.total, 'current_page': schedules.page}), 200

@api_bp.route('/schedules/history', methods=['GET'])
@jwt_required()
def get_schedule_history():
    user_id = get_jwt_identity()
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)
    schedules = Schedule.query.filter(
    Schedule.user_id == user_id,
    Schedule.date_time < datetime.now()
    ).paginate(page, per_page, False)
    if not schedules.items:
        return jsonify({'message': 'No schedule history found'}), 404
    schedules_data = [{'id': schedule.id, 'date_time': schedule.date_time} for schedule in schedules.items]
    return jsonify({'schedules_history': schedules_data, 'total': schedules.total, 'current_page': schedules.page}), 200
