"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User, Roles
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from werkzeug.security import generate_password_hash, check_password_hash

api = Blueprint('api', __name__)


@api.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([user.serialize() for user in users]), 200


@api.route("/register", methods=["POST"])
def create_new_user():
    data = request.get_json()
    role_name = data.get('role')

    # Verificar si el usuario ya existe
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        return jsonify({'message': 'El usuario ya existe'}), 400

    # Encriptar contraseña
    hashed_password = generate_password_hash(data['password'], method='sha256')

    # Obtener el objeto Role correspondiente al nombre recibido
    role = Roles.query.filter_by(type=role_name).first()
    if not role:
        return jsonify({'message': 'Rol no encontrado'}), 400

    # Crear el nuevo usuario con la relación al rol
    new_user = User(
        username=data['username'],
        firstname=data['firstname'],
        lastname=data['lastname'],
        email=data['email'],
        password=hashed_password,
        role_id=role.id
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'user': new_user.serialize()}), 200


@api.route('/login', methods=['POST'])
def login():
    # Obtener los datos del usuario desde el cliente
    data = request.get_json()
    role_name = data.get('role')
    username = data.get('username')
    password = data.get('password')

    # Verificar si el usuario existe
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'Usuario o contraseña incorrectos'}), 401

    # Verificar si la contraseña es correcta
    if not check_password_hash(user.password, password):
        return jsonify({'message': 'Usuario o contraseña incorrectos'}), 401

    # Verificar si el role es correcto
    if user.role.type != role_name:
        return jsonify({'message': 'Rol incorrecto'}), 401

    # Generar un token JWT y devolverlo como respuesta
    access_token = create_access_token(identity=username)
    return jsonify({'access_token': access_token}), 200

    