# app.py
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
import os
from bson import ObjectId

app = Flask(__name__)
CORS(app)

# Konfigurasi MongoDB
app.config['MONGO_URI'] = 'mongodb://localhost:27017/basket'
mongo = PyMongo(app)
users_collection = mongo.db.user


# Secret Key untuk JWT dan API Key 
app.config['SECRET_KEY'] = 'ini_secret_key_jwt'
API_KEY = "api-key-1234"

# Middleware: validasi API Key
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('x-api-key')
        if not key or key != API_KEY:
            return jsonify({'status': 'gagal', 'pesan': 'API Key tidak valid'}), 401
        return f(*args, **kwargs)
    return decorated

# Middleware: validasi JWT Bearer Token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            bearer = request.headers['Authorization']
            token = bearer.replace('Bearer ', '')

        if not token:
            return jsonify({'status': 'gagal', 'pesan': 'Token tidak ditemukan'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_collection.find_one({'email': data['email']})
        except:
            return jsonify({'status': 'gagal', 'pesan': 'Token tidak valid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Endpoint register
@app.route('/register', methods=['POST'])
@require_api_key
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'status': 'gagal', 'pesan': 'name, Email dan password wajib diisi'}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({'status': 'gagal', 'pesan': 'Email sudah terdaftar'}), 400

    hashed_password = generate_password_hash(password)
    users_collection.insert_one({
        'email': email,
        'password': hashed_password
    })

    return jsonify({'status': 'berhasil', 'pesan': 'Akun berhasil dibuat'}), 201

# Endpoint login dengan Basic Auth
@app.route('/login', methods=['POST'])
@require_api_key
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({'status': 'gagal', 'pesan': 'Autentikasi Basic Auth diperlukan'}), 401

    user = users_collection.find_one({'email': auth.username})
    if not user or not check_password_hash(user['password'], auth.password):
        return jsonify({'status': 'gagal', 'pesan': 'Email atau password salah'}), 401

    token = jwt.encode({
        'email': user['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=3)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'status': 'berhasil', 'token': token})

# Endpoint yang dilindungi
@app.route('/protected', methods=['GET'])
@require_api_key
@token_required
def protected(current_user):
    return jsonify({'status': 'berhasil', 'pesan': 'Token valid', 'email': current_user['email']})


if __name__ == '__main__':
   app.run(host='0.0.0.0', port=5000, debug=True)

