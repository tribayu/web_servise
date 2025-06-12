from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from functools import wraps
import jwt
import datetime
import uuid
import random
import os

app = Flask(__name__)
CORS(app)

# Konfigurasi MongoDB
app.config['MONGO_URI'] = 'mongodb://localhost:27017/basket'
mongo = PyMongo(app)
users_collection = mongo.db.user

# API Key
app.config['SECRET_KEY'] = 'ini_secret_key_jwt'
API_KEY = "api-key-1234"

#  Konfigurasi Email 
app.config['MAIL_SERVER'] = ''
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = ''    
app.config['MAIL_PASSWORD'] = ''         
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

# Middleware API Key
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('x-api-key')
        if not key or key != API_KEY:
            return jsonify({'status': 'gagal', 'pesan': 'API Key tidak valid'}), 401
        return f(*args, **kwargs)
    return decorated

# Middleware JWT
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

# REGISTER - Kirim OTP
@app.route('/register', methods=['POST'])
@require_api_key
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'status': 'gagal', 'pesan': 'Name, email dan password wajib diisi'}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({'status': 'gagal', 'pesan': 'Email sudah terdaftar'}), 400

    hashed_password = generate_password_hash(password)
    otp = str(random.randint(100000, 999999))

    users_collection.insert_one({
        'name': name,
        'email': email,
        'password': hashed_password,
        'otp': otp,
        'verified': False
    })

    try:
        msg = Message('Kode OTP Registrasi',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"Halo {name},\n\nKode OTP kamu adalah: {otp}\nMasukkan kode ini untuk menyelesaikan proses pendaftaran.\n\nTerima kasih."
        mail.send(msg)
    except Exception as e:
        return jsonify({'status': 'gagal', 'pesan': 'Gagal mengirim OTP', 'error': str(e)}), 500

    return jsonify({'status': 'berhasil', 'pesan': 'Akun dibuat. OTP dikirim ke email'}), 201

# VERIFIKASI OTP
@app.route('/verify-otp', methods=['POST'])
@require_api_key
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp_input = data.get('otp')

    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'status': 'gagal', 'pesan': 'User tidak ditemukan'}), 404

    if user.get('otp') == otp_input:
        users_collection.update_one({'email': email}, {
            '$set': {'verified': True},
            '$unset': {'otp': ""}
        })
        return jsonify({'status': 'berhasil', 'pesan': 'OTP valid. Akun diverifikasi'}), 200
    else:
        return jsonify({'status': 'gagal', 'pesan': 'OTP salah'}), 400

# LOGIN
@app.route('/login', methods=['POST'])
@require_api_key
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({'status': 'gagal', 'pesan': 'Autentikasi Basic Auth diperlukan'}), 401

    user = users_collection.find_one({'email': auth.username})
    if not user or not check_password_hash(user['password'], auth.password):
        return jsonify({'status': 'gagal', 'pesan': 'Email atau password salah'}), 401

    if not user.get('verified', False):
        return jsonify({'status': 'gagal', 'pesan': 'Akun belum diverifikasi. Silakan cek email Anda.'}), 403

    token = jwt.encode({
        'email': user['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=3)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'status': 'berhasil', 'token': token})


@app.route('/protected', methods=['GET'])
@require_api_key
@token_required
def protected(current_user):
    return jsonify({'status': 'berhasil', 'pesan': 'Token valid', 'email': current_user['email']})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
