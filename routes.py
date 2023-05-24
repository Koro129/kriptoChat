from flask import Blueprint, request, jsonify
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from functools import wraps
from datetime import datetime
import rsa
import hashlib
import base64
import jwt

# Inisialisasi Firebase Admin SDK
cred = credentials.Certificate("kriptochat.json")
firebase_admin.initialize_app(cred)

# Inisialisasi firestore database
db = firestore.client()
users_collection = db.collection('users')
chat_collection = db.collection('chats')

# Inisialisasi blueprint
bp = Blueprint('routes', __name__)

# Konfigurasi enkripsi AES
key = b'x\x800\xe4\x97\x9e%]LE\x7f8\x0e\xae\xb2\xd6\xa4p\xc3Ug\xcc\xaaw\xe8\xd5\xd6\x1e\x18\xa2\xd6\x91'  # Ganti dengan kunci rahasia yang kuat
cipher = AES.new(key, AES.MODE_ECB)

def encrypt(text):
    encrypted_text = cipher.encrypt(pad(text.encode(), AES.block_size))
    return base64.b64encode(encrypted_text).decode()

def decrypt(encrypted_text):
    decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text))
    return unpad(decrypted_text, AES.block_size).decode()

def hash_password(password):
    salted_password = '5027211056' + password + '5027211024'
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed_password

def generate_jwt(username):
    JWTkey = "iOA_yJCQUPl2Ath4KJmWouI8lb-ZWiyUxzv_J1q0r-WRLZda4g4Fvt_tBnFNhTXCHcaWYHYbHpfBK2oIwt9i8PtE0rE5_HxnwVEBZWr2veP6fMFqKmUnmHw-VKPiXEehV77RHmNkuBcahMo5beJf636_0gk5mSsBSOeagFtZaWg"
    payload = {'user1': username}
    jwt_token = jwt.encode(payload, JWTkey, algorithm='HS256')
    return jwt_token

def jwt_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        # Periksa header Authorization untuk mendapatkan token JWT
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(' ')[1]
            try:
                JWTkey = "iOA_yJCQUPl2Ath4KJmWouI8lb-ZWiyUxzv_J1q0r-WRLZda4g4Fvt_tBnFNhTXCHcaWYHYbHpfBK2oIwt9i8PtE0rE5_HxnwVEBZWr2veP6fMFqKmUnmHw-VKPiXEehV77RHmNkuBcahMo5beJf636_0gk5mSsBSOeagFtZaWg"
                # Verifikasi token JWT
                jwt.decode(auth_token, JWTkey, algorithms='HS256')
                return func(*args, **kwargs)
            except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError):
                return jsonify({'statusCode': 401, 'statusMessage': 'Token JWT tidak valid'})
        else:
            return jsonify({'statusCode': 401, 'statusMessage': 'Token JWT tidak ditemukan'})
    return decorated_function

def get_user_from_jwt(jwt_token):
    try:
        JWTkey = "iOA_yJCQUPl2Ath4KJmWouI8lb-ZWiyUxzv_J1q0r-WRLZda4g4Fvt_tBnFNhTXCHcaWYHYbHpfBK2oIwt9i8PtE0rE5_HxnwVEBZWr2veP6fMFqKmUnmHw-VKPiXEehV77RHmNkuBcahMo5beJf636_0gk5mSsBSOeagFtZaWg"
        decoded_token = jwt.decode(jwt_token, JWTkey, algorithms=['HS256'])
        user = decoded_token.get('user1')
        return user
    except jwt.exceptions.InvalidTokenError:
        return None

# route 
@bp.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    # Enkripsi username
    encrypted_username = encrypt(username)

    # Periksa apakah pengguna sudah terdaftar
    query = users_collection.where('username', '==', encrypted_username).limit(1).stream()
    if any(query):
        return jsonify({'statusCode': 400, 'statusMessage': 'Username sudah terdaftar'})

    # Generate pasangan kunci RSA baru
    public_key, private_key = rsa.newkeys(2048)

    # Konversi kunci RSA ke format string
    public_key_str = public_key.save_pkcs1().decode()
    private_key_str = private_key.save_pkcs1().decode()
    # print('public_key = '+public_key_str + '\nprivate_key = '+private_key_str)

    # Enkripsi kunci RSA
    encrypted_public_key = encrypt(public_key_str)
    encrypted_private_key = encrypt(private_key_str)

    # Hash password
    hashed_password = hash_password(password)

    # Buat pengguna baru
    new_user = {
        'username': encrypted_username,
        'password': hashed_password,
        'publicKey': encrypted_public_key,
        'privateKey': encrypted_private_key
    }
    users_collection.add(new_user)

    return jsonify({'statusCode': 200, 'statusMessage': 'Registrasi berhasil'})

@bp.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Enkripsi username
    encrypted_username = encrypt(username)

    # Periksa apakah pengguna ada dan passwordnya cocok
    query = users_collection.where('username', '==', encrypted_username).limit(1).get()
    if query:
        user = query[0]
        stored_password = user.get('password')

        # Verifikasi password
        if stored_password == hash_password(password):
            # Generate token JWT
            jwt_token = generate_jwt(username)
            if jwt_token:
                return jsonify({'statusCode': 200, 'statusMessage': 'Login berhasil', 'jwt_token': jwt_token})
            else:
                return jsonify({'statusCode': 500, 'statusMessage': 'Gagal membuat JWT'})

    return jsonify({'statusCode': 401, 'statusMessage': 'Login gagal'})

@bp.route('/search', methods=['POST'])
@jwt_required
def search():
    # Ambil user1 dari token JWT
    jwt_token = request.headers.get('Authorization').split(' ')[1]
    user_from_jwt = get_user_from_jwt(jwt_token)

    # Periksa parameter 'username' untuk mendapatkan username yang ingin dicari
    username = request.form.get('username')

    if username:
        # Periksa apakah username dari permintaan sama dengan user1 dalam token JWT
        if user_from_jwt == username:
            return jsonify({'statusCode': 404, 'statusMessage': 'Username tidak ditemukan'})

        # Enkripsi username
        encrypted_username = encrypt(username)

        # Periksa apakah pengguna ada dengan username yang cocok
        query = users_collection.where('username', '==', encrypted_username).limit(1).stream()
        if any(query):
            return jsonify({'statusCode': 200, 'statusMessage': 'Username ditemukan', 'username': username})

    return jsonify({'statusCode': 400, 'statusMessage': 'Parameter username tidak ditemukan'})

@bp.route('/add', methods=['POST'])
@jwt_required
def add_chat():
    # Mendapatkan data dari JWT
    jwt_token = request.headers.get('Authorization').split(' ')[1]
    username_jwt = get_user_from_jwt(jwt_token)

    # Mendapatkan username dari parameter request
    username_request = request.form.get('username')

    # Mendapatkan ID pengguna dari database berdasarkan username
    id_user1 = username_jwt
    id_user2 = username_request

    # Periksa apakah pengguna dengan username_request ada di database
    if not id_user2:
        return jsonify({'statusCode': 404, 'statusMessage': 'User not found'})

    # Enkripsi ID pengguna
    encrypted_id_user1 = encrypt(id_user1)
    encrypted_id_user2 = encrypt(id_user2)

    # Periksa apakah pasangan idUser1 dan idUser2 sudah ada dalam tabel chat
    chat_query = chat_collection.where('idUser1', 'in', [encrypted_id_user1, encrypted_id_user2]).where('idUser2', 'in', [encrypted_id_user1, encrypted_id_user2]).limit(1).stream()
    if any(chat_query):
        return jsonify({'statusCode': 409, 'statusMessage': 'Chat already exists'})

    # Menyimpan data chat ke dalam tabel
    new_chat = {
        'idUser1': encrypted_id_user1,
        'idUser2': encrypted_id_user2,
        'createdAt': datetime.now(),
        'updatedAt': datetime.now()
    }
    chat_collection.add(new_chat)

    return jsonify({'statusCode': 200, 'statusMessage': 'Chat added successfully'})
