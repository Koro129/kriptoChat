from flask import Blueprint, request, jsonify
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import jwt

# Inisialisasi Firebase Admin SDK
cred = credentials.Certificate("kriptochat.json")
firebase_admin.initialize_app(cred)

# Inisialisasi firestore database
db = firestore.client()
users_collection = db.collection('users')

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
    # Ambil data pengguna dari database berdasarkan username
    encrypted_username = encrypt(username)
    query = users_collection.where('username', '==', encrypted_username).limit(1).get()
    if query:
        user = query[0]
        private_key = decrypt(user.get('privateKey'))

        # Gunakan privateKey sebagai kunci rahasia untuk JWT
        payload = {'user1': username}  # Menggunakan "user1" sebagai kunci
        jwt_token = jwt.encode(payload, private_key, algorithm='HS256')
        return jwt_token

    return None

# def jwt_required(func):
#     @wraps(func)
#     def decorated_function(*args, **kwargs):
#         # Periksa header Authorization untuk mendapatkan token JWT
#         auth_header = request.headers.get('Authorization')
#         if auth_header:
#             auth_token = auth_header.split(' ')[1]
#             try:
#                 # Verifikasi token JWT
#                 jwt.decode(auth_token, algorithms='HS256')
#                 return func(*args, **kwargs)
#             except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError):
#                 return jsonify({'statusCode': 401, 'statusMessage': 'Token JWT tidak valid'})
#         else:
#             return jsonify({'statusCode': 401, 'statusMessage': 'Token JWT tidak ditemukan'})
#     return decorated_function

@bp.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    public_key = request.form.get('publicKey')
    private_key = request.form.get('privateKey')

    # Enkripsi username
    encrypted_username = encrypt(username)

    # Periksa apakah pengguna sudah terdaftar
    query = users_collection.where('username', '==', encrypted_username).limit(1).stream()
    if any(query):
        return jsonify({'statusCode': 400, 'statusMessage': 'Username sudah terdaftar'})

    # Enkripsi data kecuali password
    encrypted_public_key = encrypt(public_key)
    encrypted_private_key = encrypt(private_key)

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
def search():
    # Periksa parameter 'username' untuk mendapatkan username yang ingin dicari
    username = request.form.get('username')

    if username:
        # Enkripsi username
        encrypted_username = encrypt(username)

        # Periksa apakah pengguna ada dengan username yang cocok
        query = users_collection.where('username', '==', encrypted_username).limit(1).stream()
        if any(query):
            return jsonify({'statusCode': 200, 'statusMessage': 'Username ditemukan', 'username': username})

        return jsonify({'statusCode': 404, 'statusMessage': 'Username tidak ditemukan'})
    else:
        return jsonify({'statusCode': 400, 'statusMessage': 'Parameter username tidak ditemukan'})
