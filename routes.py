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
messages_collection = db.collection('messages')

# Inisialisasi blueprint
bp = Blueprint('routes', __name__)

# Konfigurasi enkripsi AES
key = b'x\x800\xe4\x97\x9e%]LE\x7f8\x0e\xae\xb2\xd6\xa4p\xc3Ug\xcc\xaaw\xe8\xd5\xd6\x1e\x18\xa2\xd6\x91'  # Ganti dengan kunci rahasia yang kuat
cipher = AES.new(key, AES.MODE_ECB)

JWTkey = "iOA_yJCQUPl2Ath4KJmWouI8lb-ZWiyUxzv_J1q0r-WRLZda4g4Fvt_tBnFNhTXCHcaWYHYbHpfBK2oIwt9i8PtE0rE5_HxnwVEBZWr2veP6fMFqKmUnmHw-VKPiXEehV77RHmNkuBcahMo5beJf636_0gk5mSsBSOeagFtZaWg"

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
    user_query = users_collection.where('username', '==', encrypt(username_request)).limit(1).stream()
    if not any(user_query):
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

@bp.route('/getChat', methods=['GET'])
@jwt_required
def get_chat():
    # Mendapatkan user1 dari token JWT
    jwt_token = request.headers.get('Authorization').split(' ')[1]
    user1 = get_user_from_jwt(jwt_token)

    # Enkripsi username user1
    encrypted_user1 = encrypt(user1)

    # Mencari chat dengan idUser1 atau idUser2 berisi user1
    query = chat_collection.where('idUser1', 'in', [encrypted_user1]).stream()
    chats = []
    for chat in query:
        idUser2 = decrypt(chat.get('idUser2'))
        updatedAt = chat.get('updatedAt').strftime("%Y-%m-%d %H:%M:%S")
        chats.append({'idChat': chat.id, 'username': idUser2, 'updatedAt': updatedAt})

    query = chat_collection.where('idUser2', 'in', [encrypted_user1]).stream()
    for chat in query:
        idUser1 = decrypt(chat.get('idUser1'))
        updatedAt = chat.get('updatedAt').strftime("%Y-%m-%d %H:%M:%S")
        chats.append({'idChat': chat.id, 'username': idUser1, 'updatedAt': updatedAt})

    return jsonify({'statusCode': 200, 'statusMessage': 'Success', 'chats': chats})

@bp.route('/sendMessage', methods=['POST'])
@jwt_required
def send_message():
    # Mendapatkan data dari JWT
    jwt_token = request.headers.get('Authorization').split(' ')[1]
    id_sender = get_user_from_jwt(jwt_token)

    # Mendapatkan data dari request
    id_chat = request.form.get('idChat')
    message_in = request.form.get('messageIn')
    message_out = request.form.get('messageOut')

    # Mengecek apakah id_chat ada dalam koleksi chats
    chat_doc = chat_collection.document(id_chat).get()
    if not chat_doc.exists:
        return jsonify({'statusCode': 404, 'statusMessage': 'Chat not found'})

    # Mengupdate updatedAt pada chat
    chat_doc.reference.update({'updatedAt': datetime.now()})

    # Menyimpan data message ke koleksi messages
    new_message = {
        'idChat': id_chat,
        'idSender': encrypt(id_sender),
        'messageIn': encrypt(message_in),
        'messageOut': encrypt(message_out),
        'timestamp': datetime.now()
    }
    messages_collection.add(new_message)

    return jsonify({'statusCode': 200, 'statusMessage': 'Message sent successfully'})

@bp.route('/listMessage', methods=['GET'])
@jwt_required
def list_message():
    # Get user1 from JWT token
    jwt_token = request.headers.get('Authorization').split(' ')[1]
    user1 = get_user_from_jwt(jwt_token)

    # Get idChat from form data
    id_chat = request.args.get('idChat')
    print(id_chat)

    # Check if chat document exists
    chat_doc = chat_collection.document(id_chat).get()
    if not chat_doc.exists:
        return jsonify({'statusCode': 404, 'statusMessage': 'Chat not found'})


    # Get chat data
    chat_data = chat_doc.to_dict()
    encrypted_id_user1 = chat_data['idUser1']
    encrypted_id_user2 = chat_data['idUser2']

    # Decrypt idUser1 and idUser2
    id_user1 = decrypt(encrypted_id_user1)
    id_user2 = decrypt(encrypted_id_user2)

    # Ensure user1 and user2 are as per the rule
    if user1 == id_user1:
        user1, user2 = id_user2, id_user1
    elif user1 == id_user2:
        user1, user2 = id_user1, id_user2
    else:
        return jsonify({'statusCode': 403, 'statusMessage': 'Forbidden'})

    # Retrieve user2's document from the user collection
    user2_query = users_collection.where('username', '==', encrypt(user2)).limit(1).stream()
    user2_doc = next(user2_query, None)
    if not user2_doc:
        return jsonify({'statusCode': 404, 'statusMessage': 'User not found'})
    user2_data = user2_doc.to_dict()
    user2_public_key = decrypt(user2_data.get('publicKey'))

    # Retrieve user1's document from the user collection
    user1_query = users_collection.where('username', '==', encrypt(user1)).limit(1).stream()
    user1_doc = next(user1_query, None)
    if not user1_doc:
        return jsonify({'statusCode': 404, 'statusMessage': 'User not found'})
    user1_data = user1_doc.to_dict()
    user1_private_key = decrypt(user1_data.get('privateKey'))
    user1_public_key = decrypt(user1_data.get('publicKey'))

    # Get all messages with the same idChat
    messages_query = messages_collection.where('idChat', '==', id_chat).stream()
    messages = [message_doc.to_dict() for message_doc in messages_query]

    # Decrypt messages (except for the "idChat" field)
    decrypted_messages = []
    for message in messages:
        decrypted_message = message.copy()  # Copy the message dictionary
        for key, value in message.items():
            if key not in ['idChat', 'timestamp']:
                decrypted_message[key] = decrypt(value)
        decrypted_messages.append(decrypted_message)

    decrypted_messages.sort(key=lambda x: x['timestamp'])

    # Prepare response with user2's public key, user1's private key, and all messages
    response_data = {
        'statusCode': 200,
        'statusMessage': 'list messages success',
        'user2Key': user2_public_key,
        'user1PrivateKey': user1_private_key,
        'user1PublicKey': user1_public_key,
        'messages': decrypted_messages
    }

    return jsonify(response_data)
