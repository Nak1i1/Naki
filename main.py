import eel
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId
import logging
import os
import base64
from pathlib import Path
import gridfs
import secrets
import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


CURVE = ec.SECP256R1()
HKDF_INFO = b'messenger_key_derivation'
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Создание ключа из пароля пользователя"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_private_key(private_key_pem: str, password: str) -> dict:
    """Шифрование приватного ключа"""
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    
    encrypted_key = fernet.encrypt(private_key_pem.encode())
    
    return {
        'encrypted_private_key': base64.b64encode(encrypted_key).decode(),
        'salt': base64.b64encode(salt).decode()
    }

def decrypt_private_key(encrypted_data: dict, password: str) -> str:
    """Дешифрование приватного ключа"""
    salt = base64.b64decode(encrypted_data['salt'])
    encrypted_key = base64.b64decode(encrypted_data['encrypted_private_key'])
    
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    
    return fernet.decrypt(encrypted_key).decode()

try:
    client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client['messenger_db']
    users_collection = db['users']
    messages_collection = db['messages']
    shared_keys_collection = db['shared_keys']
    ecdh_keys_collection = db['ecdh_keys']
    logger.info("Успешное подключение к MongoDB")
except Exception as e:
    logger.error(f"Ошибка подключения к MongoDB: {e}")
    raise

collections = ['users', 'messages', 'shared_keys', 'ecdh_keys']
for collection in collections:
    if collection not in db.list_collection_names():
        db.create_collection(collection)

messages_collection.create_index([("sender_id", 1), ("receiver_id", 1)])
messages_collection.create_index([("timestamp", 1)])

try:
    users_collection.drop_index("email_1")
except:
    pass

users_collection.create_index([("email_hash", 1)], unique=True)
users_collection.create_index([("nickname", 1)])

def get_local_time():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

@eel.expose
def get_current_time():
    """Получение текущего времени для клиента"""
    return datetime.now().astimezone().isoformat()

eel.init("web")




@eel.expose
def generate_ecdh_keypair(user_id, password):
    """Генерация ECDH ключевой пары с шифрованием приватного ключа"""
    try:
        # Генерируем приватный ключ
        private_key = ec.generate_private_key(CURVE)
        public_key = private_key.public_key()
        
        # Сериализуем ключи
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Шифруем приватный ключ
        encrypted_private = encrypt_private_key(private_pem, password)
        
        # Сохраняем в базу
        ecdh_keys_collection.update_one(
            {"user_id": ObjectId(user_id)},
            {
                "$set": {
                    "encrypted_private_key": encrypted_private['encrypted_private_key'],
                    "salt": encrypted_private['salt'],
                    "public_key": public_pem,
                    "created_at": datetime.utcnow()
                }
            },
            upsert=True
        )
        
        logger.info(f"Ключевая пара сгенерирована для пользователя {user_id}")
        return {"success": True, "public_key": public_pem}
        
    except Exception as e:
        logger.error(f"Ошибка генерации ключей: {e}")
        return {"success": False, "message": str(e)}
    
@eel.expose
def get_decrypted_private_key(user_id, password):
    """Получение дешифрованного приватного ключа"""
    try:
        key_data = ecdh_keys_collection.find_one({"user_id": ObjectId(user_id)})
        if not key_data:
            return {"success": False, "message": "Ключи не найдены"}
        
        encrypted_data = {
            'encrypted_private_key': key_data['encrypted_private_key'],
            'salt': key_data['salt']
        }
        
        private_pem = decrypt_private_key(encrypted_data, password)
        return {"success": True, "private_key": private_pem}
        
    except Exception as e:
        logger.error(f"Ошибка дешифрования приватного ключа: {e}")
        return {"success": False, "message": "Неверный пароль"}
    
    

@eel.expose
def get_public_key(user_id):
    """Получение публичного ключа пользователя"""
    try:
        key_data = ecdh_keys_collection.find_one({"user_id": ObjectId(user_id)})
        if not key_data or 'public_key' not in key_data:
            return {"success": False, "message": "Публичный ключ не найден"}
        
        return {"success": True, "public_key": key_data['public_key']}
        
    except Exception as e:
        logger.error(f"Ошибка получения публичного ключа: {e}")
        return {"success": False, "message": str(e)}

@eel.expose
def compute_shared_secret(user_id, peer_public_key_pem):
    """Вычисление общего секрета между двумя пользователями"""
    try:
        # Получаем приватный ключ текущего пользователя
        key_data = ecdh_keys_collection.find_one({"user_id": ObjectId(user_id)})
        if not key_data or 'private_key' not in key_data:
            return {"success": False, "message": "Приватный ключ не найден"}
        
        # Загружаем приватный ключ
        private_key = serialization.load_pem_private_key(
            key_data['private_key'].encode('utf-8'),
            password=None
        )
        
        # Загружаем публичный ключ собеседника
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_pem.encode('utf-8')
        )
        
        # Вычисляем общий секрет
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Производим ключ с помощью HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 бит для AES-256
            salt=None,
            info=HKDF_INFO
        ).derive(shared_secret)
        
        # Сохраняем общий ключ в базе
        # ВАЖНО: Нужно получить peer_id из базы данных по публичному ключу
        peer_key_data = ecdh_keys_collection.find_one({"public_key": peer_public_key_pem})
        if not peer_key_data:
            return {"success": False, "message": "Публичный ключ собеседника не найден в базе"}
            
        peer_id = peer_key_data["user_id"]
        
        shared_keys_collection.update_one(
            {
                "user_id": ObjectId(user_id),
                "peer_id": peer_id
            },
            {
                "$set": {
                    "shared_secret": derived_key.hex(),
                    "computed_at": datetime.utcnow()
                }
            },
            upsert=True
        )
        
        logger.info(f"Вычислен общий секрет для пользователя {user_id}")
        return {"success": True, "shared_secret": derived_key.hex()}
        
    except Exception as e:
        logger.error(f"Ошибка вычисления общего секрета: {e}")
        return {"success": False, "message": str(e)}
    
@eel.expose
def mark_chat_messages_as_read(user_id, peer_id):
    """Пометить все сообщения в чате как прочитанные"""
    try:
        result = messages_collection.update_many(
            {
                "sender_id": ObjectId(peer_id),
                "receiver_id": ObjectId(user_id),
                "read": False
            },
            {"$set": {"read": True}}
        )
        
        logger.info(f"Сообщения от {peer_id} для {user_id} помечены как прочитанные: {result.modified_count} сообщений")
        return {"success": True, "count": result.modified_count}
    except Exception as e:
        logger.error(f"Ошибка пометки сообщений как прочитанных: {e}")
        return {"success": False, "message": str(e)}
    
    
    
    
@eel.expose
def encrypt_message(user_id, peer_id, plaintext):
    """Шифрование сообщения с использованием AES-256-GCM"""
    try:
        logger.info(f"Шифрование сообщения от {user_id} к {peer_id}")
        
        # Получаем общий ключ из базы
        key_data = shared_keys_collection.find_one({
            "$or": [
                {"user_id": ObjectId(user_id), "peer_id": ObjectId(peer_id)},
                {"user_id": ObjectId(peer_id), "peer_id": ObjectId(user_id)}
            ]
        })
        
        if not key_data:
            logger.error("Общий ключ не найден в encrypt_message")
            return {"success": False, "message": "Общий ключ не найден"}
        
        logger.info(f"Общий ключ найден: {key_data['_id']}")
        
        # Конвертируем ключ из hex
        key = bytes.fromhex(key_data['shared_secret'])
        
        # Генерируем случайный nonce (96 бит для AES-GCM)
        nonce = os.urandom(12)
        
        # Создаем AES-GCM объект
        aesgcm = AESGCM(key)
        
        # Шифруем сообщение
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Для чата с самим собой сообщение сразу помечается как прочитанное
        is_self_chat = user_id == peer_id
        read_status = is_self_chat
        
        # Сохраняем зашифрованное сообщение
        result = messages_collection.insert_one({
            "sender_id": ObjectId(user_id),
            "receiver_id": ObjectId(peer_id),
            "ciphertext": ciphertext.hex(),
            "nonce": nonce.hex(),
            "is_encrypted": True,
            "timestamp": datetime.utcnow(),
            "read": read_status
        })
        
        logger.info(f"Сообщение зашифровано и отправлено от {user_id} к {peer_id}, прочитано: {read_status}")
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": datetime.utcnow().isoformat(),
            "read": read_status
        }
        
    except Exception as e:
        logger.error(f"Ошибка шифрования сообщения: {e}")
        return {"success": False, "message": str(e)}
    
    
    
    
@eel.expose
def debug_encryption_status(user_id, peer_id):
    """Функция для отладки статуса шифрования"""
    try:
        # Проверяем ECDH ключи
        user_ecdh = ecdh_keys_collection.find_one({"user_id": ObjectId(user_id)})
        peer_ecdh = ecdh_keys_collection.find_one({"user_id": ObjectId(peer_id)})
        
        # Проверяем общий ключ
        shared_key = shared_keys_collection.find_one({
            "$or": [
                {"user_id": ObjectId(user_id), "peer_id": ObjectId(peer_id)},
                {"user_id": ObjectId(peer_id), "peer_id": ObjectId(user_id)}
            ]
        })
        
        return {
            "user_ecdh_exists": user_ecdh is not None,
            "peer_ecdh_exists": peer_ecdh is not None,
            "shared_key_exists": shared_key is not None,
            "shared_key_data": shared_key
        }
        
    except Exception as e:
        logger.error(f"Ошибка отладки: {e}")
        return {"error": str(e)}
    
@eel.expose
def send_message_encrypted_force(sender_id, receiver_id, text):
    """Принудительная отправка зашифрованного сообщения"""
    try:
        logger.info(f"ПРИНУДИТЕЛЬНАЯ отправка зашифрованного сообщения")
        return encrypt_message(sender_id, receiver_id, text)
    except Exception as e:
        logger.error(f"Ошибка принудительного шифрования: {e}")
        return {"success": False, "message": str(e)}
    
    
@eel.expose
def get_shared_key(user_id, peer_id):
    """Получение общего ключа для чата"""
    try:
        key_data = shared_keys_collection.find_one({
            "$or": [
                {"user_id": ObjectId(user_id), "peer_id": ObjectId(peer_id)},
                {"user_id": ObjectId(peer_id), "peer_id": ObjectId(user_id)}
            ]
        })
        
        if key_data:
            return {
                "success": True,
                "shared_secret": key_data['shared_secret'],
                "computed_at": key_data.get('computed_at')
            }
        else:
            return {"success": False, "message": "Общий ключ не найден"}
            
    except Exception as e:
        logger.error(f"Ошибка получения общего ключа: {e}")
        return {"success": False, "message": str(e)}
    
    
    

@eel.expose
def decrypt_message(user_id, message_id):
    """Дешифрование сообщения с использованием общего ключа из базы"""
    try:
        # Получаем сообщение
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if not message:
            return {"success": False, "message": "Сообщение не найдено"}
        
        # Проверяем, что сообщение зашифровано
        if not message.get("is_encrypted", False):
            return {
                "success": True,
                "plaintext": message.get("text", "")
            }
        
        # Определяем отправителя и получателя
        sender_id = message['sender_id']
        receiver_id = message['receiver_id']
        
        # Определяем, кто из участников чата является peer'ом для текущего пользователя
        current_user_id = ObjectId(user_id)
        if current_user_id == sender_id:
            peer_id = receiver_id
        else:
            peer_id = sender_id
        
        # Получаем общий ключ из базы (проверяем оба направления)
        key_data = shared_keys_collection.find_one({
            "$or": [
                {"user_id": current_user_id, "peer_id": ObjectId(peer_id)},
                {"user_id": ObjectId(peer_id), "peer_id": current_user_id}
            ]
        })
        
        if not key_data:
            return {"success": False, "message": "Общий ключ не найден для этого чата"}
        
        # Конвертируем ключ из hex
        key = bytes.fromhex(key_data['shared_secret'])
        
        # Получаем зашифрованные данные
        ciphertext = bytes.fromhex(message['ciphertext'])
        nonce = bytes.fromhex(message['nonce'])
        
        # Дешифруем сообщение
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return {
            "success": True,
            "plaintext": plaintext.decode('utf-8')
        }
        
    except Exception as e:
        logger.error(f"Ошибка дешифрования сообщения {message_id}: {e}")
        return {"success": False, "message": str(e)}

@eel.expose
def get_encrypted_chat_history(user_id, peer_id):
    """Получение истории зашифрованного чата (без дешифрования на сервере)"""
    try:
        messages = messages_collection.find({
            "$or": [
                {"sender_id": ObjectId(user_id), "receiver_id": ObjectId(peer_id)},
                {"sender_id": ObjectId(peer_id), "receiver_id": ObjectId(user_id)}
            ]
        }).sort("timestamp", 1)
        
        messages_list = []
        for message in messages:
            # Проверяем, не удалено ли сообщение для текущего пользователя
            deleted_for = message.get("deleted_for", [])
            if ObjectId(user_id) in deleted_for:
                continue
                
            message_data = {
                "id": str(message["_id"]),
                "sender_id": str(message["sender_id"]),
                "receiver_id": str(message["receiver_id"]),
                "timestamp": message["timestamp"].isoformat(),
                "read": message.get("read", False),
                "is_encrypted": message.get("is_encrypted", False)
            }
            
            # Возвращаем зашифрованный текст как есть - дешифрование на клиенте
            if message.get("is_encrypted"):
                message_data["text"] = message.get("encrypted_text", "")
            else:
                message_data["text"] = message.get("text", "")
            
            messages_list.append(message_data)
        
        return {
            "success": True,
            "messages": messages_list
        }
        
    except Exception as e:
        logger.error(f"Ошибка получения зашифрованной истории: {e}")
        return {"success": False, "message": str(e)}
    


@eel.expose
def get_last_message_encrypted(user1_id, user2_id):
    """Получение последнего сообщения (зашифрованного)"""
    try:
        message = messages_collection.find_one({
            "$or": [
                {"sender_id": ObjectId(user1_id), "receiver_id": ObjectId(user2_id)},
                {"sender_id": ObjectId(user2_id), "receiver_id": ObjectId(user1_id)}
            ],
            "deleted_for": {"$ne": ObjectId(user1_id)}
        }, sort=[("timestamp", -1)])
        
        if message:
            # Для зашифрованных сообщений возвращаем специальный текст
            if message.get('is_encrypted'):
                text = "🔒 Зашифрованное сообщение"
            else:
                text = message.get("text", "[Сообщение]")
            
            return {
                "text": text,
                "sender_id": str(message["sender_id"]),
                "timestamp": message["timestamp"].isoformat(),
                "is_encrypted": message.get("is_encrypted", False)
            }
        return None
    except Exception as e:
        logger.error(f"Error getting last encrypted message: {e}")
        return None
    
    
@eel.expose
def register_user(nickname, email, password):
    try:
        email_normalized = email.lower().strip()
        email_hash = hashlib.sha256(email_normalized.encode()).hexdigest()
        
        if users_collection.find_one({"email_hash": email_hash}):
            return {"success": False, "message": "Пользователь с таким email уже существует"}

        user_data = {
            "nickname": nickname,
            "email_hash": email_hash,
            "password_hash": hashlib.sha256(password.encode()).hexdigest(),
            "created_at": datetime.utcnow(),
            "friends": [],
            "last_online": datetime.utcnow()
        }

        result = users_collection.insert_one(user_data)
        logger.info(f"Зарегистрирован новый пользователь: {nickname}")
        
        return {
            "success": True, 
            "message": "Регистрация успешна!", 
            "user_id": str(result.inserted_id)
        }
    except Exception as e:
        logger.error(f"Ошибка регистрации: {e}")
        return {"success": False, "message": "Ошибка при регистрации"}

@eel.expose
def login_user(email, password):
    try:
        email_normalized = email.lower().strip()
        email_hash = hashlib.sha256(email_normalized.encode()).hexdigest()
        
        logger.info(f"LOGIN ATTEMPT: Email: '{email}' -> Normalized: '{email_normalized}' -> Hash: {email_hash}")
        
        user = users_collection.find_one({"email_hash": email_hash})
        
        if not user:
            return {"success": False, "message": "Пользователь не найден"}

        logger.info(f"USER FOUND: {user['_id']}")
        logger.info(f"USER FIELDS: {list(user.keys())}")
        
        if "password_hash" not in user:
            logger.error(f"User document missing password_hash field. Available fields: {list(user.keys())}")
            return {"success": False, "message": "Ошибка данных пользователя"}
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if user["password_hash"] != password_hash:
            return {"success": False, "message": "Неверный пароль"}

        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_online": datetime.utcnow()}}
        )

        logger.info(f"Пользователь {user['nickname']} вошел в систему")
        return {
            "success": True,
            "nickname": user["nickname"],
            "user_id": str(user["_id"]),
            "friends": [str(friend) for friend in user.get("friends", [])]
        }
    except Exception as e:
        logger.error(f"Ошибка входа: {e}")
        return {"success": False, "message": "Ошибка при входе в систему"}

@eel.expose
def send_encrypted_message(sender_id, receiver_id, encrypted_text):
    """Сохранение уже зашифрованного сообщения"""
    try:
        # Для чата с самим собой сообщение сразу помечается как прочитанное
        is_self_chat = sender_id == receiver_id
        read_status = is_self_chat
        
        result = messages_collection.insert_one({
            "sender_id": ObjectId(sender_id),
            "receiver_id": ObjectId(receiver_id),
            "encrypted_text": encrypted_text,  # Храним уже зашифрованный текст
            "is_encrypted": True,
            "timestamp": datetime.utcnow(),
            "read": read_status
        })
        
        logger.info(f"Зашифрованное сообщение сохранено от {sender_id} к {receiver_id}")
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": datetime.utcnow().isoformat(),
            "read": read_status
        }
        
    except Exception as e:
        logger.error(f"Ошибка сохранения зашифрованного сообщения: {e}")
        return {"success": False, "message": str(e)}
    
@eel.expose
def initialize_user_encryption(user_id, password):
    """Инициализация шифрования для пользователя с паролем"""
    try:
        # Проверяем, есть ли уже ключи
        existing_keys = ecdh_keys_collection.find_one({"user_id": ObjectId(user_id)})
        if existing_keys:
            return {"success": True, "message": "Ключи уже существуют"}
        
        # Генерируем новую ключевую пару с переданным паролем
        return generate_ecdh_keypair(user_id, password)
        
    except Exception as e:
        logger.error(f"Ошибка инициализации шифрования: {e}")
        return {"success": False, "message": str(e)}
    
    
@eel.expose
def setup_chat_encryption(user_id, peer_id, password):
    """Настройка шифрования для конкретного чата с использованием пароля"""
    try:
        # Проверяем, есть ли ключи у обоих пользователей
        user_keys = ecdh_keys_collection.find_one({"user_id": ObjectId(user_id)})
        peer_keys = ecdh_keys_collection.find_one({"user_id": ObjectId(peer_id)})
        
        if not user_keys:
            # Генерируем ключи для текущего пользователя с паролем
            key_result = generate_ecdh_keypair(user_id, password)
            if not key_result['success']:
                return {"success": False, "message": "Не удалось сгенерировать ключи"}
        
        if not peer_keys:
            return {"success": False, "message": "У собеседника нет ключевой пары"}
        
        # Получаем публичный ключ собеседника
        peer_public_key = peer_keys['public_key']
        
        # Вычисляем общий секрет
        shared_secret_result = compute_shared_secret_with_password(user_id, peer_public_key, password)
        
        if shared_secret_result['success']:
            logger.info(f"Шифрование настроено для чата {user_id} -> {peer_id}")
            return {"success": True, "message": "Шифрование настроено"}
        else:
            return shared_secret_result
            
    except Exception as e:
        logger.error(f"Ошибка настройки шифрования чата: {e}")
        return {"success": False, "message": str(e)}
    
    
    
@eel.expose
def compute_shared_secret_with_password(user_id, peer_public_key_pem, password):
    """Вычисление общего секрета с использованием пароля для дешифрования приватного ключа"""
    try:
        # Получаем зашифрованные данные приватного ключа
        key_data = ecdh_keys_collection.find_one({"user_id": ObjectId(user_id)})
        if not key_data:
            return {"success": False, "message": "Ключевая пара не найдена"}
        
        # Дешифруем приватный ключ с использованием пароля
        decryption_result = get_decrypted_private_key(user_id, password)
        if not decryption_result['success']:
            return decryption_result
        
        # Загружаем приватный ключ
        private_key = serialization.load_pem_private_key(
            decryption_result['private_key'].encode('utf-8'),
            password=None
        )
        
        # Загружаем публичный ключ собеседника
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_pem.encode('utf-8')
        )
        
        # Вычисляем общий секрет
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Производим ключ с помощью HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=HKDF_INFO
        ).derive(shared_secret)
        
        # Находим peer_id по публичному ключу
        peer_key_data = ecdh_keys_collection.find_one({"public_key": peer_public_key_pem})
        if not peer_key_data:
            return {"success": False, "message": "Публичный ключ собеседника не найден в базе"}
            
        peer_id = peer_key_data["user_id"]
        
        # Сохраняем общий ключ в базе
        shared_keys_collection.update_one(
            {
                "user_id": ObjectId(user_id),
                "peer_id": peer_id
            },
            {
                "$set": {
                    "shared_secret": derived_key.hex(),
                    "computed_at": datetime.utcnow()
                }
            },
            upsert=True
        )
        
        logger.info(f"Вычислен общий секрет для пользователя {user_id}")
        return {"success": True, "shared_secret": derived_key.hex()}
        
    except Exception as e:
        logger.error(f"Ошибка вычисления общего секрета: {e}")
        return {"success": False, "message": str(e)}
    
    
    
    
@eel.expose
def send_zk_message(sender_id, receiver_id, text):
    """Универсальная функция отправки сообщения (с шифрованием если возможно)"""
    try:
        logger.info(f"Отправка сообщения от {sender_id} к {receiver_id}")
        
        # Проверяем, настроено ли шифрование для этого чата
        key_data = shared_keys_collection.find_one({
            "$or": [
                {"user_id": ObjectId(sender_id), "peer_id": ObjectId(receiver_id)},
                {"user_id": ObjectId(receiver_id), "peer_id": ObjectId(sender_id)}
            ]
        })
        
        logger.info(f"Общий ключ найден: {'да' if key_data else 'нет'}")
        
        if key_data:
            # ОТПРАВЛЯЕМ ЗАШИФРОВАННОЕ СООБЩЕНИЕ
            logger.info("Отправка ЗАШИФРОВАННОГО сообщения")
            result = encrypt_message(sender_id, receiver_id, text)
            if result['success']:
                result['is_encrypted'] = True
                logger.info(f"Сообщение успешно зашифровано, ID: {result['message_id']}")
            else:
                logger.error(f"Ошибка шифрования: {result['message']}")
            return result
        else:
            # Отправляем обычное сообщение
            logger.info("Отправка обычного сообщения (шифрование не настроено)")
            result = send_message(sender_id, receiver_id, text)
            if result['success']:
                result['is_encrypted'] = False
            return result
            
    except Exception as e:
        logger.error(f"Ошибка отправки ZK сообщения: {e}")
        return {"success": False, "message": str(e)}
    
@eel.expose
def send_message(sender_id, receiver_id, text):
    """Отправка обычного незашифрованного сообщения"""
    try:
        # Для чата с самим собой сообщение сразу помечается как прочитанное
        is_self_chat = sender_id == receiver_id
        read_status = is_self_chat
        
        result = messages_collection.insert_one({
            "sender_id": ObjectId(sender_id),
            "receiver_id": ObjectId(receiver_id),
            "text": text,
            "is_encrypted": False,
            "timestamp": datetime.utcnow(),
            "read": read_status  # Для чата с собой сразу прочитано
        })
        
        logger.info(f"Сообщение отправлено от {sender_id} к {receiver_id}, прочитано: {read_status}")
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": datetime.utcnow().isoformat(),
            "read": read_status
        }
        
    except Exception as e:
        logger.error(f"Ошибка отправки сообщения: {e}")
        return {"success": False, "message": str(e)}
    
    
@eel.expose
def get_chat_messages_decrypted(user_id, peer_id):
    """Получение истории чата с автоматическим дешифрованием"""
    try:
        messages = messages_collection.find({
            "$or": [
                {"sender_id": ObjectId(user_id), "receiver_id": ObjectId(peer_id)},
                {"sender_id": ObjectId(peer_id), "receiver_id": ObjectId(user_id)}
            ]
        }).sort("timestamp", 1)
        
        messages_list = []
        for message in messages:
            # Проверяем, не удалено ли сообщение для текущего пользователя
            deleted_for = message.get("deleted_for", [])
            if ObjectId(user_id) in deleted_for:
                continue  # Пропускаем сообщения, удаленные для этого пользователя
                
            message_data = {
                "id": str(message["_id"]),
                "sender_id": str(message["sender_id"]),
                "receiver_id": str(message["receiver_id"]),
                "timestamp": message["timestamp"].isoformat(),
                "read": message.get("read", False),
                "is_encrypted": message.get("is_encrypted", False)
            }
            
            # Если сообщение зашифровано, пытаемся дешифровать
            if message.get("is_encrypted"):
                decryption_result = decrypt_message(user_id, str(message["_id"]))
                if decryption_result["success"]:
                    message_data["text"] = decryption_result["plaintext"]
                else:
                    message_data["text"] = "[Зашифрованное сообщение]"
                    message_data["decryption_error"] = True
                    logger.warning(f"Не удалось дешифровать сообщение {message['_id']}: {decryption_result['message']}")
            else:
                message_data["text"] = message.get("text", "")
            
            messages_list.append(message_data)
        
        return messages_list
        
    except Exception as e:
        logger.error(f"Ошибка получения дешифрованных сообщений: {e}")
        return []
    
    

@eel.expose
def check_chat_encryption_status(user_id, peer_id):
    """Проверка статуса шифрования для чата"""
    try:
        key_data = shared_keys_collection.find_one({
            "$or": [
                {"user_id": ObjectId(user_id), "peer_id": ObjectId(peer_id)},
                {"user_id": ObjectId(peer_id), "peer_id": ObjectId(user_id)}
            ]
        })
        
        return {"encrypted": key_data is not None}
        
    except Exception as e:
        logger.error(f"Ошибка проверки статуса шифрования: {e}")
        return {"encrypted": False}
    
    
    
@eel.expose
def establish_secure_connection(user_id, peer_id, password):
    """Установка безопасного соединения между пользователями с использованием пароля"""
    try:
        # Генерируем ключи если их нет
        user_keys = ecdh_keys_collection.find_one({"user_id": ObjectId(user_id)})
        if not user_keys:
            generate_ecdh_keypair(user_id, password)
        
        peer_keys = ecdh_keys_collection.find_one({"user_id": ObjectId(peer_id)})
        if not peer_keys:
            return {"success": False, "message": "У собеседника нет ключевой пары"}
        
        # Получаем публичный ключ собеседника
        peer_public_key = peer_keys['public_key']
        
        # Вычисляем общий секрет с использованием пароля
        result = compute_shared_secret_with_password(user_id, peer_public_key, password)
        
        if result['success']:
            logger.info(f"Безопасное соединение установлено между {user_id} и {peer_id}")
            return {"success": True, "message": "Безопасное соединение установлено"}
        else:
            return result
            
    except Exception as e:
        logger.error(f"Ошибка установки безопасного соединения: {e}")
        return {"success": False, "message": str(e)}
    
    
@eel.expose
def get_user_data(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            user_data = {
                "user_id": str(user["_id"]),
                "nickname": user["nickname"],
                "friends": [str(friend) for friend in user.get("friends", [])],
                "last_online": user.get("last_online", datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S")
            }
            return user_data
        return None
    except Exception as e:
        logger.error(f"Ошибка получения данных пользователя: {e}")
        return None

@eel.expose
def search_users(search_term, current_user_id):
    try:
        users = users_collection.find({
            "nickname": {"$regex": f"^{search_term}", "$options": "i"},
            "_id": {"$ne": ObjectId(current_user_id)}
        }).limit(10)
        
        return [{
            "user_id": str(user["_id"]),
            "nickname": user["nickname"],
            "is_friend": ObjectId(current_user_id) in user.get("friends", [])
        } for user in users]
    except Exception as e:
        logger.error(f"Ошибка поиска пользователей: {e}")
        return []

@eel.expose
def add_friend(current_user_id, friend_id):
    try:
        if current_user_id == friend_id:
            return {"success": False, "message": "Нельзя добавить самого себя в друзья"}
        
        current_user = users_collection.find_one({"_id": ObjectId(current_user_id)})
        friend_user = users_collection.find_one({"_id": ObjectId(friend_id)})
        
        if not current_user or not friend_user:
            return {"success": False, "message": "Пользователь не найден"}
        
        if ObjectId(friend_id) in current_user.get("friends", []):
            return {"success": False, "message": "Этот пользователь уже у вас в друзьях"}
        
        users_collection.update_one(
            {"_id": ObjectId(current_user_id)},
            {"$addToSet": {"friends": ObjectId(friend_id)}}
        )
        users_collection.update_one(
            {"_id": ObjectId(friend_id)},
            {"$addToSet": {"friends": ObjectId(current_user_id)}}
        )
        
        logger.info(f"Пользователь {current_user_id} добавил в друзья {friend_id}")
        return {"success": True, "message": "Пользователь добавлен в друзья"}
    except Exception as e:
        logger.error(f"Ошибка добавления в друзья: {e}")
        return {"success": False, "message": "Ошибка при добавлении в друзья"}

@eel.expose
def remove_friend(current_user_id, friend_id):
    try:
        current_user = users_collection.find_one({"_id": ObjectId(current_user_id)})
        friend_user = users_collection.find_one({"_id": ObjectId(friend_id)})
        
        if not current_user or not friend_user:
            return {"success": False, "message": "Пользователь не найден"}
        
        if ObjectId(friend_id) not in current_user.get("friends", []):
            return {"success": False, "message": "Этот пользователь не в вашем списке друзей"}
        
        users_collection.update_one(
            {"_id": ObjectId(current_user_id)},
            {"$pull": {"friends": ObjectId(friend_id)}}
        )
        users_collection.update_one(
            {"_id": ObjectId(friend_id)},
            {"$pull": {"friends": ObjectId(current_user_id)}}
        )
        
        logger.info(f"Пользователь {current_user_id} удалил из друзей {friend_id}")
        return {"success": True, "message": "Пользователь удален из друзей"}
    except Exception as e:
        logger.error(f"Ошибка удаления из друзей: {e}")
        return {"success": False, "message": "Ошибка при удалении из друзей"}

@eel.expose
def get_chat_history(user_id, peer_user_id):
    """Получение истории чата"""
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        peer_user = users_collection.find_one({"_id": ObjectId(peer_user_id)})
        
        if not user or not peer_user:
            return {"success": False, "message": "Пользователь не найден"}
        
        messages = messages_collection.find({
            "$or": [
                {"sender_id": ObjectId(user_id), "receiver_id": ObjectId(peer_user_id)},
                {"sender_id": ObjectId(peer_user_id), "receiver_id": ObjectId(user_id)}
            ]
        }).sort("timestamp", 1)
        
        messages_list = []
        for message in messages:
            message_data = {
                "id": str(message["_id"]),
                "sender_id": str(message["sender_id"]),
                "receiver_id": str(message["receiver_id"]),
                "text": message.get("text", ""),
                "timestamp": message["timestamp"].isoformat(),
                "read": message.get("read", False)
            }
            messages_list.append(message_data)
        
        return {
            "success": True,
            "messages": messages_list
        }
        
    except Exception as e:
        logger.error(f"Ошибка получения истории чата: {e}")
        return {"success": False, "message": str(e)}

@eel.expose
def check_new_messages(user_id, last_message_id=None):
    try:
        query = {
            "receiver_id": ObjectId(user_id),
            "deleted_for": {"$ne": ObjectId(user_id)}
        }
        
        if not last_message_id:
            return []
            
        query["_id"] = {"$gt": ObjectId(last_message_id)}
        
        messages_cursor = messages_collection.find(query).sort("timestamp", 1)
        messages = list(messages_cursor)

        if messages:
            messages_collection.update_many(
                {"_id": {"$in": [msg["_id"] for msg in messages]}},
                {"$set": {"read": True}}
            )
        
        result = []
        for msg in messages:
            m = {
                "id": str(msg["_id"]),
                "sender_id": str(msg["sender_id"]),
                "receiver_id": str(msg["receiver_id"]),
                "text": msg.get("text", "[Сообщение]"),
                "timestamp": msg["timestamp"].isoformat(),
                "read": True
            }
            result.append(m)
        return result
    except Exception as e:
        logger.error(f"Ошибка проверки новых сообщений: {e}")
        return []

@eel.expose
def update_last_online(user_id):
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"last_online": datetime.utcnow()}}
        )
        return True
    except Exception as e:
        logger.error(f"Ошибка обновления времени последней активности: {e}")
        return False

@eel.expose
def get_last_message(user1_id, user2_id):
    try:
        message = messages_collection.find_one({
            "$or": [
                {"sender_id": ObjectId(user1_id), "receiver_id": ObjectId(user2_id)},
                {"sender_id": ObjectId(user2_id), "receiver_id": ObjectId(user1_id)}
            ],
            "deleted_for": {"$ne": ObjectId(user1_id)}
        }, sort=[("timestamp", -1)])
        
        if message:
            # Если сообщение зашифровано, пытаемся его дешифровать
            if message.get('is_encrypted'):
                try:
                    decryption_result = decrypt_message(user1_id, str(message['_id']))
                    if decryption_result['success']:
                        text = decryption_result['plaintext']
                    else:
                        text = "[Зашифрованное сообщение]"
                except:
                    text = "[Зашифрованное сообщение]"
            else:
                text = message.get("text", "[Сообщение]")
            
            return {
                "text": text,
                "sender_id": str(message["sender_id"]),
                "timestamp": message["timestamp"].isoformat(),
                "is_encrypted": message.get("is_encrypted", False)
            }
        return None
    except Exception as e:
        logger.error(f"Error getting last message: {e}")
        return None

@eel.expose
def edit_message(message_id, new_text):
    try:
        result = messages_collection.update_one(
            {"_id": ObjectId(message_id)},
            {"$set": {"text": new_text}}
        )
        
        if result.modified_count > 0:
            logger.info(f"Сообщение {message_id} успешно отредактировано")
            return {"success": True, "message": "Сообщение отредактировано"}
        
        return {"success": False, "message": "Сообщение не найдено или текст не изменился"}
    except Exception as e:
        logger.error(f"Ошибка редактирования сообщения: {e}")
        return {"success": False, "message": "Ошибка при редактировании сообщения"}

@eel.expose
def get_friends(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            friends = user.get("friends", [])
            friend_data = []
            for friend_id in friends:
                friend = users_collection.find_one({"_id": friend_id})
                if friend:
                    friend_data.append({
                        "user_id": str(friend["_id"]),
                        "nickname": friend["nickname"],
                        "email": "encrypted@example.com"
                    })
            return friend_data
        return []
    except Exception as e:
        logger.error(f"Ошибка получения списка друзей: {e}")
        return []

@eel.expose
def get_all_users():
    try:
        users = users_collection.find()
        user_data = []
        for user in users:
            user_data.append({
                "user_id": str(user["_id"]),
                "nickname": f"User {str(user['_id'])[:8]}",
                "email": "encrypted@example.com"
            })
        return user_data
    except Exception as e:
        logger.error(f"Ошибка получения всех пользователей: {e}")
        return []

@eel.expose
def delete_message(message_id):
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if not message:
            return {"success": False, "message": "Сообщение не найдено"}
        
        current_user_id = ObjectId(eel.get_current_user_id()())
        if message["sender_id"] != current_user_id:
            return {"success": False, "message": "Вы можете удалять только свои сообщения"}
        
        result = messages_collection.delete_one({"_id": ObjectId(message_id)})
        
        if result.deleted_count > 0:
            logger.info(f"Сообщение {message_id} успешно удалено")
            return {"success": True, "message": "Сообщение удалено"}
        
        return {"success": False, "message": "Сообщение не найдено"}
    except Exception as e:
        logger.error(f"Ошибка удаления сообщения: {e}")
        return {"success": False, "message": "Ошибка при удалении сообщения"}

@eel.expose
def save_reply_state(user_id, chat_id, message_id):
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "reply_states": {
                    chat_id: {
                        "message_id": message_id,
                        "timestamp": datetime.utcnow()
                    }
                }
            }},
            upsert=True
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Ошибка сохранения состояния ответа: {e}")
        return {"success": False}

@eel.expose
def get_reply_state(user_id, chat_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user and "reply_states" in user and chat_id in user["reply_states"]:
            reply_state = user["reply_states"][chat_id]
            
            if (datetime.utcnow() - reply_state["timestamp"]).total_seconds() > 4 * 3600:
                users_collection.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$unset": {f"reply_states.{chat_id}": ""}}
                )
                return {"success": False}
            return {
                "success": True,
                "message_id": reply_state["message_id"]
            }
        return {"success": False}
    except Exception as e:
        logger.error(f"Ошибка получения состояния ответа: {e}")
        return {"success": False}

@eel.expose
def clear_reply_state(user_id, chat_id):
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$unset": {f"reply_states.{chat_id}": ""}}
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Ошибка очистки состояния ответа: {e}")
        return {"success": False}

@eel.expose
def save_draft_message(user_id, chat_id, text):
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {f"drafts.{chat_id}": {"text": text, "timestamp": datetime.utcnow()}}},
            upsert=True
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Ошибка сохранения черновика: {e}")
        return {"success": False}

@eel.expose
def get_draft_message(user_id, chat_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user and "drafts" in user and chat_id in user["drafts"]:
            draft = user["drafts"][chat_id]
            
            if (datetime.utcnow() - draft["timestamp"]).total_seconds() > 4 * 3600:
                users_collection.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$unset": {f"drafts.{chat_id}": ""}}
                )
                return None
            return draft["text"]
        return None
    except Exception as e:
        logger.error(f"Ошибка получения черновика: {e}")
        return None

@eel.expose
def clear_draft_message(user_id, chat_id):
    """Очистка черновика сообщения для конкретного чата"""
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$unset": {f"drafts.{chat_id}": ""}}
        )
        logger.info(f"Черновик очищен для пользователя {user_id}, чат {chat_id}")
        return {"success": True}
    except Exception as e:
        logger.error(f"Ошибка очистки черновика: {e}")
        return {"success": False}

@eel.expose
def check_message_read_status(message_ids):
    try:
        messages = messages_collection.find({
            "_id": {"$in": [ObjectId(id) for id in message_ids]}
        })
        
        return {str(msg["_id"]): msg.get("read", False) for msg in messages}
    except Exception as e:
        logger.error(f"Ошибка проверки статуса прочтения: {e}")
        return {}

@eel.expose
def mark_messages_as_read(sender_id, receiver_id):
    try:
        result = messages_collection.update_many(
            {
                "sender_id": ObjectId(sender_id),
                "receiver_id": ObjectId(receiver_id),
                "read": False
            },
            {"$set": {"read": True}}
        )
        return {"success": True, "count": result.modified_count}
    except Exception as e:
        logger.error(f"Ошибка пометки сообщений как прочитанных: {e}")
        return {"success": False}

@eel.expose
def get_current_user_id():
    return ""

@eel.expose
def delete_message_for_me(user_id, message_id):
    try:
        result = messages_collection.update_one(
            {"_id": ObjectId(message_id)},
            {"$addToSet": {"deleted_for": ObjectId(user_id)}}
        )
        
        if result.modified_count > 0:
            return {"success": True, "message": "Сообщение удалено только для вас"}
        return {"success": False, "message": "Сообщение уже было удалено"}
    except Exception as e:
        logger.error(f"Ошибка удаления сообщения: {e}")
        return {"success": False, "message": "Ошибка при удалении сообщения"}

@eel.expose
def get_message_data(message_id):
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if message:
            return {
                "id": str(message["_id"]),
                "sender_id": str(message["sender_id"]),
                "text": message.get("text", "[Сообщение]"),
                "timestamp": message["timestamp"].isoformat()
            }
        return None
    except Exception as e:
        logger.error(f"Ошибка получения данных сообщения: {e}")
        return None

@eel.expose
def check_voice_messages_listened_status(message_ids):
    """Проверка статуса прослушивания голосовых сообщений"""
    try:
        messages = messages_collection.find({
            "_id": {"$in": [ObjectId(id) for id in message_ids]}
        })
        
        return {str(msg["_id"]): msg.get("listened", False) for msg in messages}
    except Exception as e:
        logger.error(f"Ошибка проверки статуса прослушивания: {e}")
        return {}
    
    


if __name__ == '__main__':
    try:
        import sys
        port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
        eel.start('login.html', size=(1000, 700), mode='chrome', port=port)
    except Exception as e:
        logger.error(f"Ошибка запуска приложения: {e}")