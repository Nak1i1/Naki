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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import hashlib
import hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding



logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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

class ECDHEncryptionSystem:
    @staticmethod
    def generate_key_pair():
        """Генерация ECDH ключевой пары"""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_public_key(public_key):
        """Сериализация публичного ключа в PEM формат"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def deserialize_public_key(public_key_bytes):
        """Десериализация публичного ключа из PEM формата"""
        return serialization.load_pem_public_key(public_key_bytes)
    
    @staticmethod
    def serialize_private_key(private_key, password=None):
        """Сериализация приватного ключа"""
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
    
    @staticmethod
    def deserialize_private_key(private_key_bytes, password=None):
        """Десериализация приватного ключа"""
        return serialization.load_pem_private_key(private_key_bytes, password=password)
    
    @staticmethod
    def derive_shared_secret(private_key, peer_public_key):
        """Вычисление общего секрета"""
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecdh key derivation',
        ).derive(shared_secret)
        
        return derived_key
    
    @staticmethod
    def encrypt_message_aes(message: str, shared_secret: bytes) -> str:
        """Настоящее AES-256 шифрование с использованием общего секрета"""
        try:
            
            iv = os.urandom(16)
            
            
            key = hashlib.sha256(shared_secret).digest()
            
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            
            padder = padding.PKCS7(128).padder()
            message_bytes = message.encode('utf-8')
            padded_data = padder.update(message_bytes) + padder.finalize()
            
            
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            
            
            result = iv + encrypted
            
            return base64.b64encode(result).decode()
            
        except Exception as e:
            logger.error(f"Ошибка AES шифрования: {e}")
            raise
    
    @staticmethod
    def decrypt_message_aes(encrypted_message: str, shared_secret: bytes) -> str:
        """Настоящее AES-256 дешифрование с использованием общего секрета"""
        try:
            
            data = base64.b64decode(encrypted_message)
            
            
            iv = data[:16]
            encrypted = data[16:]
            
            
            key = hashlib.sha256(shared_secret).digest()
            
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
            
            
            unpadder = padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            return decrypted.decode()
            
        except Exception as e:
            logger.error(f"Ошибка AES дешифрования: {e}")
            raise

    
    @staticmethod
    def encrypt_message(message: str, shared_secret: bytes) -> str:
        """Старый метод для обратной совместимости"""
        return ECDHEncryptionSystem.encrypt_message_aes(message, shared_secret)
    
    @staticmethod
    def decrypt_message(encrypted_message: str, shared_secret: bytes) -> str:
        """Старый метод для обратной совместимости"""
        return ECDHEncryptionSystem.decrypt_message_aes(encrypted_message, shared_secret)

def get_local_time():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


eel.init("web")



def encrypt_zk_message(plaintext: str, password_hash: str, salt: str) -> str:
    """Настоящее AES-256 шифрование с использованием соли из БД"""
    try:
        print(f"🔐 Шифрование текста: '{plaintext}' (длина: {len(plaintext)})")
        print(f"📎 Используемая соль: {salt[:20]}...")
        
        
        salt_bytes = base64.b64decode(salt)
        print(f"📎 Длина соли: {len(salt_bytes)} байт")
        
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  
            salt=salt_bytes,
            iterations=100000,  
            backend=default_backend()
        )
        
        
        key = kdf.derive(password_hash.encode())
        print(f"🔑 Ключ создан через PBKDF2: {len(key)} байт")
        
        
        iv = os.urandom(16)
        print(f"🔑 IV сгенерирован: {len(iv)} байт")
        
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        
        padder = padding.PKCS7(128).padder()
        plaintext_bytes = plaintext.encode('utf-8')
        padded_data = padder.update(plaintext_bytes) + padder.finalize()
        
        print(f"📊 Данные до шифрования: {len(plaintext_bytes)} -> {len(padded_data)} байт")
        
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        print(f"🔒 Зашифрованные данные: {len(encrypted)} байт")
        
        
        result = iv + encrypted
        final_base64 = base64.b64encode(result).decode()
        
        print(f"📦 Итоговый base64: {len(final_base64)} символов")
        print(f"📦 Пример: {final_base64[:50]}...")
        
        return final_base64
        
    except Exception as e:
        logger.error(f"Ошибка AES шифрования с солью: {e}")
        raise

def decrypt_zk_message_func(encrypted_data: str, password_hash: str, salt: str) -> str:
    """Настоящее AES-256 дешифрование с использованием соли из БД"""
    try:
        
        data = base64.b64decode(encrypted_data)
        
        
        iv = data[:16]
        encrypted = data[16:]
        
        
        salt_bytes = base64.b64decode(salt)
        
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
            backend=default_backend()
        )
        
        
        key = kdf.derive(password_hash.encode())
        
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        
        
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted.decode()
        
    except Exception as e:
        logger.error(f"Ошибка AES дешифрования с солью: {e}")
        raise
    

@eel.expose
def register_user(nickname, email, password):
    try:
        
        email_normalized = email.lower().strip()
        email_hash = hashlib.sha256(email_normalized.encode()).hexdigest()
        
        if users_collection.find_one({"email_hash": email_hash}):
            return {"success": False, "message": "Пользователь с таким email уже существует"}

        
        private_key, public_key = ECDHEncryptionSystem.generate_key_pair()
        
        
        public_key_bytes = ECDHEncryptionSystem.serialize_public_key(public_key)
        private_key_bytes = ECDHEncryptionSystem.serialize_private_key(private_key)
        
        user_data = {
            "nickname": nickname,
            "email_hash": email_hash,
            "password_hash": hashlib.sha256(password.encode()).hexdigest(),
            "public_key": base64.b64encode(public_key_bytes).decode(),
            "encrypted_private_key": base64.b64encode(private_key_bytes).decode(),
            "created_at": datetime.utcnow(),
            "friends": [],
            "last_online": datetime.utcnow(),
            "ecdh_initialized": True
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
def initialize_ecdh_system(user_id):
    """Инициализация ECDH системы для пользователя"""
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return {"success": False, "message": "Пользователь не найден"}
        
        
        if "public_key" not in user:
            
            private_key, public_key = ECDHEncryptionSystem.generate_key_pair()
            
            
            public_key_bytes = ECDHEncryptionSystem.serialize_public_key(public_key)
            private_key_bytes = ECDHEncryptionSystem.serialize_private_key(private_key)
            
            
            users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {
                    "public_key": base64.b64encode(public_key_bytes).decode(),
                    "encrypted_private_key": base64.b64encode(private_key_bytes).decode(),
                    "ecdh_initialized": True
                }}
            )
        
        return {"success": True, "message": "ECDH система инициализирована"}
    except Exception as e:
        logger.error(f"Ошибка инициализации ECDH системы: {e}")
        return {"success": False, "message": str(e)}

@eel.expose
def get_self_chat_secret(user_id):
    """Получение ключа для чата с самим собой"""
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return {"success": False, "message": "Пользователь не найден"}
        
        
        public_key_bytes = base64.b64decode(user["public_key"])
        public_key = ECDHEncryptionSystem.deserialize_public_key(public_key_bytes)
        
        
        key_material = public_key_bytes
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'self chat key',
        ).derive(key_material)
        
        
        shared_keys_collection.update_one(
            {
                "user1_id": ObjectId(user_id),
                "user2_id": ObjectId(user_id)
            },
            {
                "$set": {
                    "shared_secret": base64.b64encode(derived_key).decode(),
                    "created_at": datetime.utcnow()
                }
            },
            upsert=True
        )
        
        return {
            "success": True, 
            "shared_secret": base64.b64encode(derived_key).decode(),
            "message": "Ключ для чата с самим собой создан"
        }
    except Exception as e:
        logger.error(f"Ошибка получения ключа для чата с самим собой: {e}")
        return {"success": False, "message": str(e)}

@eel.expose
def get_user_public_key(user_id):
    """Получение публичного ключа пользователя"""
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return {"success": False, "message": "Пользователь не найден"}
        
        if "public_key" not in user:
            return {"success": False, "message": "Публичный ключ не найден"}
        
        return {
            "success": True, 
            "public_key": user["public_key"]
        }
    except Exception as e:
        logger.error(f"Ошибка получения публичного ключа: {e}")
        return {"success": False, "message": str(e)}

@eel.expose
def compute_shared_secret(user1_id, user2_id):
    """Вычисление общего секрета между двумя пользователями"""
    try:
        
        user1 = users_collection.find_one({"_id": ObjectId(user1_id)})
        user2 = users_collection.find_one({"_id": ObjectId(user2_id)})
        
        if not user1 or not user2:
            return {"success": False, "message": "Пользователь не найден"}
        
        
        private_key1_bytes = base64.b64decode(user1["encrypted_private_key"])
        private_key1 = ECDHEncryptionSystem.deserialize_private_key(private_key1_bytes)
        
        
        public_key2_bytes = base64.b64decode(user2["public_key"])
        public_key2 = ECDHEncryptionSystem.deserialize_public_key(public_key2_bytes)
        
        
        shared_secret = ECDHEncryptionSystem.derive_shared_secret(private_key1, public_key2)
        
        
        shared_keys_collection.update_one(
            {
                "user1_id": ObjectId(user1_id),
                "user2_id": ObjectId(user2_id)
            },
            {
                "$set": {
                    "shared_secret": base64.b64encode(shared_secret).decode(),
                    "created_at": datetime.utcnow()
                }
            },
            upsert=True
        )
        
        return {
            "success": True,
            "shared_secret": base64.b64encode(shared_secret).decode(),
            "message": "Общий секрет вычислен и сохранен"
        }
    except Exception as e:
        logger.error(f"Ошибка вычисления общего секрета: {e}")
        return {"success": False, "message": str(e)}

@eel.expose
def get_shared_secret(user1_id, user2_id):
    """Получение общего секрета между двумя пользователями"""
    try:
        key_data = shared_keys_collection.find_one({
            "$or": [
                {"user1_id": ObjectId(user1_id), "user2_id": ObjectId(user2_id)},
                {"user1_id": ObjectId(user2_id), "user2_id": ObjectId(user1_id)}
            ]
        })
        
        if key_data and "shared_secret" in key_data:
            return {
                "success": True, 
                "shared_secret": key_data["shared_secret"]
            }
        
        return {"success": False, "message": "Общий секрет не найден"}
    except Exception as e:
        logger.error(f"Ошибка получения общего секрета: {e}")
        return {"success": False, "message": str(e)}

@eel.expose
def send_encrypted_message(sender_id, receiver_id, encrypted_text):
    """Отправка зашифрованного сообщения с настоящим AES"""
    try:
        sender = users_collection.find_one({"_id": ObjectId(sender_id)})
        receiver = users_collection.find_one({"_id": ObjectId(receiver_id)})
        
        if not sender or not receiver:
            return {"success": False, "message": "Пользователь не найден"}
        
        utc_time = datetime.utcnow()
        is_self_message = sender_id == receiver_id
        
        message_data = {
            "sender_id": ObjectId(sender_id),
            "receiver_id": ObjectId(receiver_id),
            "encrypted_text": encrypted_text,
            "text": "[Зашифрованное сообщение]",
            "timestamp": utc_time,
            "read": is_self_message,
            "is_encrypted": True,
            "encryption_type": "ecdh_aes"  
        }
        
        result = messages_collection.insert_one(message_data)
        
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": utc_time.isoformat(),
            "read": is_self_message
        }
    except Exception as e:
        logger.error(f"Ошибка отправки зашифрованного сообщения: {e}")
        return {"success": False, "message": str(e)}

@eel.expose
def decrypt_message_content(user_id, message_id):
    """Дешифрование содержимого сообщения с настоящим AES"""
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if not message or not message.get("is_encrypted"):
            return {"success": False, "message": "Сообщение не найдено или не зашифровано"}
        
        
        if str(message["sender_id"]) == user_id:
            peer_user_id = str(message["receiver_id"])
        else:
            peer_user_id = str(message["sender_id"])
        
        
        shared_secret_result = get_shared_secret(user_id, peer_user_id)
        if not shared_secret_result["success"]:
            return {"success": False, "message": "Не удалось получить общий секрет"}
        
        shared_secret = base64.b64decode(shared_secret_result["shared_secret"])
        
        
        decrypted_text = ECDHEncryptionSystem.decrypt_message_aes(message["encrypted_text"], shared_secret)
        
        return {
            "success": True,
            "decrypted_text": decrypted_text,
            "message_id": message_id
        }
    except Exception as e:
        logger.error(f"Ошибка дешифрования сообщения: {e}")
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
                "last_online": user.get("last_online", datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S"),
                "ecdh_initialized": user.get("ecdh_initialized", False)
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
def get_chat_history(user1_id, user2_id):
    try:
        messages = messages_collection.find({
            "$or": [
                {"sender_id": ObjectId(user1_id), "receiver_id": ObjectId(user2_id)},
                {"sender_id": ObjectId(user2_id), "receiver_id": ObjectId(user1_id)}
            ]
        }).sort("timestamp", 1)
        
        result = []
        for msg in messages:
            message_data = {
                "id": str(msg["_id"]),
                "sender_id": str(msg["sender_id"]),
                "receiver_id": str(msg["receiver_id"]),
                "timestamp": msg["timestamp"].isoformat(),
                "read": msg.get("read", False),
                "is_encrypted": msg.get("is_encrypted", False),
                "encryption_type": msg.get("encryption_type", "")
            }
            
            
            if user1_id == user2_id and msg.get("is_encrypted") and msg.get("encryption_type") == "zk_password":
                
                message_data["text"] = "[ZK Зашифрованное сообщение]"
            elif msg.get("is_encrypted"):
                message_data["text"] = "[Зашифрованное сообщение]"
            else:
                message_data["text"] = msg.get("text", "[Сообщение]")
            
            result.append(message_data)
        
        return result
    except Exception as e:
        logger.error(f"Ошибка получения истории чата: {e}")
        return []

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
            return {
                "text": message.get("text", "[Сообщение]"),
                "sender_id": str(message["sender_id"]),
                "timestamp": message["timestamp"].isoformat()
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
def verify_encryption_system(user_id):
    """Проверка целостности системы шифрования"""
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return {"success": False, "message": "Пользователь не найден"}
        
        
        required_fields = ["password_hash", "public_key", "encrypted_private_key"]
        for field in required_fields:
            if field not in user:
                return {"success": False, "message": f"Отсутствует поле: {field}"}
        
        
        self_chat_key = shared_keys_collection.find_one({
            "user1_id": ObjectId(user_id),
            "user2_id": ObjectId(user_id)
        })
        
        if not self_chat_key:
            
            get_self_chat_secret(user_id)
        
        return {"success": True, "message": "Система шифрования в порядке"}
        
    except Exception as e:
        logger.error(f"Ошибка проверки системы шифрования: {e}")
        return {"success": False, "message": str(e)}    
@eel.expose
def decrypt_zk_message(user_id, message_id):
    """Дешифрование ZK сообщения с настоящим AES и солью"""
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if not message:
            return {"success": False, "message": "Сообщение не найдено"}
        
        
        is_self_chat = str(message["sender_id"]) == user_id and str(message["receiver_id"]) == user_id
        is_zk_encrypted = message.get("is_zk_encrypted", False)
        
        if not is_self_chat or not is_zk_encrypted:
            return {"success": False, "message": "Сообщение не требует дешифрования"}
        
        
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return {"success": False, "message": "Пользователь не найден"}
        
        
        password_hash = user["password_hash"]
        salt_used = message.get("salt_used", "")
        
        if not salt_used:
            return {"success": False, "message": "Соль для дешифрования не найдена"}
        
        try:
            decrypted_text = decrypt_zk_message_func(message["encrypted_text"], password_hash, salt_used)
        except Exception as decrypt_error:
            logger.error(f"Ошибка дешифрования AES с солью: {decrypt_error}")
            return {"success": False, "message": f"Ошибка дешифрования: {str(decrypt_error)}"}
        
        return {
            "success": True,
            "decrypted_text": decrypted_text,
            "message_id": message_id
        }
        
    except Exception as e:
        logger.error(f"Ошибка дешифрования ZK сообщения: {e}")
        return {"success": False, "message": f"Ошибка дешифрования: {str(e)}"}
    
    
    
    
@eel.expose
def send_zk_message(sender_id, receiver_id, plain_text, salt):
    """Отправка ZK-зашифрованного сообщения с настоящим AES и солью"""
    try:
        sender = users_collection.find_one({"_id": ObjectId(sender_id)})
        receiver = users_collection.find_one({"_id": ObjectId(receiver_id)})
        
        if not sender or not receiver:
            return {"success": False, "message": "Пользователь не найден"}
        
        encrypted_text = plain_text
        is_self_message = sender_id == receiver_id
        
        print(f"=== ОТПРАВКА ZK СООБЩЕНИЯ С СОЛЬЮ ===")
        print(f"От: {sender_id}, Кому: {receiver_id}")
        print(f"Текст: '{plain_text}' (длина: {len(plain_text)})")
        print(f"Соль: {salt[:20]}...")
        print(f"Сообщение самому себе: {is_self_message}")
        
        if is_self_message:
            
            print("🔐 Используем AES шифрование с солью для чата с самим собой")
            password_hash = sender["password_hash"]
            
            try:
                print("📢 Вызываем encrypt_zk_message с солью...")
                encrypted_text = encrypt_zk_message(plain_text, password_hash, salt)
                print(f"✅ Текст успешно зашифрован с солью")
                print(f"📏 Длина зашифрованного текста: {len(encrypted_text)}")
                print(f"📋 Пример: {encrypted_text[:50]}...")
                
                
                try:
                    decrypted_check = decrypt_zk_message_func(encrypted_text, password_hash, salt)
                    print(f"🔍 Проверка расшифрования: '{decrypted_check}'")
                    print(f"✅ Совпадает с оригиналом: {decrypted_check == plain_text}")
                except Exception as decrypt_error:
                    print(f"❌ Ошибка проверки расшифрования: {decrypt_error}")
                    
            except Exception as encrypt_error:
                print(f"❌ Ошибка шифрования с солью: {encrypt_error}")
                import traceback
                print(f"📋 Traceback: {traceback.format_exc()}")
                return {"success": False, "message": f"Ошибка шифрования: {encrypt_error}"}
        
        utc_time = datetime.utcnow()
        
        message_data = {
            "sender_id": ObjectId(sender_id),
            "receiver_id": ObjectId(receiver_id),
            "encrypted_text": encrypted_text,
            "text": "[ZK Зашифрованное сообщение]" if is_self_message else plain_text,
            "timestamp": utc_time,
            "read": is_self_message,
            "is_encrypted": is_self_message,
            "encryption_type": "zk_password_aes" if is_self_message else "plain",  
            "is_zk_encrypted": is_self_message,
            "salt_used": salt
        }
        
        print(f"📦 Данные для сохранения в БД:")
        print(f"   encrypted_text длина: {len(encrypted_text)}")
        print(f"   is_encrypted: {is_self_message}")
        print(f"   salt_used: {salt[:20]}...")
        
        result = messages_collection.insert_one(message_data)
        
        print(f"✅ Сообщение сохранено в БД, ID: {result.inserted_id}")
        
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": utc_time.isoformat(),
            "read": is_self_message
        }
    except Exception as e:
        print(f"❌ Критическая ошибка отправки ZK сообщения: {e}")
        logger.error(f"Ошибка отправки ZK сообщения: {e}")
        return {"success": False, "message": str(e)}
    
    
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
    
    
@eel.expose
def get_user_salt(user_id):
    """Получение соли пользователя для ZK шифрования"""
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return {"success": False, "message": "Пользователь не найден"}
        
        
        if "salt" not in user:
            
            salt = os.urandom(32)
            salt_b64 = base64.b64encode(salt).decode()
            
            
            users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"salt": salt_b64}}
            )
            
            return {"success": True, "salt": salt_b64}
        
        return {"success": True, "salt": user["salt"]}
        
    except Exception as e:
        logger.error(f"Ошибка получения соли пользователя: {e}")
        return {"success": False, "message": str(e)}
        
def encrypt_shared_secret(secret: bytes, master_key: bytes) -> dict:
    """
    Шифрование общего секрета с использованием мастер-ключа
    Возвращает словарь с зашифрованными данными и метаданными
    """
    try:
        
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  
            salt=b'shared_secret_encryption',  
            info=b'encryption_key',
            backend=default_backend()
        ).derive(master_key)

        
        iv = os.urandom(16)
        
        
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(secret) + padder.finalize()
        
        
        encrypted_secret = encryptor.update(padded_data) + encryptor.finalize()
        
        
        hmac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'shared_secret_hmac',
            info=b'hmac_key', 
            backend=default_backend()
        ).derive(master_key)
        
        hmac_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hmac_digest.update(iv + encrypted_secret)
        hmac_value = hmac_digest.finalize()
        
        
        return {
            "success": True,
            "encrypted_data": base64.b64encode(encrypted_secret).decode(),
            "iv": base64.b64encode(iv).decode(),
            "hmac": base64.b64encode(hmac_value).decode(),
            "algorithm": "AES-256-CBC-HMAC-SHA256",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Ошибка шифрования общего секрета: {e}")
        return {
            "success": False,
            "message": f"Ошибка шифрования: {str(e)}"
        }
        
        
        
def decrypt_shared_secret(encrypted_data: dict, master_key: bytes) -> bytes:
    """
    Дешифрование общего секрета с использованием мастер-ключа
    """
    try:
        
        required_fields = ["encrypted_data", "iv", "hmac"]
        for field in required_fields:
            if field not in encrypted_data:
                raise ValueError(f"Отсутствует обязательное поле: {field}")
        
        
        encrypted_secret = base64.b64decode(encrypted_data["encrypted_data"])
        iv = base64.b64decode(encrypted_data["iv"])
        stored_hmac = base64.b64decode(encrypted_data["hmac"])
        
        
        hmac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'shared_secret_hmac', 
            info=b'hmac_key',
            backend=default_backend()
        ).derive(master_key)
        
        hmac_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hmac_digest.update(iv + encrypted_secret)
        calculated_hmac = hmac_digest.finalize()
        
        
        if not hmac.compare_digest(stored_hmac, calculated_hmac):
            raise ValueError("Ошибка проверки целостности данных")
        
        
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'shared_secret_encryption',
            info=b'encryption_key',
            backend=default_backend()
        ).derive(master_key)
        
        
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(encrypted_secret) + decryptor.finalize()
        
        
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_secret = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted_secret
        
    except Exception as e:
        logger.error(f"Ошибка дешифрования общего секрета: {e}")
        raise
    
    
def generate_master_key(user_password: str, user_salt: bytes) -> bytes:
    """
    Генерация мастер-ключа из пароля пользователя и соли
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=user_salt,
        iterations=100000,  
        backend=default_backend()
    )
    
    return kdf.derive(user_password.encode())  



          
def encrypt_private_key(private_key_bytes, user_password):
    
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), iterations=100000)
    key = kdf.derive(user_password.encode())
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(os.urandom(12)))
    encryptor = cipher.encryptor()
    return encryptor.update(private_key_bytes) + encryptor.finalize()

def hash_password(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt + key  
@eel.expose
def save_protected_shared_secret(user1_id: str, user2_id: str, secret: bytes, user_password: str):
    """
    Сохранение защищенного общего секрета в базе
    """
    try:
        
        user = users_collection.find_one({"_id": ObjectId(user1_id)})
        if not user or "salt" not in user:
            return {"success": False, "message": "Соль пользователя не найдена"}
        
        user_salt = base64.b64decode(user["salt"])
        
        
        master_key = generate_master_key(user_password, user_salt)
        
        
        encrypted_result = encrypt_shared_secret(secret, master_key)
        if not encrypted_result["success"]:
            return encrypted_result
        
        
        shared_keys_collection.update_one(
            {
                "user1_id": ObjectId(user1_id),
                "user2_id": ObjectId(user2_id)
            },
            {
                "$set": {
                    "protected_secret": encrypted_result,  
                    "created_at": datetime.utcnow(),
                    "key_version": "v2_protected"  
                }
            },
            upsert=True
        )
        
        return {"success": True, "message": "Защищенный секрет сохранен"}
        
    except Exception as e:
        logger.error(f"Ошибка сохранения защищенного секрета: {e}")
        return {"success": False, "message": str(e)}
    
    
@eel.expose  
def get_protected_shared_secret(user1_id: str, user2_id: str, user_password: str) -> dict:
    """
    Получение и дешифрование защищенного общего секрета
    """
    try:
        
        key_data = shared_keys_collection.find_one({
            "$or": [
                {"user1_id": ObjectId(user1_id), "user2_id": ObjectId(user2_id)},
                {"user1_id": ObjectId(user2_id), "user2_id": ObjectId(user1_id)}
            ],
            "key_version": "v2_protected"
        })
        
        if not key_data or "protected_secret" not in key_data:
            return {"success": False, "message": "Защищенный секрет не найден"}
        
        
        user = users_collection.find_one({"_id": ObjectId(user1_id)})
        if not user or "salt" not in user:
            return {"success": False, "message": "Соль пользователя не найдена"}
        
        user_salt = base64.b64decode(user["salt"])
        
        
        master_key = generate_master_key(user_password, user_salt)
        
        
        encrypted_data = key_data["protected_secret"]
        decrypted_secret = decrypt_shared_secret(encrypted_data, master_key)
        
        return {
            "success": True, 
            "shared_secret": base64.b64encode(decrypted_secret).decode()
        }
        
    except Exception as e:
        logger.error(f"Ошибка получения защищенного секрета: {e}")
        return {"success": False, "message": str(e)}
    
    
            
@eel.expose
def compute_shared_master_key(user1_id, user2_id, password1, password2):
    """Вычисление общего мастер-ключа для ZK шифрования"""
    try:
        
        user1 = users_collection.find_one({"_id": ObjectId(user1_id)})
        user2 = users_collection.find_one({"_id": ObjectId(user2_id)})
        
        if not user1 or not user2:
            return {"success": False, "message": "Пользователь не найден"}
        
        
        salt1 = base64.b64decode(user1.get("salt", base64.b64encode(secrets.token_bytes(32)).decode()))
        salt2 = base64.b64decode(user2.get("salt", base64.b64encode(secrets.token_bytes(32)).decode()))
        
        
        combined_salt = salt1 + salt2
        
        
        combined_password = f"{password1}:{password2}"
        
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=combined_salt,
            iterations=100000,
            backend=default_backend()
        )
        
        master_key = kdf.derive(combined_password.encode())
        
        
        shared_keys_collection.update_one(
            {
                "user1_id": ObjectId(user1_id),
                "user2_id": ObjectId(user2_id),
                "key_type": "zk_master"
            },
            {
                "$set": {
                    "master_key": base64.b64encode(master_key).decode(),
                    "created_at": datetime.utcnow()
                }
            },
            upsert=True
        )
        
        return {
            "success": True,
            "message": "Мастер-ключ вычислен и сохранен"
        }
    except Exception as e:
        logger.error(f"Ошибка вычисления мастер-ключа: {e}")
        return {"success": False, "message": str(e)}
    
@eel.expose
def get_shared_master_key(user1_id, user2_id):
    """Получение общего мастер-ключа ZK"""
    try:
        key_data = shared_keys_collection.find_one({
            "$or": [
                {"user1_id": ObjectId(user1_id), "user2_id": ObjectId(user2_id), "key_type": "zk_master"},
                {"user1_id": ObjectId(user2_id), "user2_id": ObjectId(user1_id), "key_type": "zk_master"}
            ]
        })
        
        if key_data and "master_key" in key_data:
            return {
                "success": True, 
                "master_key": key_data["master_key"]
            }
        
        return {"success": False, "message": "Мастер-ключ не найден"}
    except Exception as e:
        logger.error(f"Ошибка получения мастер-ключа: {e}")
        return {"success": False, "message": str(e)}
            
@eel.expose
def repair_ecdh_system(user_id):
    """Восстановление ECDH системы для пользователя"""
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return {"success": False, "message": "Пользователь не найден"}
        

        private_key, public_key = ECDHEncryptionSystem.generate_key_pair()

        public_key_bytes = ECDHEncryptionSystem.serialize_public_key(public_key)
        private_key_bytes = ECDHEncryptionSystem.serialize_private_key(private_key)
        

        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "public_key": base64.b64encode(public_key_bytes).decode(),
                "encrypted_private_key": base64.b64encode(private_key_bytes).decode(),
                "ecdh_initialized": True
            }}
        )

        shared_keys_collection.delete_many({
            "$or": [
                {"user1_id": ObjectId(user_id)},
                {"user2_id": ObjectId(user_id)}
            ]
        })
        

        get_self_chat_secret(user_id)
        
        return {"success": True, "message": "ECDH система восстановлена"}
    except Exception as e:
        logger.error(f"Ошибка восстановления ECDH системы: {e}")
        return {"success": False, "message": str(e)}

if __name__ == '__main__':
    try:
        import sys
        port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
        eel.start('login.html', size=(1000, 700), mode='chrome', port=port)
    except Exception as e:
        logger.error(f"Ошибка запуска приложения: {e}")