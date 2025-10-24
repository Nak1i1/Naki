import eel
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId
import logging
import os
import base64
from pathlib import Path
import gridfs
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import json

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Инициализация MongoDB
try:
    client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client['messenger_db']
    users_collection = db['users']
    messages_collection = db['messages']
    keys_collection = db['encryption_keys']
    logger.info("Успешное подключение к MongoDB")
except Exception as e:
    logger.error(f"Ошибка подключения к MongoDB: {e}")
    raise

# Создание коллекций и индексов
collections = ['users', 'messages', 'encryption_keys']
for collection in collections:
    if collection not in db.list_collection_names():
        db.create_collection(collection)

messages_collection.create_index([("sender_id", 1), ("receiver_id", 1)])
messages_collection.create_index([("timestamp", 1)])

# УДАЛИТЬ старый индекс на email и создать новый на email_hash
try:
    users_collection.drop_index("email_1")  # Удаляем старый проблемный индекс
except:
    pass  # Если индекса нет, просто продолжаем

users_collection.create_index([("email_hash", 1)], unique=True)  # Новый правильный индекс

# Ключ для шифрования метаданных (должен быть защищен в production)
MASTER_KEY = Fernet.generate_key()
fernet = Fernet(MASTER_KEY)

class ZeroKnowledgeCrypto:
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def generate_salt() -> bytes:
        """Generate random salt"""
        return secrets.token_bytes(16)

    @staticmethod
    def encrypt_data(data: str, key: bytes) -> dict:
        """Encrypt data with derived key"""
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data.encode())
        return {
            'encrypted_data': base64.b64encode(encrypted_data).decode(),
            'timestamp': datetime.utcnow().isoformat()
        }

    @staticmethod
    def decrypt_data(encrypted_data: str, key: bytes) -> str:
        """Decrypt data with derived key"""
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(base64.b64decode(encrypted_data))
        return decrypted_data.decode()

# Функция для получения локального времени
def get_local_time():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

# Инициализация Eel
eel.init("web")
import hashlib

@eel.expose
def register_user(nickname, email, password):
    try:
        # Нормализуем email к нижнему регистру перед хешированием
        email_normalized = email.lower().strip()
        email_hash = hashlib.sha256(email_normalized.encode()).hexdigest()
        
        if users_collection.find_one({"email_hash": email_hash}):
            return {"success": False, "message": "Пользователь с таким email уже существует"}

        # Генерируем соль и ключ для пользователя
        salt = ZeroKnowledgeCrypto.generate_salt()
        user_key = ZeroKnowledgeCrypto.derive_key(password, salt)

        # Шифруем данные пользователя (используем оригинальный email для шифрования)
        encrypted_nickname = ZeroKnowledgeCrypto.encrypt_data(nickname, user_key)
        encrypted_email = ZeroKnowledgeCrypto.encrypt_data(email, user_key)  # Сохраняем оригинальный регистр

        user_data = {
            "email_hash": email_hash,  # Для поиска дубликатов (нижний регистр)
            "salt": base64.b64encode(salt).decode(),
            "encrypted_nickname": encrypted_nickname,
            "encrypted_email": encrypted_email,
            "public_key": base64.b64encode(secrets.token_bytes(32)).decode(),
            "created_at": datetime.utcnow(),
            "friends": [],
            "last_online": datetime.utcnow()
        }

        result = users_collection.insert_one(user_data)
        logger.info(f"Зарегистрирован новый пользователь: {email_hash}")
        
        return {
            "success": True, 
            "message": "Регистрация успешна!", 
            "user_id": str(result.inserted_id)
        }
    except Exception as e:
        logger.error(f"Ошибка регистрации: {e}")
        return {"success": False, "message": "Ошибка при регистрации"}
    
    
@eel.expose
def debug_get_all_users():
    """Функция для отладки - получить всех пользователей"""
    try:
        users = list(users_collection.find({}, {
            'email_hash': 1,
            'created_at': 1,
            '_id': 1
        }))
        return [{
            'id': str(user['_id']),
            'email_hash': user['email_hash'],
            'created_at': user['created_at'].isoformat() if 'created_at' in user else 'N/A'
        } for user in users]
    except Exception as e:
        logger.error(f"Ошибка получения пользователей: {e}")
        return []
@eel.expose
def debug_check_email_hash(email):
    """Отладочная функция для проверки хеша email"""
    try:
        email_normalized = email.lower().strip()
        email_hash = hashlib.sha256(email_normalized.encode()).hexdigest()
        
        logger.info(f"DEBUG: Email: '{email}'")
        logger.info(f"DEBUG: Normalized: '{email_normalized}'")
        logger.info(f"DEBUG: Hash: {email_hash}")
        
        # Проверим, есть ли пользователь с таким хешем
        user = users_collection.find_one({"email_hash": email_hash})
        if user:
            logger.info(f"DEBUG: User found: {user['_id']}")
            return {"found": True, "hash": email_hash}
        else:
            # Посмотрим все существующие хеши
            all_users = list(users_collection.find({}, {"email_hash": 1}))
            existing_hashes = [u["email_hash"] for u in all_users]
            logger.info(f"DEBUG: Existing hashes: {existing_hashes}")
            return {"found": False, "hash": email_hash, "existing_hashes": existing_hashes}
    except Exception as e:
        logger.error(f"DEBUG Error: {e}")
        return {"error": str(e)}    

@eel.expose
def login_user(email, password):
    try:
        # Нормализуем email к нижнему регистру перед хешированием
        email_normalized = email.lower().strip()
        email_hash = hashlib.sha256(email_normalized.encode()).hexdigest()
        
        logger.info(f"LOGIN ATTEMPT: Email: '{email}' -> Normalized: '{email_normalized}' -> Hash: {email_hash}")
        
        user = users_collection.find_one({"email_hash": email_hash})
        
        if not user:
            return {"success": False, "message": "Пользователь не найден"}

        logger.info(f"USER FOUND: {user['_id']}")
        
        # Остальной код остается без изменений...
        salt = base64.b64decode(user["salt"])
        
        # Расшифровываем никнейм для возврата (опционально)
        try:
            user_key = ZeroKnowledgeCrypto.derive_key(password, salt)
            nickname = ZeroKnowledgeCrypto.decrypt_data(
                user["encrypted_nickname"]["encrypted_data"], 
                user_key
            )
        except Exception as decrypt_error:
            logger.warning(f"Не удалось расшифровать никнейм: {decrypt_error}")
            nickname = f"User {str(user['_id'])[:8]}"

        # Обновляем время последней активности
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_online": datetime.utcnow()}}
        )

        logger.info(f"Пользователь {email_hash} вошел в систему")
        return {
            "success": True,
            "nickname": nickname,
            "user_id": str(user["_id"]),
            "public_key": user.get("public_key", ""),
            "friends": [str(friend) for friend in user.get("friends", [])],
            "salt": user["salt"]  # Убедитесь, что соль возвращается
        }
    except Exception as e:
        logger.error(f"Ошибка входа: {e}")
        return {"success": False, "message": "Ошибка при входе в систему"}
    
    
    

@eel.expose
def get_user_data(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            # Для ZK архитектуры возвращаем только публичные данные
            user_data = {
                "user_id": str(user["_id"]),
                "public_key": user.get("public_key", ""),
                "friends": [str(friend) for friend in user.get("friends", [])],
                "last_online": user.get("last_online", datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S"),
            }
            
            # Для отображения в интерфейсе используем ID как имя
            user_data["nickname"] = f"User {user_id[:8]}"
            
            return user_data
        return None
    except Exception as e:
        logger.error(f"Ошибка получения данных пользователя: {e}")
        return None

@eel.expose
def get_user_salt(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user and "salt" in user:
            return {"success": True, "salt": user["salt"]}
        return {"success": False, "message": "Соль не найдена"}
    except Exception as e:
        logger.error(f"Ошибка получения соли: {e}")
        return {"success": False, "message": str(e)}

@eel.expose
def update_user_salt(user_id, salt):
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"salt": salt}}
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Ошибка обновления соли: {e}")
        return {"success": False, "message": str(e)}

@eel.expose
def search_users(search_term, current_user_id):
    try:
        # В ZK архитектуре мы не можем искать по зашифрованным данным
        # Возвращаем всех пользователей кроме текущего
        users = users_collection.find({
            "_id": {"$ne": ObjectId(current_user_id)}
        }).limit(10)
        
        return [{
            "user_id": str(user["_id"]),
            "public_key": user["public_key"],
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
def send_message(sender_id, receiver_id, encrypted_text, reply_to=None):
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
            "timestamp": utc_time,
            "read": is_self_message,
            "reply_to": ObjectId(reply_to) if reply_to else None,
            "is_encrypted": True
        }
        
        result = messages_collection.insert_one(message_data)
        
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": utc_time.isoformat(),
            "read": is_self_message
        }
    except Exception as e:
        logger.error(f"Ошибка отправки сообщения: {str(e)}")
        return {"success": False, "message": "Ошибка при отправке сообщения"}

@eel.expose
def get_chat_history(user1_id, user2_id):
    try:
        messages = messages_collection.find({
            "$or": [
                {"sender_id": ObjectId(user1_id), "receiver_id": ObjectId(user2_id)},
                {"sender_id": ObjectId(user2_id), "receiver_id": ObjectId(user1_id)}
            ],
            "deleted_for": {"$ne": ObjectId(user1_id)}
        }).sort("timestamp", 1)
        
        result = []
        for msg in messages:
            m = {
                "id": str(msg["_id"]),
                "sender_id": str(msg["sender_id"]),
                "receiver_id": str(msg["receiver_id"]),
                "encrypted_text": msg.get("encrypted_text", ""),
                "timestamp": msg["timestamp"].isoformat(),
                "read": msg.get("read", False),
                "is_encrypted": msg.get("is_encrypted", True),
                "is_media": msg.get("is_media", False),
                "is_voice": msg.get("is_voice", False)
            }
            
            # Добавляем текстовое поле для совместимости
            if msg.get("is_media"):
                m["text"] = f"[{msg.get('media_type', 'Медиа')}]"
            elif msg.get("is_voice"):
                m["text"] = "[Голосовое сообщение]"
            else:
                m["text"] = "[Зашифрованное сообщение]"
            
            if msg.get("is_media"):
                m["media_type"] = msg.get("media_type")
                m["filename"] = msg.get("filename")
            
            if msg.get("is_voice"):
                m["duration"] = msg.get("duration", 0)
                m["encrypted_voice_data"] = msg.get("encrypted_voice_data")
            
            if msg.get("reply_to"):
                m["reply_to"] = str(msg["reply_to"])
                
            result.append(m)
        return result
    except Exception as e:
        logger.error(f"Ошибка получения истории чата: {e}")
        return []

@eel.expose
def send_media_message(sender_id, receiver_id, encrypted_media_data, media_type, filename, caption=None):
    try:
        # Проверяем размер данных (увеличьте лимит если нужно)
        if len(encrypted_media_data) > 20 * 1024 * 1024:  # 20MB
            return {"success": False, "message": "File too large"}
        
        sender = users_collection.find_one({"_id": ObjectId(sender_id)})
        receiver = users_collection.find_one({"_id": ObjectId(receiver_id)})
        
        if not sender or not receiver:
            return {"success": False, "message": "User not found"}
        
        utc_time = datetime.utcnow()
        is_self_message = sender_id == receiver_id
        
        # Сохраняем зашифрованные медиа данные в GridFS
        fs = gridfs.GridFS(db)
        file_data = base64.b64decode(encrypted_media_data)
        
        # Проверяем размер после декодирования
        if len(file_data) > 15 * 1024 * 1024:  # 15MB
            return {"success": False, "message": "File too large after decoding"}
        
        file_id = fs.put(file_data, filename=filename, content_type=f"{media_type}/*")
        
        # Используем caption если он передан, иначе стандартный текст
        message_text = caption if caption else f"[{media_type.capitalize()}]"
        
        message_data = {
            "sender_id": ObjectId(sender_id),
            "receiver_id": ObjectId(receiver_id),
            "encrypted_text": encrypted_media_data,  # Сохраняем зашифрованные данные
            "timestamp": utc_time,
            "read": is_self_message,
            "is_media": True,
            "media_type": media_type,
            "file_id": file_id,
            "filename": filename,
            "is_encrypted": True
        }
        
        result = messages_collection.insert_one(message_data)
        
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": utc_time.isoformat(),
            "read": is_self_message
        }
    except Exception as e:
        logger.error(f"Error sending media message: {str(e)}")
        return {"success": False, "message": f"Error sending media message: {str(e)}"}

@eel.expose
def get_media_message(message_id):
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if message and message.get("is_media"):
            fs = gridfs.GridFS(db)
            if fs.exists(message["file_id"]):
                media_file = fs.get(message["file_id"])
                encrypted_media_data = base64.b64encode(media_file.read()).decode('utf-8')
                
                return {
                    "success": True,
                    "encrypted_media_data": encrypted_media_data,
                    "media_type": message["media_type"],
                    "filename": message["filename"]
                }
            return {"success": False, "message": "Файл не найден"}
        return {"success": False, "message": "Медиа-сообщение не найдено"}
    except Exception as e:
        logger.error(f"Ошибка получения медиа-сообщения: {e}")
        return {"success": False, "message": "Ошибка при получении медиа-сообщения"}

@eel.expose
def send_voice_message(sender_id, receiver_id, encrypted_voice_data, duration):
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
            "encrypted_text": "[Голосовое сообщение]",
            "timestamp": utc_time,
            "read": is_self_message,
            "is_voice": True,
            "encrypted_voice_data": encrypted_voice_data,
            "duration": float(duration),
            "is_encrypted": True
        }
        
        result = messages_collection.insert_one(message_data)
        
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": utc_time.isoformat(),
            "read": is_self_message
        }
    except Exception as e:
        logger.error(f"Ошибка отправки голосового сообщения: {e}")
        return {"success": False, "message": "Ошибка при отправке голосового сообщения"}

@eel.expose
def get_voice_message(message_id):
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if message and message.get("is_voice"):
            return {
                "success": True,
                "encrypted_voice_data": message["encrypted_voice_data"],
                "duration": message["duration"]
            }
        return {"success": False, "message": "Голосовое сообщение не найдено"}
    except Exception as e:
        logger.error(f"Ошибка получения голосового сообщения: {e}")
        return {"success": False, "message": "Ошибка при получении голосового сообщения"}

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

# ОСТАЛЬНЫЕ ФУНКЦИИ ОСТАЮТСЯ БЕЗ ИЗМЕНЕНИЙ
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
                        "nickname": f"User {str(friend['_id'])[:8]}",  # Используем ID как имя
                        "email": "encrypted@example.com"  # Заглушка для ZK
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
        # Сначала получаем сообщение, чтобы проверить права
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if not message:
            return {"success": False, "message": "Сообщение не найдено"}
        
        # Проверяем, что удаляет отправитель
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
            # Удаляем старые состояния (старше 4 часов)
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
            # Удаляем старые черновики (старше 4 часов)
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
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$unset": {f"drafts.{chat_id}": ""}}
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Ошибка удаления черновика: {e}")
        return {"success": False}

@eel.expose
def check_new_messages(user_id, last_message_id=None):
    try:
        query = {
            "receiver_id": ObjectId(user_id),
            "deleted_for": {"$ne": ObjectId(user_id)}
        }
        if last_message_id:
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
                "read": True,
                "listened": msg.get("listened", False) if msg.get("is_voice") else True
            }
            if msg.get("is_voice"):
                m["isVoiceMessage"] = True
                m["voiceData"] = msg.get("voice_data")
                m["duration"] = msg.get("duration", 0)
                m["visualization"] = msg.get("visualization", [])
            result.append(m)
        return result
    except Exception as e:
        logger.error(f"Ошибка проверки новых сообщений: {e}")
        return []

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
def mark_voice_message_as_listened(message_id, listener_id):
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if not message:
            return {"success": False, "message": "Сообщение не найдено"}
        
        # Проверяем, что слушатель является получателем сообщения
        if str(message["receiver_id"]) != listener_id:
            return {"success": False, "message": "Недостаточно прав для отметки сообщения"}
        
        result = messages_collection.update_one(
            {"_id": ObjectId(message_id)},
            {"$set": {"listened": True}}
        )
        
        if result.modified_count > 0:
            return {"success": True}
        return {"success": False, "message": "Сообщение уже было отмечено как прослушанное"}
    except Exception as e:
        logger.error(f"Ошибка отметки голосового сообщения как прослушанного: {e}")
        return {"success": False, "message": "Ошибка при отметке сообщения"}

@eel.expose
def check_voice_messages_listened_status(message_ids):
    try:
        messages = messages_collection.find({
            "_id": {"$in": [ObjectId(id) for id in message_ids]},
            "is_voice": True
        })
        
        return {str(msg["_id"]): msg.get("listened", False) for msg in messages}
    except Exception as e:
        logger.error(f"Ошибка проверки статуса прослушивания: {e}")
        return {}

@eel.expose
def mark_messages_as_read(sender_id, receiver_id):
    try:
        result = messages_collection.update_many(
            {
                "sender_id": ObjectId(sender_id),
                "receiver_id": ObjectId(receiver_id),
                "read": False,
                "is_voice": {"$ne": True}
            },
            {"$set": {"read": True}}
        )
        return {"success": True, "count": result.modified_count}
    except Exception as e:
        logger.error(f"Ошибка пометки сообщений как прочитанных: {e}")
        return {"success": False}

@eel.expose
def get_current_user_id():
    # Эта функция должна возвращать ID текущего пользователя из сессии
    # В реальном приложении это может быть из токена или сессии
    # В нашем случае можно использовать последнего авторизованного пользователя
    # Это временное решение, в продакшене нужно использовать сессии/токены
    from flask import request
    return request.cookies.get('user_id') or ''

@eel.expose
def delete_message_for_me(user_id, message_id):
    try:
        # Добавляем пользователя в список "deleted_for" для этого сообщения
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
def create_video_cache_folder():
    try:
        cache_dir = Path.home() / '.messenger_video_cache'
        cache_dir.mkdir(exist_ok=True)
        return str(cache_dir)
    except Exception as e:
        logger.error(f"Error creating video cache folder: {e}")
        return ""

@eel.expose
def check_video_cache(message_id):
    try:
        cache_dir = Path.home() / '.messenger_video_cache'
        video_path = cache_dir / f"{message_id}.mp4"
        return {
            "exists": video_path.exists(),
            "path": str(video_path) if video_path.exists() else ""
        }
    except Exception as e:
        logger.error(f"Error checking video cache: {e}")
        return {"exists": False, "path": ""}

@eel.expose
def save_video_to_cache(message_id, video_data):
    try:
        cache_dir = Path.home() / '.messenger_video_cache'
        video_path = cache_dir / f"{message_id}.mp4"
        
        # Если video_data - это URL, создаем из него файл
        if video_data.startswith('blob:'):
            # Здесь нужно реализовать сохранение из blob URL
            # Это пример - в реальности нужно использовать соответствующий метод
            with open(video_path, 'wb') as f:
                f.write(base64.b64decode(video_data.split(',')[1]))
        else:
            with open(video_path, 'wb') as f:
                f.write(base64.b64decode(video_data))
                
        return {"success": True}
    except Exception as e:
        logger.error(f"Error saving video to cache: {e}")
        return {"success": False}

@eel.expose
def save_media_file(media_data, filename):
    try:
        # Создаем папку для хранения медиа в директории приложения
        media_dir = Path('messenger_media')
        media_dir.mkdir(exist_ok=True)
        
        # Генерируем уникальное имя файла
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        ext = Path(filename).suffix
        unique_filename = f"{timestamp}{ext}"
        
        # Сохраняем файл
        file_path = media_dir / unique_filename
        with open(file_path, 'wb') as f:
            f.write(base64.b64decode(media_data))
            
        return {"success": True, "path": str(file_path)}
    except Exception as e:
        logger.error(f"Error saving media file: {e}")
        return {"success": False}

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

if __name__ == '__main__':
    try:
        import sys
        port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
        eel.start('login.html', size=(1000, 700), mode='chrome', port=port)
    except Exception as e:
        logger.error(f"Ошибка запуска приложения: {e}")