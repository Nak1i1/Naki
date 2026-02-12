import eel
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId
import logging
import os
import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CURVE = ec.SECP256R1()
HKDF_INFO = b"messenger_key_derivation"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client["messenger_db"]

    users_collection = db["users"]
    messages_collection = db["messages"]
    shared_keys_collection = db["shared_keys"]
    ecdh_keys_collection = db["ecdh_keys"]

    logger.info("Успешное подключение к MongoDB")
except Exception as e:
    logger.error(f"Ошибка подключения к MongoDB: {e}")
    raise

collections = ["users", "messages", "shared_keys", "ecdh_keys"]
for collection in collections:
    if collection not in db.list_collection_names():
        db.create_collection(collection)

messages_collection.create_index([("sender_id", 1), ("receiver_id", 1)])
messages_collection.create_index([("timestamp", 1)])
messages_collection.create_index([("reply_to_message_id", 1)])

try:
    users_collection.drop_index("email_1")
except Exception:
    pass

users_collection.create_index([("email_hash", 1)], unique=True)
users_collection.create_index([("nickname", 1)])

eel.init("web")


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_private_key(private_key_pem: str, password: str) -> dict:
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    encrypted_key = fernet.encrypt(private_key_pem.encode())
    return {
        "encrypted_private_key": base64.b64encode(encrypted_key).decode(),
        "salt": base64.b64encode(salt).decode(),
    }


def decrypt_private_key(encrypted_data: dict, password: str) -> str:
    salt = base64.b64decode(encrypted_data["salt"])
    encrypted_key = base64.b64decode(encrypted_data["encrypted_private_key"])
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_key).decode()


def get_local_time():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


@eel.expose
def get_current_time():
    return datetime.now().astimezone().isoformat()


@eel.expose
def get_current_time_utc():
    return datetime.utcnow().isoformat()


@eel.expose
def get_server_timestamp():
    try:
        return datetime.utcnow().isoformat() + "Z"
    except Exception as e:
        logger.error(f"Ошибка получения временного штампа: {e}")
        return datetime.utcnow().isoformat() + "Z"


@eel.expose
def format_timestamp_for_display(timestamp_str):
    try:
        dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        local_dt = dt.astimezone()
        return local_dt.strftime("%H:%M")
    except Exception as e:
        logger.error(f"Ошибка форматирования времени {timestamp_str}: {e}")

    try:
        if "T" in timestamp_str:
            dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(timestamp_str)
        local_dt = dt.astimezone()
        return local_dt.strftime("%H:%M")
    except Exception:
        return "--:--"


@eel.expose
def update_last_online(user_id):
    try:
        current_time = datetime.now().astimezone()
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"last_online": current_time}},
        )
        return True
    except Exception as e:
        logger.error(f"Ошибка обновления времени последней активности: {e}")
        return False


@eel.expose
def generate_ecdh_keypair(user_id, password):
    try:
        private_key = ec.generate_private_key(CURVE)
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        encrypted_private = encrypt_private_key(private_pem, password)

        ecdh_keys_collection.update_one(
            {"user_id": ObjectId(user_id)},
            {
                "$set": {
                    "encrypted_private_key": encrypted_private["encrypted_private_key"],
                    "salt": encrypted_private["salt"],
                    "public_key": public_pem,
                    "created_at": datetime.utcnow(),
                }
            },
            upsert=True,
        )

        logger.info(f"Ключевая пара сгенерирована для пользователя {user_id}")
        return {"success": True, "public_key": public_pem}
    except Exception as e:
        logger.error(f"Ошибка генерации ключей: {e}")
        return {"success": False, "message": str(e)}


@eel.expose
def get_decrypted_private_key(user_id, password):
    try:
        key_data = ecdh_keys_collection.find_one({"user_id": ObjectId(user_id)})
        if not key_data:
            return {"success": False, "message": "Ключи не найдены"}

        encrypted_data = {
            "encrypted_private_key": key_data["encrypted_private_key"],
            "salt": key_data["salt"],
        }

        private_pem = decrypt_private_key(encrypted_data, password)
        return {"success": True, "private_key": private_pem}
    except Exception as e:
        logger.error(f"Ошибка дешифрования приватного ключа: {e}")
        return {"success": False, "message": "Неверный пароль"}


@eel.expose
def get_public_key(user_id):
    try:
        key_data = ecdh_keys_collection.find_one({"user_id": ObjectId(user_id)})
        if not key_data or "public_key" not in key_data:
            return {"success": False, "message": "Публичный ключ не найден"}
        return {"success": True, "public_key": key_data["public_key"]}
    except Exception as e:
        logger.error(f"Ошибка получения публичного ключа: {e}")
        return {"success": False, "message": str(e)}


@eel.expose
def compute_shared_secret(user_id, peer_public_key_pem, password):
    try:
        key_data = ecdh_keys_collection.find_one({"user_id": ObjectId(user_id)})
        if not key_data:
            return {"success": False, "message": "Ключевая пара не найдена"}

        decryption_result = get_decrypted_private_key(user_id, password)
        if not decryption_result["success"]:
            return decryption_result

        private_key = serialization.load_pem_private_key(
            decryption_result["private_key"].encode("utf-8"),
            password=None,
        )

        peer_public_key = serialization.load_pem_public_key(peer_public_key_pem.encode("utf-8"))

        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=HKDF_INFO,
        ).derive(shared_secret)

        peer_key_data = ecdh_keys_collection.find_one({"public_key": peer_public_key_pem})
        if not peer_key_data:
            return {"success": False, "message": "Публичный ключ собеседника не найден в базе"}

        peer_id = peer_key_data["user_id"]

        shared_keys_collection.update_one(
            {"user_id": ObjectId(user_id), "peer_id": peer_id},
            {"$set": {"shared_secret": derived_key.hex(), "computed_at": datetime.utcnow()}},
            upsert=True,
        )

        logger.info(f"Вычислен общий секрет для пользователя {user_id}")
        return {"success": True, "shared_secret": derived_key.hex()}
    except Exception as e:
        logger.error(f"Ошибка вычисления общего секрета: {e}")
        return {"success": False, "message": str(e)}


@eel.expose
def get_shared_key(user_id, peer_id):
    try:
        key_data = shared_keys_collection.find_one(
            {
                "$or": [
                    {"user_id": ObjectId(user_id), "peer_id": ObjectId(peer_id)},
                    {"user_id": ObjectId(peer_id), "peer_id": ObjectId(user_id)},
                ]
            }
        )
        if key_data:
            return {
                "success": True,
                "shared_secret": key_data["shared_secret"],
                "computed_at": key_data.get("computed_at"),
            }
        return {"success": False, "message": "Общий ключ не найден"}
    except Exception as e:
        logger.error(f"Ошибка получения общего ключа: {e}")
        return {"success": False, "message": str(e)}


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
            "last_online": datetime.utcnow(),
        }

        result = users_collection.insert_one(user_data)
        logger.info(f"Зарегистрирован новый пользователь: {nickname}")

        return {"success": True, "message": "Регистрация успешна!", "user_id": str(result.inserted_id)}
    except Exception as e:
        logger.error(f"Ошибка регистрации: {e}")
        return {"success": False, "message": "Ошибка при регистрации"}


@eel.expose
def login_user(email, password):
    try:
        email_normalized = email.lower().strip()
        email_hash = hashlib.sha256(email_normalized.encode()).hexdigest()

        logger.info(
            f"LOGIN ATTEMPT: Email: '{email}' -> Normalized: '{email_normalized}' -> Hash: {email_hash}"
        )

        user = users_collection.find_one({"email_hash": email_hash})
        if not user:
            return {"success": False, "message": "Пользователь не найден"}

        if "password_hash" not in user:
            logger.error(
                f"User document missing password_hash field. Available fields: {list(user.keys())}"
            )
            return {"success": False, "message": "Ошибка данных пользователя"}

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if user["password_hash"] != password_hash:
            return {"success": False, "message": "Неверный пароль"}

        users_collection.update_one({"_id": user["_id"]}, {"$set": {"last_online": datetime.utcnow()}})

        logger.info(f"Пользователь {user['nickname']} вошел в систему")
        return {
            "success": True,
            "nickname": user["nickname"],
            "user_id": str(user["_id"]),
            "friends": [str(friend) for friend in user.get("friends", [])],
        }
    except Exception as e:
        logger.error(f"Ошибка входа: {e}")
        return {"success": False, "message": "Ошибка при входе в систему"}


@eel.expose
def initialize_user_encryption(user_id, password):
    try:
        existing_keys = ecdh_keys_collection.find_one({"user_id": ObjectId(user_id)})
        if existing_keys:
            return {"success": True, "message": "Ключи уже существуют"}

        result = generate_ecdh_keypair(user_id, password)
        if not result["success"]:
            logger.warning(
                f"Не удалось сгенерировать ECDH ключи для пользователя {user_id}: {result['message']}"
            )
            return {"success": True, "message": "Продолжаем без ECDH шифрования", "ecdh_disabled": True}

        return result
    except Exception as e:
        logger.error(f"Ошибка инициализации шифрования: {e}")
        return {
            "success": True,
            "message": f"Продолжаем без ECDH шифрования: {str(e)}",
            "ecdh_disabled": True,
        }


@eel.expose
def get_user_data(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            return {
                "user_id": str(user["_id"]),
                "nickname": user["nickname"],
                "friends": [str(friend) for friend in user.get("friends", [])],
                "last_online": user.get("last_online", datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S"),
            }
        return None
    except Exception as e:
        logger.error(f"Ошибка получения данных пользователя: {e}")
        return None


@eel.expose
def get_friends(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return []

        friends = user.get("friends", [])
        friend_data = []
        for friend_id in friends:
            friend = users_collection.find_one({"_id": friend_id})
            if friend:
                friend_data.append(
                    {"user_id": str(friend["_id"]), "nickname": friend["nickname"], "email": "encrypted@example.com"}
                )
        return friend_data
    except Exception as e:
        logger.error(f"Ошибка получения списка друзей: {e}")
        return []


@eel.expose
def get_all_users():
    try:
        users = users_collection.find()
        user_data = []
        for user in users:
            user_data.append(
                {"user_id": str(user["_id"]), "nickname": f"User {str(user['_id'])[:8]}", "email": "encrypted@example.com"}
            )
        return user_data
    except Exception as e:
        logger.error(f"Ошибка получения всех пользователей: {e}")
        return []


@eel.expose
def search_users(search_term, current_user_id):
    try:
        users = users_collection.find(
            {"nickname": {"$regex": f"^{search_term}", "$options": "i"}, "_id": {"$ne": ObjectId(current_user_id)}}
        ).limit(10)

        return [
            {
                "user_id": str(user["_id"]),
                "nickname": user["nickname"],
                "is_friend": ObjectId(current_user_id) in user.get("friends", []),
            }
            for user in users
        ]
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

        users_collection.update_one({"_id": ObjectId(current_user_id)}, {"$addToSet": {"friends": ObjectId(friend_id)}})
        users_collection.update_one({"_id": ObjectId(friend_id)}, {"$addToSet": {"friends": ObjectId(current_user_id)}})

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

        users_collection.update_one({"_id": ObjectId(current_user_id)}, {"$pull": {"friends": ObjectId(friend_id)}})
        users_collection.update_one({"_id": ObjectId(friend_id)}, {"$pull": {"friends": ObjectId(current_user_id)}})

        logger.info(f"Пользователь {current_user_id} удалил из друзей {friend_id}")
        return {"success": True, "message": "Пользователь удален из друзей"}
    except Exception as e:
        logger.error(f"Ошибка удаления из друзей: {e}")
        return {"success": False, "message": "Ошибка при удалении из друзей"}


@eel.expose
def send_ecdh_encrypted_message(sender_id, receiver_id, ciphertext_hex, nonce_hex, reply_to_message_id=None):
    try:
        if not ciphertext_hex or not nonce_hex:
            return {"success": False, "message": "Отсутствуют данные шифрования"}

        nonce_bytes = bytes.fromhex(nonce_hex)
        if len(nonce_bytes) != 12:
            return {"success": False, "message": "Неверный размер nonce"}

        is_self_chat = sender_id == receiver_id
        read_status = is_self_chat

        current_time = datetime.utcnow()
        message_data = {
            "sender_id": ObjectId(sender_id),
            "receiver_id": ObjectId(receiver_id),
            "ciphertext": ciphertext_hex,
            "nonce": nonce_hex,
            "is_encrypted": True,
            "encryption_type": "ECDH-AES-GCM",
            "timestamp": current_time,
            "read": read_status,
        }

        if reply_to_message_id:
            message_data["reply_to_message_id"] = ObjectId(reply_to_message_id)

        result = messages_collection.insert_one(message_data)
        logger.info(f"Сообщение с ECDH шифрованием сохранено от {sender_id} к {receiver_id}")

        return {"success": True, "message_id": str(result.inserted_id), "timestamp": current_time.isoformat() + "Z", "read": read_status}
    except Exception as e:
        logger.error(f"Ошибка сохранения ECDH зашифрованного сообщения: {e}")
        return {"success": False, "message": str(e)}


@eel.expose
def get_ecdh_chat_history(user_id, peer_id):
    try:
        messages = messages_collection.find(
            {
                "$or": [
                    {"sender_id": ObjectId(user_id), "receiver_id": ObjectId(peer_id)},
                    {"sender_id": ObjectId(peer_id), "receiver_id": ObjectId(user_id)},
                ],
                "encryption_type": "ECDH-AES-GCM",
            }
        ).sort("timestamp", 1)

        messages_list = []
        for message in messages:
            deleted_for = message.get("deleted_for", [])
            if ObjectId(user_id) in deleted_for:
                continue

            message_data = {
                "id": str(message["_id"]),
                "sender_id": str(message["sender_id"]),
                "receiver_id": str(message["receiver_id"]),
                "ciphertext": message["ciphertext"],
                "nonce": message["nonce"],
                "timestamp": message["timestamp"].isoformat(),
                "read": message.get("read", False),
                "is_encrypted": True,
                "encryption_type": message.get("encryption_type", "ECDH-AES-GCM"),
            }

            if "reply_to_message_id" in message:
                message_data["reply_to_message_id"] = str(message["reply_to_message_id"])
                try:
                    replied_message = messages_collection.find_one({"_id": message["reply_to_message_id"]})
                    if replied_message:
                        message_data["replied_message"] = {
                            "id": str(replied_message["_id"]),
                            "sender_id": str(replied_message["sender_id"]),
                            "is_encrypted": replied_message.get("is_encrypted", False),
                        }
                except Exception as e:
                    logger.error(f"Ошибка получения данных ответного сообщения: {e}")

            messages_list.append(message_data)

        return {"success": True, "messages": messages_list}
    except Exception as e:
        logger.error(f"Ошибка получения ECDH истории чата: {e}")
        return {"success": False, "message": str(e)}


@eel.expose
def get_new_messages(user_id, chat_id, last_message_id=None):
    try:
        query = {
            "$or": [
                {"sender_id": ObjectId(user_id), "receiver_id": ObjectId(chat_id)},
                {"sender_id": ObjectId(chat_id), "receiver_id": ObjectId(user_id)},
            ]
        }

        if last_message_id:
            query["_id"] = {"$gt": ObjectId(last_message_id)}

        messages = messages_collection.find(query).sort("timestamp", 1)

        result = []
        for msg in messages:
            deleted_for = msg.get("deleted_for", [])
            if ObjectId(user_id) in deleted_for:
                continue

            message_data = {
                "id": str(msg["_id"]),
                "sender_id": str(msg["sender_id"]),
                "receiver_id": str(msg["receiver_id"]),
                "timestamp": msg["timestamp"].isoformat(),
                "read": msg.get("read", False),
                "is_encrypted": msg.get("is_encrypted", False),
            }

            if msg.get("is_encrypted"):
                if msg.get("encryption_type") == "ECDH-AES-GCM":
                    message_data.update({"ciphertext": msg.get("ciphertext"), "nonce": msg.get("nonce"), "encryption_type": "ECDH-AES-GCM"})
                else:
                    message_data["text"] = msg.get("encrypted_text", "")
            else:
                message_data["text"] = msg.get("text", "")

            if "reply_to_message_id" in msg:
                message_data["reply_to_message_id"] = str(msg["reply_to_message_id"])

            result.append(message_data)

        messages_to_mark = [m for m in result if m["sender_id"] == chat_id and not m["read"]]
        if messages_to_mark:
            message_ids = [ObjectId(m["id"]) for m in messages_to_mark]
            messages_collection.update_many({"_id": {"$in": message_ids}}, {"$set": {"read": True}})

        return {"success": True, "messages": result}
    except Exception as e:
        logger.error(f"Ошибка получения новых сообщений: {e}")
        return {"success": False, "messages": []}


@eel.expose
def mark_chat_messages_as_read(user_id, peer_id):
    try:
        result = messages_collection.update_many(
            {"sender_id": ObjectId(peer_id), "receiver_id": ObjectId(user_id), "read": False},
            {"$set": {"read": True}},
        )
        logger.info(f"Сообщения от {peer_id} для {user_id} помечены как прочитанные: {result.modified_count} сообщений")
        return {"success": True, "count": result.modified_count}
    except Exception as e:
        logger.error(f"Ошибка пометки сообщений как прочитанных: {e}")
        return {"success": False, "message": str(e)}


@eel.expose
def mark_messages_as_read(sender_id, receiver_id):
    try:
        result = messages_collection.update_many(
            {"sender_id": ObjectId(sender_id), "receiver_id": ObjectId(receiver_id), "read": False},
            {"$set": {"read": True}},
        )
        return {"success": True, "count": result.modified_count}
    except Exception as e:
        logger.error(f"Ошибка пометки сообщений как прочитанных: {e}")
        return {"success": False}


@eel.expose
def get_last_message(user1_id, user2_id):
    try:
        message = messages_collection.find_one(
            {
                "$or": [
                    {"sender_id": ObjectId(user1_id), "receiver_id": ObjectId(user2_id)},
                    {"sender_id": ObjectId(user2_id), "receiver_id": ObjectId(user1_id)},
                ],
                "deleted_for": {"$ne": ObjectId(user1_id)},
            },
            sort=[("timestamp", -1)],
        )

        if not message:
            return None

        message_data = {
            "id": str(message["_id"]),
            "sender_id": str(message["sender_id"]),
            "timestamp": message["timestamp"].isoformat(),
            "is_encrypted": message.get("is_encrypted", False),
            "encryption_type": message.get("encryption_type"),
        }

        if message.get("is_encrypted"):
            if message.get("encryption_type") == "ECDH-AES-GCM":
                message_data.update({"ciphertext": message.get("ciphertext"), "nonce": message.get("nonce"), "text": message.get("ciphertext", "")})
            else:
                message_data.update({"text": message.get("encrypted_text", message.get("text", "[Сообщение]"))})
        else:
            message_data.update({"text": message.get("text", "[Сообщение]")})

        return message_data
    except Exception as e:
        logger.error(f"Error getting last message: {e}")
        return None


@eel.expose
def get_message_data(message_id):
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if not message:
            return None

        message_data = {
            "id": str(message["_id"]),
            "sender_id": str(message["sender_id"]),
            "timestamp": message["timestamp"].isoformat(),
            "is_encrypted": message.get("is_encrypted", False),
        }

        if message.get("is_encrypted"):
            message_data["text"] = message.get("encrypted_text", "[Зашифрованное сообщение]")
        else:
            message_data["text"] = message.get("text", "[Сообщение]")

        return message_data
    except Exception as e:
        logger.error(f"Ошибка получения данных сообщения: {e}")
        return None


@eel.expose
def delete_message(message_id):
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if not message:
            return {"success": False, "message": "Сообщение не найдено"}

        current_user_id = ObjectId(eel.get_current_user_id()())
        if message["sender_id"] != current_user_id:
            return {"success": False, "message": "Вы можете удалять только свои сообщения"}

        sender_id = str(message["sender_id"])
        receiver_id = str(message["receiver_id"])

        result = messages_collection.delete_one({"_id": ObjectId(message_id)})
        if result.deleted_count <= 0:
            return {"success": False, "message": "Сообщение не найдено"}

        logger.info(f"Сообщение {message_id} успешно удалено")
        last_message = get_last_message(sender_id, receiver_id)

        try:
            eel.notify_message_deleted(message_id, sender_id, receiver_id)()
        except Exception as notify_error:
            logger.warning(f"Не удалось уведомить получателя: {notify_error}")

        return {"success": True, "message": "Сообщение удалено", "sender_id": sender_id, "receiver_id": receiver_id, "last_message": last_message}
    except Exception as e:
        logger.error(f"Ошибка удаления сообщения: {e}")
        return {"success": False, "message": "Ошибка при удалении сообщения"}


@eel.expose
def notify_message_deleted(message_id, sender_id, receiver_id):
    try:
        last_message = get_last_message(sender_id, receiver_id)
        return {"success": True, "message_id": message_id, "sender_id": sender_id, "receiver_id": receiver_id, "last_message": last_message}
    except Exception as e:
        logger.error(f"Ошибка уведомления об удалении: {e}")
        return {"success": False, "message": str(e)}


@eel.expose
def check_message_read_status(message_ids):
    try:
        messages = messages_collection.find({"_id": {"$in": [ObjectId(i) for i in message_ids]}})
        return {str(msg["_id"]): msg.get("read", False) for msg in messages}
    except Exception as e:
        logger.error(f"Ошибка проверки статуса прочтения: {e}")
        return {}


@eel.expose
def check_message_read_status_bulk(message_ids):
    try:
        object_ids = []
        for i in message_ids:
            try:
                object_ids.append(ObjectId(i))
            except Exception:
                continue

        if not object_ids:
            return {}

        messages = messages_collection.find({"_id": {"$in": object_ids}})
        return {str(msg["_id"]): msg.get("read", False) for msg in messages}
    except Exception as e:
        logger.error(f"Ошибка проверки статуса прочтения: {e}")
        return {}


@eel.expose
def get_unread_messages_count(user_id, chat_id):
    try:
        count = messages_collection.count_documents(
            {"sender_id": ObjectId(chat_id), "receiver_id": ObjectId(user_id), "read": False}
        )
        return {"success": True, "count": count}
    except Exception as e:
        logger.error(f"Ошибка получения непрочитанных сообщений: {e}")
        return {"success": False, "count": 0}


@eel.expose
def save_draft_message(user_id, chat_id, text):
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {f"drafts.{chat_id}": {"text": text, "timestamp": datetime.utcnow()}}},
            upsert=True,
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
                users_collection.update_one({"_id": ObjectId(user_id)}, {"$unset": {f"drafts.{chat_id}": ""}})
                return None
            return draft["text"]
        return None
    except Exception as e:
        logger.error(f"Ошибка получения черновика: {e}")
        return None


@eel.expose
def clear_draft_message(user_id, chat_id):
    try:
        users_collection.update_one({"_id": ObjectId(user_id)}, {"$unset": {f"drafts.{chat_id}": ""}})
        logger.info(f"Черновик очищен для пользователя {user_id}, чат {chat_id}")
        return {"success": True}
    except Exception as e:
        logger.error(f"Ошибка очистки черновика: {e}")
        return {"success": False}


@eel.expose
def save_reply_state(user_id, chat_id, message_id):
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {f"reply_states.{chat_id}": {"message_id": message_id, "timestamp": datetime.utcnow()}}},
            upsert=True,
        )
        logger.info(f"Состояние ответа сохранено для пользователя {user_id}, чат {chat_id}")
        return {"success": True}
    except Exception as e:
        logger.error(f"Ошибка сохранения состояния ответа: {e}")
        return {"success": False, "message": str(e)}


@eel.expose
def get_reply_state(user_id, chat_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user and "reply_states" in user and chat_id in user["reply_states"]:
            reply_state = user["reply_states"][chat_id]
            if (datetime.utcnow() - reply_state["timestamp"]).total_seconds() > 4 * 3600:
                users_collection.update_one({"_id": ObjectId(user_id)}, {"$unset": {f"reply_states.{chat_id}": ""}})
                return {"success": False, "message": "Состояние ответа устарело"}
            return {"success": True, "message_id": reply_state["message_id"]}
        return {"success": False, "message": "Состояние ответа не найдено"}
    except Exception as e:
        logger.error(f"Ошибка получения состояния ответа: {e}")
        return {"success": False, "message": str(e)}


@eel.expose
def clear_reply_state(user_id, chat_id):
    try:
        users_collection.update_one({"_id": ObjectId(user_id)}, {"$unset": {f"reply_states.{chat_id}": ""}})
        logger.info(f"Состояние ответа очищено для пользователя {user_id}, чат {chat_id}")
        return {"success": True}
    except Exception as e:
        logger.error(f"Ошибка очистки состояния ответа: {e}")
        return {"success": False, "message": str(e)}


@eel.expose
def get_current_user_id():
    return ""


if __name__ == "__main__":
    try:
        import sys

        port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000

        eel.start(
            "login.html",
            size=(1000, 700),
            mode="chrome",
            port=port,
            cmdline_args=["--app-icon=web/logo.ico", "--disable-extensions", "--no-first-run"],
        )
    except Exception as e:
        logger.error(f"Ошибка запуска приложения: {e}")
