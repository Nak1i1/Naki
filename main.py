import eel
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId
import logging
import pytz
import os
import base64
from pathlib import Path
import gridfs


# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Инициализация MongoDB
# Настройка MongoDB
try:
    client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
    client.server_info()  # Проверка подключения
    db = client['messenger_db']
    users_collection = db['users']
    messages_collection = db['messages']
    logger.info("Успешное подключение к MongoDB")
except Exception as e:
    logger.error(f"Ошибка подключения к MongoDB: {e}")
    # Создаем локальные коллекции в памяти, если MongoDB недоступна
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
    try:
        client = MongoClient('mongodb://localhost:27017/', connect=False)
        db = client['messenger_db']
        users_collection = db['users']
        messages_collection = db['messages']
        logger.warning("Используется локальное подключение к MongoDB")
    except Exception as e:
        logger.error(f"Не удалось создать локальное подключение: {e}")
        raise

# Создание коллекций и индексов
if 'users' not in db.list_collection_names():
    db.create_collection('users')
    logger.info("Коллекция users создана")

if 'messages' not in db.list_collection_names():
    db.create_collection('messages')
    logger.info("Коллекция messages создана")

messages_collection.create_index([("sender_id", 1), ("receiver_id", 1)])
messages_collection.create_index([("timestamp", 1)])
users_collection.create_index([("email", 1)], unique=True)
users_collection.create_index([("nickname", 1)])

# Функция для получения локального времени
def get_local_time():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

# Инициализация Eel
eel.init("web")

@eel.expose
def register_user(nickname, email, password):
    try:
        if users_collection.find_one({"$or": [{"email": email}, {"nickname": nickname}]}):
            return {"success": False, "message": "Пользователь с таким email или никнеймом уже существует"}
        
        user_data = {
            "nickname": nickname,
            "email": email,
            "password": password,
            "created_at": datetime.utcnow(),
            "friends": [],
            "last_online": datetime.utcnow()
        }
        result = users_collection.insert_one(user_data)
        logger.info(f"Зарегистрирован новый пользователь: {email}")
        return {"success": True, "message": "Регистрация успешна!", "user_id": str(result.inserted_id)}
    except Exception as e:
        logger.error(f"Ошибка регистрации: {e}")
        return {"success": False, "message": "Ошибка при регистрации"}
    
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
                        "email": friend["email"]
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
                "nickname": user["nickname"],
                "email": user["email"]
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
        current_user_id = ObjectId(eel.get_current_user_id()())  # Нужно добавить эту функцию
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
def login_user(email, password):
    try:
        user = users_collection.find_one({"email": email, "password": password})
        if user:
            users_collection.update_one(
                {"_id": user["_id"]},
                {"$set": {"last_online": datetime.utcnow()}}
            )
            logger.info(f"Пользователь {email} вошел в систему")
            return {
                "success": True,
                "nickname": user["nickname"],
                "user_id": str(user["_id"]),
                "friends": [str(friend) for friend in user.get("friends", [])]
            }
        return {"success": False, "message": "Неверные учетные данные"}
    except Exception as e:
        logger.error(f"Ошибка входа: {e}")
        return {"success": False, "message": "Ошибка при входе в систему"}
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
def get_user_data(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            return {
                "nickname": user["nickname"],
                "email": user["email"],
                "user_id": str(user["_id"]),
                "friends": [str(friend) for friend in user.get("friends", [])],
                "last_online": user.get("last_online", datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S")
            }
        return None
    except Exception as e:
        logger.error(f"Ошибка получения данных пользователя: {e}")
        return None

@eel.expose
def search_users(search_term, current_user_id):
    try:
        regex = {"$regex": f".*{search_term}.*", "$options": "i"}
        users = users_collection.find({
            "$or": [
                {"nickname": regex},
                {"email": regex}
            ],
            "_id": {"$ne": ObjectId(current_user_id)}
        }).limit(10)
        
        return [{
            "user_id": str(user["_id"]),
            "nickname": user["nickname"],
            "email": user["email"],
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
        return {"success": True, "message": f"{friend_user['nickname']} добавлен(а) в друзья"}
    except Exception as e:
        logger.error(f"Ошибка добавления в друзья: {e}")
        return {"success": False, "message": "Ошибка при добавлении в друзья"}
    
    
    
    
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
        return {"success": True, "message": f"{friend_user['nickname']} удален(а) из друзей"}
    except Exception as e:
        logger.error(f"Ошибка удаления из друзей: {e}")
        return {"success": False, "message": "Ошибка при удалении из друзей"}

@eel.expose
def send_message(sender_id, receiver_id, text, reply_to=None):
    try:
        logger.info(f"Попытка отправить сообщение: sender_id={sender_id}, receiver_id={receiver_id}, text={text}")
        
        sender = users_collection.find_one({"_id": ObjectId(sender_id)})
        receiver = users_collection.find_one({"_id": ObjectId(receiver_id)})
        
        if not sender or not receiver:
            logger.error("Отправитель или получатель не найдены")
            return {"success": False, "message": "Пользователь не найден"}
        
        utc_time = datetime.utcnow()
        local_time_str = get_local_time()
        
        # Если пользователь отправляет сообщение самому себе, помечаем как прочитанное сразу
        is_self_message = sender_id == receiver_id
        
        message_data = {
            "sender_id": ObjectId(sender_id),
            "receiver_id": ObjectId(receiver_id),
            "text": text,
            "timestamp": utc_time,
            "read": is_self_message,
            "local_timestamp": local_time_str,
            "reply_to": ObjectId(reply_to) if reply_to else None  # Сохраняем ID сообщения, на которое отвечаем
        }
        
        result = messages_collection.insert_one(message_data)
        logger.info(f"Сообщение успешно сохранено в БД, ID: {result.inserted_id}")
        
        # Получаем данные сообщения, на которое отвечаем (если есть)
        reply_message = None
        if reply_to:
            reply_message = messages_collection.find_one({"_id": ObjectId(reply_to)})
        
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": local_time_str,
            "read": is_self_message,
            "text": text,
            "reply_to": reply_to,
            "reply_text": reply_message["text"] if reply_message else None,
            "reply_sender_id": str(reply_message["sender_id"]) if reply_message else None
        }
    except Exception as e:
        logger.error(f"Ошибка отправки сообщения: {str(e)}")
        return {"success": False, "message": "Ошибка при отправке сообщения"}
    
    
    
@eel.expose
def save_reply_state(user_id, chat_id, message_id):
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "reply_states": {  # Изменили на множественное число для хранения состояний для разных чатов
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
def send_media_message(sender_id, receiver_id, media_data, media_type, filename, caption=None):
    try:
        sender = users_collection.find_one({"_id": ObjectId(sender_id)})
        receiver = users_collection.find_one({"_id": ObjectId(receiver_id)})
        
        if not sender or not receiver:
            return {"success": False, "message": "User not found"}
        
        utc_time = datetime.utcnow()
        local_time_str = get_local_time()
        
        is_self_message = sender_id == receiver_id
        
        # Сохраняем медиа данные напрямую в MongoDB (GridFS)
        fs = gridfs.GridFS(db)
        file_id = fs.put(base64.b64decode(media_data), filename=filename, content_type=f"{media_type}/*")
        
        message_data = {
            "sender_id": ObjectId(sender_id),
            "receiver_id": ObjectId(receiver_id),
            "text": caption or f"[{media_type.capitalize()}]",
            "timestamp": utc_time,
            "read": is_self_message,
            "local_timestamp": local_time_str,
            "is_media": True,
            "media_type": media_type,
            "file_id": file_id,  # Сохраняем ID файла в GridFS
            "filename": filename,
            "file_size": len(base64.b64decode(media_data))
        }
        
        result = messages_collection.insert_one(message_data)
        
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": local_time_str,
            "read": is_self_message,
            "file_id": str(file_id)  # Возвращаем ID файла
        }
    except Exception as e:
        logger.error(f"Error sending media message: {str(e)}")
        return {"success": False, "message": "Error sending media message"}

@eel.expose
def get_media_message(message_id):
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if message and message.get("is_media"):
            fs = gridfs.GridFS(db)
            media_file = fs.get(message["file_id"])
            media_data = base64.b64encode(media_file.read()).decode('utf-8')
            
            return {
                "success": True,
                "media_data": media_data,
                "media_type": message["media_type"],
                "filename": message["filename"],
                "file_size": message.get("file_size", 0)
            }
        return {"success": False, "message": "Media message not found"}
    except Exception as e:
        logger.error(f"Error getting media message: {e}")
        return {"success": False, "message": "Error getting media message"}
    
    
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
                "text": message["text"],
                "timestamp": message.get("local_timestamp", message["timestamp"].astimezone().strftime("%Y-%m-%d %H:%M:%S"))
            }
        return None
    except Exception as e:
        logger.error(f"Ошибка получения данных сообщения: {e}")
        return None
    
    
    
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
def get_chat_history(user1_id, user2_id):
    try:
        messages = messages_collection.find({
            "$or": [
                {"sender_id": ObjectId(user1_id), "receiver_id": ObjectId(user2_id)},
                {"sender_id": ObjectId(user2_id), "receiver_id": ObjectId(user1_id)}
            ],
            "deleted_for": {"$ne": ObjectId(user1_id)}  # Исключаем сообщения, удаленные для этого пользователя
        }).sort("timestamp", 1)
        
        # Помечаем текстовые сообщения как прочитанные, но не голосовые
        if user1_id != user2_id:
            messages_collection.update_many(
                {
                    "sender_id": ObjectId(user2_id),
                    "receiver_id": ObjectId(user1_id),
                    "read": False,
                    "is_voice": {"$ne": True}  # Не обновляем статус для голосовых
                },
                {"$set": {"read": True}}
            )
        
        result = []
        for msg in messages:
            # Получаем данные сообщения, на которое есть ответ (если есть)
            reply_message = None
            if msg.get("reply_to"):
                reply_message = messages_collection.find_one({"_id": msg["reply_to"]})
            
            m = {
                "id": str(msg["_id"]),
                "sender_id": str(msg["sender_id"]),
                "receiver_id": str(msg["receiver_id"]),
                "text": msg["text"],
                "timestamp": msg.get("local_timestamp", msg["timestamp"].astimezone().strftime("%Y-%m-%d %H:%M:%S")),
                "read": msg.get("read", False),
                "listened": msg.get("listened", False) if msg.get("is_voice") else True,
                "reply_to": str(msg["reply_to"]) if msg.get("reply_to") else None,
                "reply_text": reply_message["text"] if reply_message else None,
                "reply_sender_id": str(reply_message["sender_id"]) if reply_message else None
            }
            
            # Добавляем информацию о медиафайлах
            if msg.get("is_media"):
                m["isMedia"] = True
                m["mediaType"] = msg["media_type"]
                # Проверяем наличие media_path перед добавлением
                if msg.get("media_path"):
                    m["mediaPath"] = msg["media_path"]
                m["filename"] = msg.get("filename", "")
                m["fileSize"] = msg.get("file_size", 0)
                
            if msg.get("is_voice"):
                m["isVoiceMessage"] = True
                m["voiceData"] = msg.get("voice_data")
                m["duration"] = msg.get("duration", 0)
                m["visualization"] = msg.get("visualization", [])
            result.append(m)
        return result
    except Exception as e:
        logger.error(f"Ошибка получения истории чата: {e}")
        return []
    
    
    

@eel.expose
def check_new_messages(user_id, last_message_id=None):
    try:
        query = {
            "receiver_id": ObjectId(user_id),
            "deleted_for": {"$ne": ObjectId(user_id)}  # Исключаем удаленные сообщения
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
                "text": msg["text"],
                "timestamp": msg.get("local_timestamp", msg["timestamp"].astimezone().strftime("%Y-%m-%d %H:%M:%S")),
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
def send_voice_message(sender_id, receiver_id, voice_data, duration, visualization_data=None):
    try:
        sender = users_collection.find_one({"_id": ObjectId(sender_id)})
        receiver = users_collection.find_one({"_id": ObjectId(receiver_id)})
        
        if not sender or not receiver:
            return {"success": False, "message": "Пользователь не найден"}
        
        utc_time = datetime.utcnow()
        local_time_str = get_local_time()
        
        is_self_message = sender_id == receiver_id
        
        message_data = {
            "sender_id": ObjectId(sender_id),
            "receiver_id": ObjectId(receiver_id),
            "text": "[Голосовое сообщение]",
            "timestamp": utc_time,
            "read": is_self_message,
            "listened": is_self_message,  # Для сообщений самому себе сразу помечаем как прослушанные
            "local_timestamp": local_time_str,
            "is_voice": True,
            "voice_data": voice_data,
            "duration": float(duration),
            "visualization": visualization_data
        }
        
        result = messages_collection.insert_one(message_data)
        
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": local_time_str,
            "read": is_self_message,
            "listened": is_self_message
        }
    except Exception as e:
        logger.error(f"Ошибка отправки голосового сообщения: {e}")
        return {"success": False, "message": "Ошибка при отправке голосового сообщения"}
    
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
def get_voice_message(message_id):
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if message and message.get("is_voice"):
            return {
                "success": True,
                "voice_data": message["voice_data"],
                "duration": message["duration"]
            }
        return {"success": False, "message": "Голосовое сообщение не найдено"}
    except Exception as e:
        logger.error(f"Ошибка получения голосового сообщения: {e}")
        return {"success": False, "message": "Ошибка при получении голосового сообщения"}

@eel.expose
def mark_messages_as_read(sender_id, receiver_id):
    try:
        result = messages_collection.update_many(
            {
                "sender_id": ObjectId(sender_id),
                "receiver_id": ObjectId(receiver_id),
                "read": False,
                "is_voice": {"$ne": True}  # Не помечаем голосовые как прочитанные
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
def get_last_message(user1_id, user2_id):
    try:
        # Ищем последнее сообщение, которое НЕ удалено для user1_id
        message = messages_collection.find_one({
            "$or": [
                {"sender_id": ObjectId(user1_id), "receiver_id": ObjectId(user2_id)},
                {"sender_id": ObjectId(user2_id), "receiver_id": ObjectId(user1_id)}
            ],
            "deleted_for": {"$ne": ObjectId(user1_id)}  # Исключаем сообщения, удаленные для этого пользователя
        }, sort=[("timestamp", -1)])
        
        if message:
            return {
                "text": message["text"],
                "sender_id": str(message["sender_id"]),
                "timestamp": message.get("local_timestamp", message["timestamp"].astimezone().strftime("%Y-%m-%d %H:%M:%S"))
            }
        return None
    except Exception as e:
        logger.error(f"Error getting last message: {e}")
        return None
    
# Запуск приложения
if __name__ == '__main__':
    try:
        eel.start('login.html', size=(1000, 700), mode='chrome', port=8000)
    except Exception as e:
        logger.error(f"Ошибка запуска приложения: {e}")