import eel
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId
import logging
import pytz

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Инициализация MongoDB
try:
    client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
    client.server_info()  # Проверка подключения
    db = client['messenger_db']
    users_collection = db['users']
    messages_collection = db['messages']
    logger.info("Успешное подключение к MongoDB")
except Exception as e:
    logger.error(f"Ошибка подключения к MongoDB: {e}")
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
def send_message(sender_id, receiver_id, text):
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
            "read": is_self_message,  # True если сообщение самому себе
            "local_timestamp": local_time_str
        }
        
        result = messages_collection.insert_one(message_data)
        logger.info(f"Сообщение успешно сохранено в БД, ID: {result.inserted_id}")
        
        # Если это не сообщение самому себе и это первое сообщение - добавляем в друзья
        if not is_self_message:
            existing_messages = messages_collection.count_documents({
                "$or": [
                    {"sender_id": ObjectId(sender_id), "receiver_id": ObjectId(receiver_id)},
                    {"sender_id": ObjectId(receiver_id), "receiver_id": ObjectId(sender_id)}
                ]
            })
            
            if existing_messages == 0:
                add_friend_result = add_friend(sender_id, receiver_id)
                if not add_friend_result["success"]:
                    logger.warning(f"Не удалось автоматически добавить в друзья: {add_friend_result['message']}")
        
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": local_time_str,
            "read": is_self_message,
            "text": text  # Добавляем текст сообщения в ответ
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
            ]
        }).sort("timestamp", 1)
        
        # Помечаем сообщения как прочитанные только если они адресованы нам и это не чат с самим собой
        if user1_id != user2_id:
            messages_collection.update_many(
                {
                    "sender_id": ObjectId(user2_id),
                    "receiver_id": ObjectId(user1_id),
                    "read": False
                },
                {"$set": {"read": True}}
            )
        
        return [{
            "id": str(msg["_id"]),
            "sender_id": str(msg["sender_id"]),
            "receiver_id": str(msg["receiver_id"]),
            "text": msg["text"],
            "timestamp": msg.get("local_timestamp", msg["timestamp"].astimezone().strftime("%Y-%m-%d %H:%M:%S")),
            "read": msg.get("read", False)
        } for msg in messages]
    except Exception as e:
        logger.error(f"Ошибка получения истории чата: {e}")
        return []

@eel.expose
def check_new_messages(user_id, last_message_id=None):
    try:
        query = {"receiver_id": ObjectId(user_id)}
        if last_message_id:
            query["_id"] = {"$gt": ObjectId(last_message_id)}
        
        messages_cursor = messages_collection.find(query).sort("timestamp", 1)
        messages = list(messages_cursor)

        if messages:
            messages_collection.update_many(
                {"_id": {"$in": [msg["_id"] for msg in messages]}},
                {"$set": {"read": True}}
            )
        
        return [{
            "id": str(msg["_id"]),
            "sender_id": str(msg["sender_id"]),
            "receiver_id": str(msg["receiver_id"]),
            "text": msg["text"],
            "timestamp": msg.get("local_timestamp", msg["timestamp"].astimezone().strftime("%Y-%m-%d %H:%M:%S")),
            "read": True
        } for msg in messages]
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
def get_last_message(user1_id, user2_id):
    try:
        message = messages_collection.find_one({
            "$or": [
                {"sender_id": ObjectId(user1_id), "receiver_id": ObjectId(user2_id)},
                {"sender_id": ObjectId(user2_id), "receiver_id": ObjectId(user1_id)}
            ]
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