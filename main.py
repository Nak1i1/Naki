import eel
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId

# Инициализация MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['messenger_db']
users_collection = db['users']

# Создаем коллекции, если их нет
if 'users' not in db.list_collection_names():
    db.create_collection('users')
    print("Коллекция users создана")

eel.init("web")

@eel.expose
def register_user(nickname, email, password):
    # Проверка существования пользователя
    if users_collection.find_one({"$or": [{"email": email}, {"nickname": nickname}]}):
        return {"success": False, "message": "Пользователь уже существует"}
    
    # Создание нового пользователя
    user_data = {
        "nickname": nickname,
        "email": email,
        "password": password,  # В реальном приложении используйте хеширование!
        "created_at": datetime.now(),
        "friends": []  # Изначально нет друзей
    }
    result = users_collection.insert_one(user_data)
    return {"success": True, "message": "Регистрация успешна!", "user_id": str(result.inserted_id)}

@eel.expose
def login_user(email, password):
    user = users_collection.find_one({"email": email, "password": password})
    if user:
        return {"success": True, "nickname": user["nickname"], "user_id": str(user["_id"])}
    return {"success": False, "message": "Неверные учетные данные"}

@eel.expose
def get_user_data(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            return {
                "nickname": user["nickname"],
                "user_id": str(user["_id"]),
                "friends": [str(friend_id) for friend_id in user.get("friends", [])]
            }
    except:
        pass
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
        }).limit(10)  # Ограничиваем результаты поиска
        
        return [{
            "user_id": str(user["_id"]),
            "nickname": user["nickname"],
            "email": user["email"]
        } for user in users]
    except:
        return []

@eel.expose
def add_friend(current_user_id, friend_id):
    try:
        # Проверяем, что пользователь не пытается добавить себя
        if current_user_id == friend_id:
            return {"success": False, "message": "Нельзя добавить самого себя в друзья"}
        
        # Проверяем существование пользователей
        current_user = users_collection.find_one({"_id": ObjectId(current_user_id)})
        friend_user = users_collection.find_one({"_id": ObjectId(friend_id)})
        
        if not current_user or not friend_user:
            return {"success": False, "message": "Пользователь не найден"}
        
        # Проверяем, что они еще не друзья
        if ObjectId(friend_id) in current_user.get("friends", []):
            return {"success": False, "message": "Этот пользователь уже у вас в друзьях"}
        
        # Добавляем друга
        users_collection.update_one(
            {"_id": ObjectId(current_user_id)},
            {"$addToSet": {"friends": ObjectId(friend_id)}}
        )
        
        return {"success": True, "message": f"{friend_user['nickname']} добавлен(а) в друзья"}
    except Exception as e:
        print("Error adding friend:", e)
        return {"success": False, "message": "Ошибка при добавлении в друзья"}

@eel.expose
def remove_friend(current_user_id, friend_id):
    try:
        # Проверяем существование пользователей
        current_user = users_collection.find_one({"_id": ObjectId(current_user_id)})
        friend_user = users_collection.find_one({"_id": ObjectId(friend_id)})
        
        if not current_user or not friend_user:
            return {"success": False, "message": "Пользователь не найден"}
        
        # Проверяем, что они действительно друзья
        if ObjectId(friend_id) not in current_user.get("friends", []):
            return {"success": False, "message": "Этот пользователь не в вашем списке друзей"}
        
        # Удаляем друга
        users_collection.update_one(
            {"_id": ObjectId(current_user_id)},
            {"$pull": {"friends": ObjectId(friend_id)}}
        )
        
        return {"success": True, "message": f"{friend_user['nickname']} удален(а) из друзей"}
    except Exception as e:
        print("Error removing friend:", e)
        return {"success": False, "message": "Ошибка при удалении из друзей"}

# Запуск приложения с экраном логина
eel.start("login.html", size=(800, 600), mode='chrome')