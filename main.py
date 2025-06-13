import eel
from pymongo import MongoClient
from datetime import datetime

# Инициализация MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['messenger_db']
users_collection = db['users']

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
        "created_at": datetime.now()
    }
    users_collection.insert_one(user_data)
    return {"success": True, "message": "Регистрация успешна!"}

@eel.expose
def login_user(email, password):
    user = users_collection.find_one({"email": email, "password": password})
    if user:
        return {"success": True, "nickname": user["nickname"]}
    return {"success": False, "message": "Неверные учетные данные"}

# Запуск приложения с экраном логина
eel.start("login.html", size=(800, 600))