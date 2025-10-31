@eel.expose
def send_encrypted_media_message(sender_id, receiver_id, file_data, media_type, filename, caption=None):
    """Отправка зашифрованного медиа-сообщения"""
    try:
        # Вычисляем или получаем общий секрет
        secret_result = get_shared_secret(sender_id, receiver_id)
        if not secret_result["success"]:
            secret_result = compute_shared_secret(sender_id, receiver_id)
            if not secret_result["success"]:
                return {"success": False, "message": "Не удалось установить безопасное соединение"}
        
        shared_secret = base64.b64decode(secret_result["shared_secret"])
        
        # Декодируем base64 данные файла
        file_binary_data = base64.b64decode(file_data)
        
        # Шифруем данные файла
        encrypted_media_data = ECDHZKEncryption.encrypt_file(file_binary_data, shared_secret)
        
        # Проверяем размер данных
        if len(encrypted_media_data) > 20 * 1024 * 1024:
            return {"success": False, "message": "File too large"}
        
        sender = users_collection.find_one({"_id": ObjectId(sender_id)})
        receiver = users_collection.find_one({"_id": ObjectId(receiver_id)})
        
        if not sender or not receiver:
            return {"success": False, "message": "User not found"}
        
        utc_time = datetime.utcnow()
        is_self_message = sender_id == receiver_id
        
        # Сохраняем зашифрованные медиа данные в GridFS
        fs = gridfs.GridFS(db)
        file_id = fs.put(base64.b64decode(encrypted_media_data), filename=filename, content_type=f"{media_type}/*")
        
        # Шифруем caption если он есть
        encrypted_caption = None
        if caption:
            encrypted_caption = ECDHZKEncryption.encrypt_message(caption, shared_secret)
        
        message_data = {
            "sender_id": ObjectId(sender_id),
            "receiver_id": ObjectId(receiver_id),
            "encrypted_text": encrypted_caption or f"[{media_type.capitalize()}]",
            "timestamp": utc_time,
            "read": is_self_message,
            "is_media": True,
            "media_type": media_type,
            "file_id": file_id,
            "filename": filename,
            "is_encrypted": True,
            "encryption_type": "ecdh_aes_gcm"
        }
        
        result = messages_collection.insert_one(message_data)
        
        return {
            "success": True,
            "message_id": str(result.inserted_id),
            "timestamp": utc_time.isoformat(),
            "read": is_self_message
        }
    except Exception as e:
        logger.error(f"Error sending encrypted media message: {str(e)}")
        return {"success": False, "message": f"Error sending media message: {str(e)}"}
    
    
    
    
@eel.expose
def get_encrypted_media_message(message_id, user_id):
    """Получение и дешифрование медиа-сообщения"""
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if message and message.get("is_media"):
            # Определяем собеседника
            if str(message["sender_id"]) == user_id:
                peer_user_id = str(message["receiver_id"])
            else:
                peer_user_id = str(message["sender_id"])
            
            # Получаем общий секрет
            secret_result = get_shared_secret(user_id, peer_user_id)
            if not secret_result["success"]:
                return {"success": False, "message": "Не удалось получить ключ для дешифрования"}
            
            shared_secret = base64.b64decode(secret_result["shared_secret"])
            
            fs = gridfs.GridFS(db)
            if fs.exists(message["file_id"]):
                media_file = fs.get(message["file_id"])
                encrypted_media_data = base64.b64encode(media_file.read()).decode('utf-8')
                
                # Дешифруем медиа данные
                decrypted_media_data = ECDHZKEncryption.decrypt_file(encrypted_media_data, shared_secret)
                
                return {
                    "success": True,
                    "media_data": base64.b64encode(decrypted_media_data).decode('utf-8'),
                    "media_type": message["media_type"],
                    "filename": message["filename"]
                }
            return {"success": False, "message": "Файл не найден"}
        return {"success": False, "message": "Медиа-сообщение не найдено"}
    except Exception as e:
        logger.error(f"Ошибка получения медиа-сообщения: {e}")
        return {"success": False, "message": "Ошибка при получении медиа-сообщения"}
    
    
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
\
    
    
    
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
def get_chat_history(user1_id, user2_id):
    """Получение истории чата с автоматическим дешифрованием"""
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
            message_data = {
                "id": str(msg["_id"]),
                "sender_id": str(msg["sender_id"]),
                "receiver_id": str(msg["receiver_id"]),
                "encrypted_text": msg.get("encrypted_text", ""),
                "timestamp": msg["timestamp"].isoformat(),
                "read": msg.get("read", False),
                "is_encrypted": msg.get("is_encrypted", True),
                "is_media": msg.get("is_media", False),
                "is_voice": msg.get("is_voice", False),
                "encryption_type": msg.get("encryption_type", "unknown")
            }
            
            # Для медиа-сообщений
            if msg.get("is_media"):
                message_data["media_type"] = msg.get("media_type")
                message_data["filename"] = msg.get("filename")
                message_data["text"] = f"[{msg.get('media_type', 'Медиа')}]"
            
            # Для голосовых сообщений
            elif msg.get("is_voice"):
                message_data["duration"] = msg.get("duration", 0)
                message_data["text"] = "[Голосовое сообщение]"
            
            # Для текстовых сообщений
            else:
                message_data["text"] = "[Зашифрованное сообщение]"
            
            if msg.get("reply_to"):
                message_data["reply_to"] = str(msg["reply_to"])
                
            result.append(message_data)
        return result
    except Exception as e:
        logger.error(f"Ошибка получения истории чата: {e}")
        return []
    
    
@eel.expose
def get_chat_history(user1_id, user2_id):
    """Получение истории чата с автоматическим дешифрованием"""
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
            message_data = {
                "id": str(msg["_id"]),
                "sender_id": str(msg["sender_id"]),
                "receiver_id": str(msg["receiver_id"]),
                "encrypted_text": msg.get("encrypted_text", ""),
                "timestamp": msg["timestamp"].isoformat(),
                "read": msg.get("read", False),
                "is_encrypted": msg.get("is_encrypted", True),
                "encryption_type": msg.get("encryption_type", "unknown")
            }
            
            # Для текстовых сообщений
            message_data["text"] = "[Зашифрованное сообщение]"
            
            if msg.get("reply_to"):
                message_data["reply_to"] = str(msg["reply_to"])
                
            result.append(message_data)
        return result
    except Exception as e:
        logger.error(f"Ошибка получения истории чата: {e}")
        return []
    
    
    
@staticmethod
    def encrypt_file(file_data, shared_secret):
        """Шифрование файла с использованием общего секрета"""
        try:
            # Генерируем случайный IV
            iv = secrets.token_bytes(12)
            
            # Создаем cipher с AES-GCM
            cipher = Cipher(algorithms.AES(shared_secret), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Шифруем данные файла
            encrypted_data = encryptor.update(file_data) + encryptor.finalize()
            
            # Объединяем IV + зашифрованные данные + тег аутентификации
            result = iv + encryptor.tag + encrypted_data
            
            return base64.b64encode(result).decode()
        except Exception as e:
            logger.error(f"Ошибка шифрования файла: {e}")
            raise
        
        
    @staticmethod
    def decrypt_file(encrypted_file_data, shared_secret):
        """Дешифрование файла с использованием общего секрета"""
        try:
            # Декодируем из base64
            encrypted_data = base64.b64decode(encrypted_file_data)
            
            # Извлекаем компоненты
            iv = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            # Создаем cipher с AES-GCM
            cipher = Cipher(algorithms.AES(shared_secret), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Дешифруем данные файла
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted_data
        except Exception as e:
            logger.error(f"Ошибка дешифрования файла: {e}")
            
            
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
                "text": "[Зашифрованное сообщение]",
                "timestamp": msg["timestamp"].isoformat(),
                "read": True
            }
            result.append(m)
        return result
    except Exception as e:
        logger.error(f"Ошибка проверки новых сообщений: {e}")
        return []
    
    
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
