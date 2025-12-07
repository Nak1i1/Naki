import time
import threading
import random
import string
from pymongo import MongoClient
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

class OptimizedStressTester:
    def __init__(self, db_uri="mongodb://localhost:27017/", db_name="messenger_db"):
        self.client = MongoClient(db_uri)
        self.db = self.client[db_name]
        self.messages_collection = self.db['optimized_stress_test']
        self.performance_data = []
        self.total_messages = 0
        self.lock = threading.Lock()
        self.running = True
        self.test_start_time = 0
        
    def generate_16char_message(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    
    def optimized_sender(self, thread_id, duration=10):
        batch = []
        batch_size = 100
        
        end_time = self.test_start_time + duration
        
        while time.time() < end_time and self.running:
            try:
                message = {
                    "content": self.generate_16char_message(),
                    "timestamp": datetime.utcnow(),
                    "thread_id": thread_id,
                    "send_time": time.time()
                }
                batch.append(message)
                
                if len(batch) >= batch_size and time.time() < end_time - 0.05:
                    self.messages_collection.insert_many(batch)
                    with self.lock:
                        self.total_messages += len(batch)
                    batch = []
                    
            except Exception as e:
                print(f"Ошибка в потоке {thread_id}: {e}")
                break
        
        if batch and len(batch) <= batch_size * 2:
            try:
                self.messages_collection.insert_many(batch)
                with self.lock:
                    self.total_messages += len(batch)
            except Exception as e:
                print(f"Ошибка финальной отправки в потоке {thread_id}: {e}")
    
    def smooth_monitor_performance(self, duration=10):
        last_count = 0
        last_time = self.test_start_time
        
        while time.time() - self.test_start_time < duration and self.running:
            time.sleep(0.2)
            
            current_time = time.time()
            elapsed = current_time - last_time
            
            with self.lock:
                current_count = self.total_messages
            
            if elapsed > 0:
                instant_speed = (current_count - last_count) / elapsed
            else:
                instant_speed = 0
            
            self.performance_data.append({
                'timestamp': current_time - self.test_start_time,
                'total_messages': current_count,
                'instant_speed': instant_speed
            })
            
            last_count = current_count
            last_time = current_time
    
    def analyze_optimized_performance(self, duration, num_threads):
        if not self.performance_data:
            print("❌ Нет данных для анализа")
            return
        
        timestamps = [p['timestamp'] for p in self.performance_data]
        speeds = [p['instant_speed'] for p in self.performance_data]
        
        stable_indices = [i for i, t in enumerate(timestamps) if t >= 2]
        
        if stable_indices:
            stable_speeds = [speeds[i] for i in stable_indices]
            avg_speed = np.mean(stable_speeds)
            max_speed = max(stable_speeds)
            min_speed = min(stable_speeds)
            std_speed = np.std(stable_speeds)
        else:
            avg_speed = np.mean(speeds)
            max_speed = max(speeds)
            min_speed = min(speeds)
            std_speed = np.std(speeds)
        
        print(f"\n📊 РЕЗУЛЬТАТЫ ОПТИМИЗИРОВАННОГО ТЕСТА:")
        print(f"├─ Всего сообщений: {self.total_messages:,}")
        print(f"├─ Общее время: {duration:.2f} сек")
        print(f"├─ Средняя скорость: {avg_speed:,.0f} сообщ/сек")
        print(f"├─ Пиковая скорость: {max_speed:,.0f} сообщ/сек")
        print(f"├─ Минимальная скорость: {min_speed:,.0f} сообщ/сек")
        print(f"├─ Стандартное отклонение: {std_speed:,.0f} сообщ/сек")
        print(f"└─ Потоков использовано: {num_threads}")
        
        self.analyze_by_seconds(timestamps, speeds, duration)
        self.plot_optimized_performance(timestamps, speeds, avg_speed, max_speed)
    
    def analyze_by_seconds(self, timestamps, speeds, duration):
        print(f"\n📈 ПРОИЗВОДИТЕЛЬНОСТЬ ПО СЕКУНДАМ:")
        
        for second in range(int(duration)):
            second_speeds = [s for t, s in zip(timestamps, speeds) if second <= t < second + 1 and s > 0]
            if second_speeds:
                avg_second_speed = np.mean(second_speeds)
                max_second_speed = max(second_speeds)
                
                if second == 0:
                    trend = "🔄"
                else:
                    prev_speeds = [s for t, s in zip(timestamps, speeds) if second-1 <= t < second and s > 0]
                    if prev_speeds:
                        prev_avg = np.mean(prev_speeds)
                        if avg_second_speed > prev_avg * 1.1:
                            trend = "📈"
                        elif avg_second_speed < prev_avg * 0.9:
                            trend = "📉"
                        else:
                            trend = "➡️"
                    else:
                        trend = "➡️"
                
                print(f"Секунда {second}: {avg_second_speed:6.0f} сообщ/сек (макс: {max_second_speed:6.0f}) {trend}")
    
    def plot_optimized_performance(self, timestamps, speeds, avg_speed, max_speed):
        plt.figure(figsize=(12, 6))
        
        plt.plot(timestamps, speeds, 'b-', alpha=0.7, linewidth=1, label='Мгновенная скорость')
        plt.fill_between(timestamps, speeds, alpha=0.3)
        
        plt.axhline(y=avg_speed, color='r', linestyle='--', 
                   label=f'Средняя: {avg_speed:,.0f} сообщ/сек')
        plt.axhline(y=max_speed, color='g', linestyle='--', 
                   label=f'Максимальная: {max_speed:,.0f} сообщ/сек')
        
        if len(timestamps) > 0:
            stable_start = 2
            plt.axvspan(stable_start, max(timestamps), alpha=0.2, color='green', 
                       label='Стабильная зона работы')
        
        plt.title('Оптимизированная производительность MongoDB\n(Баланс скорости и стабильности)', 
                 fontweight='bold', fontsize=12)
        plt.xlabel('Время (секунды)', fontsize=10)
        plt.ylabel('Сообщений в секунду', fontsize=10)
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        stats_text = f'''Статистика:
Всего сообщений: {self.total_messages:,}
Средняя скорость: {avg_speed:,.0f} сообщ/сек
Максимальная скорость: {max_speed:,.0f} сообщ/сек
Рекомендуемая нагрузка: {avg_speed * 0.7:,.0f} сообщ/сек'''
        
        plt.text(0.02, 0.98, stats_text, transform=plt.gca().transAxes,
                verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8),
                fontsize=9)
        
        plt.tight_layout()
        plt.show()
    
    def run_optimized_test(self, num_threads=20, duration=10):
        print(f"⚡ ЗАПУСК ОПТИМИЗИРОВАННОГО ТЕСТА")
        print(f"Баланс между скоростью и стабильностью")
        
        try:
            self.messages_collection.delete_many({})
        except:
            pass
        
        self.performance_data = []
        self.total_messages = 0
        self.running = True
        self.test_start_time = time.time()
        
        monitor_thread = threading.Thread(target=self.smooth_monitor_performance, args=(duration,))
        monitor_thread.start()
        
        sender_threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=self.optimized_sender, args=(i, duration))
            sender_threads.append(thread)
            thread.start()
        
        time.sleep(duration - 0.1)
        self.running = False
        
        for thread in sender_threads:
            thread.join()
        
        monitor_thread.join()
        
        total_time = time.time() - self.test_start_time
        self.analyze_optimized_performance(total_time, num_threads)
        
        try:
            self.messages_collection.delete_many({})
        except:
            pass
        
        return self.performance_data

if __name__ == "__main__":
    tester = OptimizedStressTester()
    tester.run_optimized_test(num_threads=20, duration=10)