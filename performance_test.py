import time
import statistics
import json
import secrets
import os
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
import matplotlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import concurrent.futures
import threading
from queue import Queue
import warnings

matplotlib.rcParams['font.sans-serif'] = ['DejaVu Sans']
matplotlib.rcParams['axes.unicode_minus'] = False

class EnhancedEncryptionPerformanceTester:
    
    def __init__(self):
        self.results = []
        self.ten_second_results = {}
        self.multithreading_results = {}
        self.key_exchange_results = {}
        
    def generate_test_data(self):
        """Генерация тестовых данных разного размера"""
        test_messages = []
        
        sizes = [10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000, 500000]
        
        for size in sizes:
            if size <= 10000:
                text = secrets.token_hex(size // 2)[:size]
            else:
                text = secrets.token_bytes(size // 2).hex()[:size]
            
            test_messages.append({
                'size_bytes': len(text.encode('utf-8')) if isinstance(text, str) else len(text),
                'size_chars': size,
                'text': text,
                'type': 'text' if isinstance(text, str) else 'hex'
            })
        
        return test_messages
    
    def test_aes_gcm_performance(self):
        """Тестирование производительности AES-256-GCM"""
        print("=== ТЕСТИРОВАНИЕ ПРОИЗВОДИТЕЛЬНОСТИ AES-256-GCM ===")
        
        test_messages = self.generate_test_data()
        key = secrets.token_bytes(32)
        aesgcm = AESGCM(key)
        
        results = []
        
        for msg_data in test_messages:
            text = msg_data['text']
            size_bytes = msg_data['size_bytes']
            
            print(f"\nТестирование: {size_bytes:,} байт ({msg_data['size_chars']:,} символов)")
            
            if isinstance(text, str):
                data = text.encode('utf-8')
            else:
                data = text.encode('utf-8') if isinstance(text, str) else text
            
            encryption_times = []
            decryption_times = []
            throughput_encryption = []
            throughput_decryption = []
            
            for i in range(20):
                nonce = secrets.token_bytes(12)
                
                start_time = time.perf_counter_ns()
                ciphertext = aesgcm.encrypt(nonce, data, None)
                end_time = time.perf_counter_ns()
                encryption_time = (end_time - start_time) / 1_000_000
                encryption_times.append(encryption_time)
                throughput_encryption.append(size_bytes / (encryption_time / 1000) if encryption_time > 0 else 0)
                
                start_time = time.perf_counter_ns()
                decrypted = aesgcm.decrypt(nonce, ciphertext, None)
                end_time = time.perf_counter_ns()
                decryption_time = (end_time - start_time) / 1_000_000
                decryption_times.append(decryption_time)
                throughput_decryption.append(size_bytes / (decryption_time / 1000) if decryption_time > 0 else 0)
            
            avg_encryption = statistics.mean(encryption_times)
            std_encryption = statistics.stdev(encryption_times) if len(encryption_times) > 1 else 0
            avg_throughput_enc = statistics.mean(throughput_encryption)
            
            avg_decryption = statistics.mean(decryption_times)
            std_decryption = statistics.stdev(decryption_times) if len(decryption_times) > 1 else 0
            avg_throughput_dec = statistics.mean(throughput_decryption)
            
            latency_encryption = avg_encryption
            latency_decryption = avg_decryption
            
            result = {
                'size_bytes': size_bytes,
                'size_chars': msg_data['size_chars'],
                'encryption_ms': round(avg_encryption, 3),
                'encryption_std': round(std_encryption, 3),
                'decryption_ms': round(avg_decryption, 3),
                'decryption_std': round(std_decryption, 3),
                'throughput_encryption_mbps': round(avg_throughput_enc / 125000, 3),
                'throughput_decryption_mbps': round(avg_throughput_dec / 125000, 3),
                'latency_encryption_ms': round(latency_encryption, 3),
                'latency_decryption_ms': round(latency_decryption, 3)
            }
            
            results.append(result)
            
            print(f"  Шифрование: {avg_encryption:.3f} ± {std_encryption:.3f} мс")
            print(f"  Дешифрование: {avg_decryption:.3f} ± {std_decryption:.3f} мс")
            print(f"  Пропускная способность шифр.: {avg_throughput_enc / 125000:.3f} Мбит/с")
            print(f"  Пропускная способность дешифр.: {avg_throughput_dec / 125000:.3f} Мбит/с")
        
        self.results = results
        
        with open('aes_gcm_performance.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nРезультаты сохранены в aes_gcm_performance.json")
        return results
    
    def test_key_exchange_performance(self):
        """Тестирование производительности обмена ключами ECDH"""
        print("\n=== ТЕСТИРОВАНИЕ ПРОИЗВОДИТЕЛЬНОСТИ ECDH (P-256) ===")
        
        results = {
            'key_generation': [],
            'key_exchange': [],
            'derivation': []
        }
        
        for i in range(50):
            start_time = time.perf_counter_ns()
            private_key_a = ec.generate_private_key(ec.SECP256R1())
            public_key_a = private_key_a.public_key()
            key_gen_time = (time.perf_counter_ns() - start_time) / 1_000_000
            results['key_generation'].append(key_gen_time)
            
            private_key_b = ec.generate_private_key(ec.SECP256R1())
            public_key_b = private_key_b.public_key()
            
            start_time = time.perf_counter_ns()
            shared_key_a = private_key_a.exchange(ec.ECDH(), public_key_b)
            key_exchange_time = (time.perf_counter_ns() - start_time) / 1_000_000
            results['key_exchange'].append(key_exchange_time)
            
            start_time = time.perf_counter_ns()
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data'
            ).derive(shared_key_a)
            derivation_time = (time.perf_counter_ns() - start_time) / 1_000_000
            results['derivation'].append(derivation_time)
        
        avg_results = {
            'key_generation_ms': round(statistics.mean(results['key_generation']), 3),
            'key_generation_std': round(statistics.stdev(results['key_generation']), 3),
            'key_exchange_ms': round(statistics.mean(results['key_exchange']), 3),
            'key_exchange_std': round(statistics.stdev(results['key_exchange']), 3),
            'key_derivation_ms': round(statistics.mean(results['derivation']), 3),
            'key_derivation_std': round(statistics.stdev(results['derivation']), 3),
            'total_handshake_ms': round(
                statistics.mean(results['key_generation']) * 2 +
                statistics.mean(results['key_exchange']) +
                statistics.mean(results['derivation']), 3
            )
        }
        
        print(f"Генерация ключа: {avg_results['key_generation_ms']:.3f} ± {avg_results['key_generation_std']:.3f} мс")
        print(f"Обмен ключами: {avg_results['key_exchange_ms']:.3f} ± {avg_results['key_exchange_std']:.3f} мс")
        print(f"Производная ключа: {avg_results['key_derivation_ms']:.3f} ± {avg_results['key_derivation_std']:.3f} мс")
        print(f"Полное рукопожатие: {avg_results['total_handshake_ms']:.3f} мс")
        
        self.key_exchange_results = avg_results
        
        with open('key_exchange_performance.json', 'w') as f:
            json.dump(avg_results, f, indent=2)
        
        return avg_results
    
    def test_multithreading_performance(self, num_threads=4):
        """Тестирование производительности в многопоточном режиме"""
        print(f"\n=== ТЕСТИРОВАНИЕ МНОГОПОТОЧНОСТИ ({num_threads} потока) ===")
        
        key = secrets.token_bytes(32)
        test_data = secrets.token_bytes(1024)
        
        def encrypt_worker(data, results_queue):
            aesgcm = AESGCM(key)
            nonce = secrets.token_bytes(12)
            start_time = time.perf_counter_ns()
            ciphertext = aesgcm.encrypt(nonce, data, None)
            end_time = time.perf_counter_ns()
            results_queue.put((end_time - start_time) / 1_000_000)
        
        def decrypt_worker(ciphertext, nonce, results_queue):
            aesgcm = AESGCM(key)
            start_time = time.perf_counter_ns()
            aesgcm.decrypt(nonce, ciphertext, None)
            end_time = time.perf_counter_ns()
            results_queue.put((end_time - start_time) / 1_000_000)
        
        encryption_times = []
        decryption_times = []
        
        for _ in range(10):
            results_queue = Queue()
            threads = []
            
            for _ in range(num_threads):
                t = threading.Thread(target=encrypt_worker, args=(test_data, results_queue))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
            
            while not results_queue.empty():
                encryption_times.append(results_queue.get())
        
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, test_data, None)
        
        for _ in range(10):
            results_queue = Queue()
            threads = []
            
            for _ in range(num_threads):
                t = threading.Thread(target=decrypt_worker, args=(ciphertext, nonce, results_queue))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
            
            while not results_queue.empty():
                decryption_times.append(results_queue.get())
        
        avg_encryption = statistics.mean(encryption_times)
        avg_decryption = statistics.mean(decryption_times)
        throughput_encryption = (num_threads * len(test_data) * 8) / (avg_encryption / 1000) / 1_000_000
        throughput_decryption = (num_threads * len(test_data) * 8) / (avg_decryption / 1000) / 1_000_000
        
        results = {
            'num_threads': num_threads,
            'avg_encryption_ms': round(avg_encryption, 3),
            'avg_decryption_ms': round(avg_decryption, 3),
            'throughput_encryption_mbps': round(throughput_encryption, 3),
            'throughput_decryption_mbps': round(throughput_decryption, 3),
            'total_operations': num_threads * 10,
            'data_per_operation_bytes': len(test_data)
        }
        
        print(f"Среднее время шифрования (на поток): {avg_encryption:.3f} мс")
        print(f"Среднее время дешифрования (на поток): {avg_decryption:.3f} мс")
        print(f"Пропускная способность шифрования: {throughput_encryption:.3f} Мбит/с")
        print(f"Пропускная способность дешифрования: {throughput_decryption:.3f} Мбит/с")
        print(f"Всего операций: {results['total_operations']}")
        
        self.multithreading_results = results
        
        with open('multithreading_performance.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def test_memory_usage(self):
        """Тестирование использования памяти"""
        print("\n=== ТЕСТИРОВАНИЕ ИСПОЛЬЗОВАНИЯ ПАМЯТИ ===")
        
        import psutil
        import gc
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024
        
        key = secrets.token_bytes(32)
        aesgcm = AESGCM(key)
        
        test_sizes = [1000, 10000, 100000, 1000000]
        results = []
        
        for size in test_sizes:
            gc.collect()
            before_memory = process.memory_info().rss / 1024 / 1024
            
            data = secrets.token_bytes(size)
            nonce = secrets.token_bytes(12)
            
            ciphertexts = []
            for _ in range(100):
                ciphertext = aesgcm.encrypt(nonce, data, None)
                ciphertexts.append(ciphertext)
            
            after_memory = process.memory_info().rss / 1024 / 1024
            memory_increase = after_memory - before_memory
            
            gc.collect()
            final_memory = process.memory_info().rss / 1024 / 1024
            
            results.append({
                'data_size_bytes': size,
                'iterations': 100,
                'initial_memory_mb': round(initial_memory, 2),
                'before_memory_mb': round(before_memory, 2),
                'after_memory_mb': round(after_memory, 2),
                'memory_increase_mb': round(memory_increase, 2),
                'final_memory_mb': round(final_memory, 2),
                'memory_per_operation_mb': round(memory_increase / 100, 4)
            })
            
            print(f"Размер данных: {size:,} байт, Использовано памяти: {memory_increase:.2f} МБ")
            print(f"  Память на операцию: {memory_increase / 100:.4f} МБ")
        
        with open('memory_usage.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def test_10_second_stress(self):
        """10-секундный стресс-тест"""
        print("\n=== 10-СЕКУНДНЫЙ СТРЕСС-ТЕСТ ===")
        
        key = secrets.token_bytes(32)
        aesgcm = AESGCM(key)
        test_data = secrets.token_bytes(4096)
        
        encryption_count = 0
        decryption_count = 0
        encryption_times = []
        decryption_times = []
        
        start_time = time.perf_counter()
        end_time = start_time + 10
        
        print("Тестирование шифрования...")
        while time.perf_counter() < end_time:
            nonce = secrets.token_bytes(12)
            operation_start = time.perf_counter()
            ciphertext = aesgcm.encrypt(nonce, test_data, None)
            operation_end = time.perf_counter()
            encryption_times.append((operation_end - operation_start) * 1000)
            encryption_count += 1
        
        encryption_rate = encryption_count / 10
        avg_encryption_time = statistics.mean(encryption_times) if encryption_times else 0
        encryption_throughput = (encryption_count * len(test_data) * 8) / 10 / 1_000_000
        
        print("Тестирование дешифрования...")
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, test_data, None)
        
        start_time = time.perf_counter()
        end_time = start_time + 10
        
        while time.perf_counter() < end_time:
            operation_start = time.perf_counter()
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            operation_end = time.perf_counter()
            decryption_times.append((operation_end - operation_start) * 1000)
            decryption_count += 1
        
        decryption_rate = decryption_count / 10
        avg_decryption_time = statistics.mean(decryption_times) if decryption_times else 0
        decryption_throughput = (decryption_count * len(test_data) * 8) / 10 / 1_000_000
        
        results = {
            'encryption_operations': encryption_count,
            'encryption_rate_ops_per_sec': round(encryption_rate, 1),
            'avg_encryption_time_ms': round(avg_encryption_time, 3),
            'encryption_throughput_mbps': round(encryption_throughput, 3),
            'decryption_operations': decryption_count,
            'decryption_rate_ops_per_sec': round(decryption_rate, 1),
            'avg_decryption_time_ms': round(avg_decryption_time, 3),
            'decryption_throughput_mbps': round(decryption_throughput, 3),
            'data_size_bytes': len(test_data),
            'total_data_processed_mb': round((encryption_count + decryption_count) * len(test_data) / 1024 / 1024, 2)
        }
        
        print(f"Операций шифрования: {encryption_count:,}")
        print(f"Скорость шифрования: {encryption_rate:.1f} оп/с")
        print(f"Пропускная способность шифрования: {encryption_throughput:.3f} Мбит/с")
        print(f"\nОпераций дешифрования: {decryption_count:,}")
        print(f"Скорость дешифрования: {decryption_rate:.1f} оп/с")
        print(f"Пропускная способность дешифрования: {decryption_throughput:.3f} Мбит/с")
        print(f"\nВсего обработано данных: {results['total_data_processed_mb']:.2f} МБ")
        
        self.ten_second_results = results
        
        with open('stress_test_10s.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def plot_comprehensive_results(self):
        """Построение комплексных графиков"""
        if not self.results:
            print("Сначала запустите основные тесты!")
            return
        
        fig = plt.figure(figsize=(20, 16))
        
        sizes = [r['size_bytes'] for r in self.results]
        
        ax1 = plt.subplot(3, 3, 1)
        encryption_times = [r['encryption_ms'] for r in self.results]
        decryption_times = [r['decryption_ms'] for r in self.results]
        
        ax1.semilogx(sizes, encryption_times, 'bo-', label='Шифрование', linewidth=2, markersize=8)
        ax1.semilogx(sizes, decryption_times, 'ro-', label='Дешифрование', linewidth=2, markersize=8)
        ax1.set_xlabel('Размер данных (байты)', fontsize=12)
        ax1.set_ylabel('Время (мс)', fontsize=12)
        ax1.set_title('Зависимость времени от размера данных', fontsize=14, fontweight='bold')
        ax1.grid(True, alpha=0.3, which='both')
        ax1.legend(fontsize=11)
        
        ax2 = plt.subplot(3, 3, 2)
        throughput_enc = [r['throughput_encryption_mbps'] for r in self.results]
        throughput_dec = [r['throughput_decryption_mbps'] for r in self.results]
        
        ax2.loglog(sizes, throughput_enc, 'go-', label='Шифрование', linewidth=2, markersize=8)
        ax2.loglog(sizes, throughput_dec, 'mo-', label='Дешифрование', linewidth=2, markersize=8)
        ax2.set_xlabel('Размер данных (байты)', fontsize=12)
        ax2.set_ylabel('Пропускная способность (Мбит/с)', fontsize=12)
        ax2.set_title('Пропускная способность', fontsize=14, fontweight='bold')
        ax2.grid(True, alpha=0.3, which='both')
        ax2.legend(fontsize=11)
        
        ax3 = plt.subplot(3, 3, 3)
        if self.key_exchange_results:
            labels = ['Генерация\nключа', 'Обмен\nключами', 'Производная\nключа']
            values = [
                self.key_exchange_results['key_generation_ms'],
                self.key_exchange_results['key_exchange_ms'],
                self.key_exchange_results['key_derivation_ms']
            ]
            bars = ax3.bar(labels, values, color=['#FF6B6B', '#4ECDC4', '#45B7D1'])
            ax3.set_ylabel('Время (мс)', fontsize=12)
            ax3.set_title('Производительность ECDH', fontsize=14, fontweight='bold')
            ax3.grid(True, alpha=0.3, axis='y')
            for bar, value in zip(bars, values):
                height = bar.get_height()
                ax3.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                        f'{value:.2f} мс', ha='center', va='bottom', fontsize=10)
        
        ax4 = plt.subplot(3, 3, 4)
        latency_enc = [r['latency_encryption_ms'] for r in self.results]
        latency_dec = [r['latency_decryption_ms'] for r in self.results]
        
        ax4.plot(sizes, latency_enc, 'b^-', label='Шифрование', linewidth=2, markersize=8)
        ax4.plot(sizes, latency_dec, 'rv-', label='Дешифрование', linewidth=2, markersize=8)
        ax4.set_xlabel('Размер данных (байты)', fontsize=12)
        ax4.set_ylabel('Задержка (мс)', fontsize=12)
        ax4.set_title('Задержка обработки', fontsize=14, fontweight='bold')
        ax4.grid(True, alpha=0.3)
        ax4.legend(fontsize=11)
        ax4.set_xscale('log')
        
        ax5 = plt.subplot(3, 3, 5)
        if self.ten_second_results:
            categories = ['Шифрование', 'Дешифрование']
            ops_per_sec = [
                self.ten_second_results['encryption_rate_ops_per_sec'],
                self.ten_second_results['decryption_rate_ops_per_sec']
            ]
            throughput = [
                self.ten_second_results['encryption_throughput_mbps'],
                self.ten_second_results['decryption_throughput_mbps']
            ]
            
            x = np.arange(len(categories))
            width = 0.35
            
            bars1 = ax5.bar(x - width/2, ops_per_sec, width, label='Операций/сек', color='#95E1D3')
            bars2 = ax5.bar(x + width/2, throughput, width, label='Мбит/сек', color='#F38181')
            
            ax5.set_xlabel('Операция', fontsize=12)
            ax5.set_ylabel('Производительность', fontsize=12)
            ax5.set_title('Стресс-тест (10 секунд)', fontsize=14, fontweight='bold')
            ax5.set_xticks(x)
            ax5.set_xticklabels(categories)
            ax5.legend(fontsize=11)
            ax5.grid(True, alpha=0.3, axis='y')
            
            for bars in [bars1, bars2]:
                for bar in bars:
                    height = bar.get_height()
                    ax5.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                            f'{height:.1f}', ha='center', va='bottom', fontsize=9)
        
        ax6 = plt.subplot(3, 3, 6)
        efficiency = [t/e if e > 0 else 0 for t, e in zip(throughput_enc, encryption_times)]
        ax6.plot(sizes, efficiency, 'co-', linewidth=2, markersize=8)
        ax6.set_xlabel('Размер данных (байты)', fontsize=12)
        ax6.set_ylabel('Эффективность (Мбит/с/мс)', fontsize=12)
        ax6.set_title('Эффективность шифрования', fontsize=14, fontweight='bold')
        ax6.grid(True, alpha=0.3)
        ax6.set_xscale('log')
        
        ax7 = plt.subplot(3, 3, 7)
        if self.multithreading_results:
            threads = [1, 2, 4, 8]
            throughputs = []
            for t in threads:
                test_key = secrets.token_bytes(32)
                test_aesgcm = AESGCM(test_key)
                test_data = secrets.token_bytes(1024)
                
                start_time = time.perf_counter()
                for _ in range(t * 100):
                    nonce = secrets.token_bytes(12)
                    test_aesgcm.encrypt(nonce, test_data, None)
                end_time = time.perf_counter()
                
                total_data = t * 100 * len(test_data) * 8
                time_sec = end_time - start_time
                throughput_mbps = total_data / time_sec / 1_000_000
                throughputs.append(throughput_mbps)
            
            ax7.plot(threads, throughputs, 'mo-', linewidth=2, markersize=10)
            ax7.set_xlabel('Количество потоков', fontsize=12)
            ax7.set_ylabel('Пропускная способность (Мбит/с)', fontsize=12)
            ax7.set_title('Масштабируемость по потокам', fontsize=14, fontweight='bold')
            ax7.grid(True, alpha=0.3)
            ax7.set_xticks(threads)
            
            for i, (t, th) in enumerate(zip(threads, throughputs)):
                ax7.annotate(f'{th:.1f} Мбит/с', xy=(t, th), xytext=(0, 10),
                           textcoords='offset points', ha='center', fontsize=9)
        
        ax8 = plt.subplot(3, 3, 8)
        std_enc = [r['encryption_std'] for r in self.results]
        std_dec = [r['decryption_std'] for r in self.results]
        
        ax8.plot(sizes, std_enc, 'bs-', label='Шифрование', linewidth=2, markersize=6)
        ax8.plot(sizes, std_dec, 'r^-', label='Дешифрование', linewidth=2, markersize=6)
        ax8.set_xlabel('Размер данных (байты)', fontsize=12)
        ax8.set_ylabel('Стандартное отклонение (мс)', fontsize=12)
        ax8.set_title('Стабильность производительности', fontsize=14, fontweight='bold')
        ax8.grid(True, alpha=0.3)
        ax8.legend(fontsize=11)
        ax8.set_xscale('log')
        
        ax9 = plt.subplot(3, 3, 9)
        ratios = [d/e if e > 0 else 0 for d, e in zip(decryption_times, encryption_times)]
        ax9.plot(sizes, ratios, 'gd-', linewidth=2, markersize=8)
        ax9.axhline(y=1.0, color='r', linestyle='--', alpha=0.5, label='Равная скорость')
        ax9.set_xlabel('Размер данных (байты)', fontsize=12)
        ax9.set_ylabel('Соотношение (дешифр./шифр.)', fontsize=12)
        ax9.set_title('Относительная производительность', fontsize=14, fontweight='bold')
        ax9.grid(True, alpha=0.3)
        ax9.legend(fontsize=11)
        ax9.set_xscale('log')
        
        plt.suptitle('Комплексный анализ производительности E2EE шифрования\nAES-256-GCM с ECDH ключами', 
                    fontsize=18, fontweight='bold', y=0.98)
        
        plt.tight_layout()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'comprehensive_performance_{timestamp}.png'
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"\nКомплексный график сохранен как: {filename}")
        
        plt.show()
        
        return filename
    
    def generate_performance_report(self):
        """Генерация отчета о производительности"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'system_info': {
                'python_version': os.sys.version,
                'platform': os.sys.platform,
                'processor': os.cpu_count()
            },
            'aes_gcm_performance': self.results,
            'key_exchange_performance': self.key_exchange_results,
            'multithreading_performance': self.multithreading_results,
            'stress_test_10s': self.ten_second_results
        }
        
        summary = {
            'avg_encryption_throughput_mbps': round(statistics.mean(
                [r['throughput_encryption_mbps'] for r in self.results if r['size_bytes'] >= 1000]
            ), 2),
            'avg_decryption_throughput_mbps': round(statistics.mean(
                [r['throughput_decryption_mbps'] for r in self.results if r['size_bytes'] >= 1000]
            ), 2),
            'avg_encryption_latency_ms': round(statistics.mean(
                [r['latency_encryption_ms'] for r in self.results if r['size_bytes'] <= 1000]
            ), 3),
            'avg_decryption_latency_ms': round(statistics.mean(
                [r['latency_decryption_ms'] for r in self.results if r['size_bytes'] <= 1000]
            ), 3),
            'key_exchange_total_ms': self.key_exchange_results.get('total_handshake_ms', 0),
            'max_throughput_mbps': round(max(
                [r['throughput_encryption_mbps'] for r in self.results]
            ), 2)
        }
        
        report['summary'] = summary
        
        with open('performance_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print("\n" + "="*70)
        print("СВОДКА ПРОИЗВОДИТЕЛЬНОСТИ")
        print("="*70)
        print(f"Средняя пропускная способность шифрования: {summary['avg_encryption_throughput_mbps']} Мбит/с")
        print(f"Средняя пропускная способность дешифрования: {summary['avg_decryption_throughput_mbps']} Мбит/с")
        print(f"Средняя задержка шифрования (малые данные): {summary['avg_encryption_latency_ms']} мс")
        print(f"Средняя задержка дешифрования (малые данные): {summary['avg_decryption_latency_ms']} мс")
        print(f"Полное время обмена ключами: {summary['key_exchange_total_ms']} мс")
        print(f"Максимальная пропускная способность: {summary['max_throughput_mbps']} Мбит/с")
        print("="*70)
        
        return report

def main():
    """Главная функция для запуска всех тестов"""
    print("=" * 70)
    print("КОМПЛЕКСНОЕ ТЕСТИРОВАНИЕ ПРОИЗВОДИТЕЛЬНОСТИ ШИФРОВАНИЯ")
    print("E2EE Мессенджер - AES-256-GCM + ECDH")
    print("=" * 70)
    
    warnings.filterwarnings('ignore')
    
    tester = EnhancedEncryptionPerformanceTester()
    
    try:
        print("\n1. Тестирование AES-256-GCM для разных размеров данных...")
        tester.test_aes_gcm_performance()
        
        print("\n2. Тестирование производительности обмена ключами ECDH...")
        tester.test_key_exchange_performance()
        
        print("\n3. Тестирование многопоточности...")
        tester.test_multithreading_performance(num_threads=4)
        
        print("\n4. 10-секундный стресс-тест...")
        tester.test_10_second_stress()
        
        try:
            print("\n5. Тестирование использования памяти...")
            tester.test_memory_usage()
        except ImportError:
            print("  Пропуск теста памяти (psutil не установлен)")
        
        print("\n6. Построение комплексных графиков...")
        tester.plot_comprehensive_results()
        
        print("\n7. Генерация отчета...")
        tester.generate_performance_report()
        
    except KeyboardInterrupt:
        print("\n\nТестирование прервано пользователем.")
    except Exception as e:
        print(f"\nОшибка во время тестирования: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 70)
    print("ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("Все результаты сохранены в JSON файлах")
    print("Графики сохранены в PNG файлах")
    print("=" * 70)

if __name__ == "__main__":
    try:
        import matplotlib
        import numpy as np
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
    except ImportError as e:
        print(f"Ошибка: Не установлена необходимая библиотека: {e}")
        print("Установите необходимые библиотеки:")
        print("pip install matplotlib numpy cryptography")
        exit(1)
    
    main()