
import hashlib
import itertools
import time
from concurrent.futures import ThreadPoolExecutor

# Целевые хэши
target_hashes_md5 = [
    "7a68f09bd992671bb3b19a5e70b7827e"
]

target_hashes_sha256 = [
    "1115dd800feaacefdf481f1f9070374a2a81e27880f187396db67958b207cbad",
    "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
    "74e1bb62f8dabb8125a58852b63bdf6eaef667cb56ac7f7cdba6d7305c50a22f"
]

# Генерация MD5 хэша
def hash_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

# Генерация SHA-256 хэша
def hash_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Функция для полного перебора пятибуквенных паролей
def brute_force(target_hashes, hash_func, mode='md5', thread_count=1):
    letters = "abcdefghijklmnopqrstuvwxyz"
    found_passwords = {}
    start_time = time.time()
    
    def check_password(password_tuple):
        password = ''.join(password_tuple)
        hashed_password = hash_func(password)
        if hashed_password in target_hashes:
            return password, hashed_password
        return None

    # Однопоточный режим
    if thread_count == 1:
        for password_tuple in itertools.product(letters, repeat=5):
            result = check_password(password_tuple)
            if result:
                password, hashed_password = result
                found_passwords[hashed_password] = password
                if len(found_passwords) == len(target_hashes):
                    break
    # Многопоточный режим
    else:
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            results = executor.map(check_password, itertools.product(letters, repeat=5))
            for result in results:
                if result:
                    password, hashed_password = result
                    found_passwords[hashed_password] = password
                    if len(found_passwords) == len(target_hashes):
                        break

    end_time = time.time()
    elapsed_time = end_time - start_time
    return found_passwords, elapsed_time

# Основная программа
if __name__ == "__main__":
    # Параметры для многопоточного режима
    thread_count = int(input("Введите количество потоков: "))
    
    # Перебор для MD5
    print("\nПоиск для MD5 хэшей:")
    found_md5, time_md5 = brute_force(target_hashes_md5, hash_md5, mode='md5', thread_count=thread_count)
    for hash_val, password in found_md5.items():
        print(f"Найден пароль для {hash_val}: {password}")
    print(f"Затраченное время (MD5): {time_md5:.2f} секунд\n")
    
    # Перебор для SHA-256
    print("Поиск для SHA-256 хэшей:")
    found_sha256, time_sha256 = brute_force(target_hashes_sha256, hash_sha256, mode='sha256', thread_count=thread_count)
    for hash_val, password in found_sha256.items():
        print(f"Найден пароль для {hash_val}: {password}")
    print(f"Затраченное время (SHA-256): {time_sha256:.2f} секунд\n")
