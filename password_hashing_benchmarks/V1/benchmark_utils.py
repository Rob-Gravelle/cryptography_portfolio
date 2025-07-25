import time
import os
import bcrypt
import hashlib
import statistics
import psutil
import platform
from argon2 import PasswordHasher

# === Hashing Functions ===

def hash_argon2(password: str, time_cost=3, memory_cost=65536, parallelism=4):
    """
    Argon2id hash with tunable time, memory, and parallelism.
    Returns: (hash, time, memory in MB)
    """
    ph = PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism)
    process = psutil.Process(os.getpid())
    start_mem = process.memory_info().rss / 1024 / 1024
    start = time.perf_counter()
    hashed = ph.hash(password)
    end = time.perf_counter()
    end_mem = process.memory_info().rss / 1024 / 1024
    return hashed, end - start, end_mem - start_mem

def hash_bcrypt(password: str, rounds=12):
    salt = bcrypt.gensalt(rounds=rounds)
    process = psutil.Process(os.getpid())
    start_mem = process.memory_info().rss / 1024 / 1024
    start = time.perf_counter()
    hashed = bcrypt.hashpw(password.encode(), salt)
    end = time.perf_counter()
    end_mem = process.memory_info().rss / 1024 / 1024
    return hashed.decode(), end - start, end_mem - start_mem

def hash_pbkdf2(password: str, iterations=600_000, dklen=32):
    salt = os.urandom(16)
    process = psutil.Process(os.getpid())
    start_mem = process.memory_info().rss / 1024 / 1024
    start = time.perf_counter()
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen)
    end = time.perf_counter()
    end_mem = process.memory_info().rss / 1024 / 1024
    return f"{salt.hex()}:{hashed.hex()}", end - start, end_mem - start_mem

# === Benchmark Function ===

def run_benchmarks(password='correcthorsebatterystaple', runs=10):
    print(f"🔐 Benchmarking for password: '{password}' ({runs} runs)\n")
    print(f"📟 System: {platform.processor()} | {platform.system()} {platform.release()}\n")

    # Argon2 Benchmarks - varying memory cost
    print("== Argon2: Varying Memory Cost ==")
    for mem_cost in [65536, 131072, 262144]:  # 64MB, 128MB, 256MB
        times, mems = [], []
        for _ in range(runs):
            hashed, duration, mem_usage = hash_argon2(password, time_cost=3, memory_cost=mem_cost, parallelism=4)
            times.append(duration)
            mems.append(mem_usage)
        print(f"Memory={mem_cost//1024}MB | Avg Time: {statistics.mean(times):.4f}s | "
              f"Length: {len(hashed)} | Avg RSS Delta: {statistics.mean(mems):.2f} MB")

    # Argon2 Benchmarks - varying parallelism
    print("\n== Argon2: Varying Parallelism ==")
    for threads in [1, 2, 4, 8]:
        times, mems = [], []
        for _ in range(runs):
            hashed, duration, mem_usage = hash_argon2(password, time_cost=3, memory_cost=65536, parallelism=threads)
            times.append(duration)
            mems.append(mem_usage)
        print(f"Parallelism={threads} | Avg Time: {statistics.mean(times):.4f}s | "
              f"Length: {len(hashed)} | Avg RSS Delta: {statistics.mean(mems):.2f} MB")

    # bcrypt Benchmarks
    print("\n== bcrypt ==")
    for rounds in [12, 13, 14]:
        times, mems = [], []
        for _ in range(runs):
            hashed, duration, mem_usage = hash_bcrypt(password, rounds=rounds)
            times.append(duration)
            mems.append(mem_usage)
        print(f"Rounds={rounds} | Avg Time: {statistics.mean(times):.4f}s | "
              f"Length: {len(hashed)} | Avg RSS Delta: {statistics.mean(mems):.2f} MB")

    # PBKDF2 Benchmarks
    print("\n== PBKDF2 ==")
    for iterations in [600_000, 800_000, 1_000_000]:
        times, mems = [], []
        for _ in range(runs):
            hashed, duration, mem_usage = hash_pbkdf2(password, iterations=iterations)
            times.append(duration)
            mems.append(mem_usage)
        print(f"Iterations={iterations} | Avg Time: {statistics.mean(times):.4f}s | "
              f"Length: {len(hashed)} | Avg RSS Delta: {statistics.mean(mems):.2f} MB")

# === Main ===
if __name__ == "__main__":
    run_benchmarks()
