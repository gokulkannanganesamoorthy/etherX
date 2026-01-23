import requests
import random
import time
import sys
import threading

TARGET_URL = "http://localhost:8000"

def attack_sql(i):
    payloads = [
        "' OR 1=1 --",
        "UNION SELECT * FROM users",
        "admin' --",
        "' OR '1'='1"
    ]
    p = random.choice(payloads)
    try:
        r = requests.post(f"{TARGET_URL}/login", data={"user": p, "pass": "123"})
        print(f"[{i}] SQLi Attack: {r.status_code}")
    except: pass

def attack_xss(i):
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)"
    ]
    p = random.choice(payloads)
    try:
        r = requests.post(f"{TARGET_URL}/feedback", data={"comment": p})
        print(f"[{i}] XSS Attack: {r.status_code}")
    except: pass

def run_dos():
    print("\n🚀 Launching Volumetric DoS Attack (Rate Limit Test)...")
    def flood():
        for _ in range(50):
            try:
                requests.get(f"{TARGET_URL}/")
            except: pass
            
    threads = []
    for _ in range(10): # 10 threads x 50 reqs = 500 reqs (Should trigger 429)
        t = threading.Thread(target=flood)
        t.start()
        threads.append(t)
        
    for t in threads: t.join()
    print("DoS Attack Complete. Check Dashboard for Throttling.")

if __name__ == "__main__":
    print(f"EtherX Red Team Simulator targeting {TARGET_URL}")
    print("1. Sending discrete attacks (SQLi/XSS)...")
    
    for i in range(100):
        if random.random() > 0.5: attack_sql(i)
        else: attack_xss(i)
        time.sleep(0.2)
        
    run_dos()
