import aiohttp
import asyncio
import random
import time
import sys

# Target Configuration
TARGET_URL = "http://localhost:8000"
CONCURRENT_USERS = 50
REQUESTS_PER_USER = 50 

PATHS = [
    "/login", "/dashboard", "/api/v1/user", "/search", "/admin", 
    "/contact", "/about", "/products", "/checkout"
]

PAYLOADS = [
    # Benign
    {"type": "benign", "method": "GET", "body": ""},
    {"type": "benign", "method": "POST", "body": "username=user&password=password"},
    # Malicious
    {"type": "xss", "method": "POST", "body": "<script>alert(1)</script>"},
    {"type": "sqli", "method": "POST", "body": "' OR 1=1 --"},
    {"type": "rce", "method": "POST", "body": "; cat /etc/passwd"}
]

async def user_simulation(session, user_id):
    for i in range(REQUESTS_PER_USER):
        attack = random.choice(PAYLOADS)
        path = random.choice(PATHS)
        url = f"{TARGET_URL}{path}"
        
        try:
            start = time.time()
            if attack["method"] == "GET":
                async with session.get(url) as resp:
                    await resp.read()
            else:
                async with session.post(url, data=attack["body"]) as resp:
                    await resp.read()
            # Random delay 10-100ms
            await asyncio.sleep(random.uniform(0.01, 0.1))
        except Exception as e:
            print(f"Error: {e}")

async def main():
    print(f"🚀 EtherX Stress Test: Threading {CONCURRENT_USERS} users...")
    start_time = time.time()
    
    async with aiohttp.ClientSession() as session:
        tasks = [user_simulation(session, i) for i in range(CONCURRENT_USERS)]
        await asyncio.gather(*tasks)
        
    duration = time.time() - start_time
    total_reqs = CONCURRENT_USERS * REQUESTS_PER_USER
    rps = total_reqs / duration
    
    print(f"\n✅ Stress Test Complete!")
    print(f"Total Requests: {total_reqs}")
    print(f"Duration: {duration:.2f}s")
    print(f"Throughput: {rps:.2f} Req/Sec")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")
