import requests
import random
import time
import sys
import json
import urllib.parse

# Base URL of the JuiceShop
BASE_URL = "http://localhost:8000"

# User Agents to simulate different devices
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
]

# Extended list of paths
PATHS = [
    "/",
    "/#/search",
    "/#/login",
    "/#/register",
    "/#/basket",
    "/#/score-board",
    "/#/about",
    "/#/contact",
    "/api/Users",
    "/api/Products",
    "/api/Feedbacks",
    "/api/Challenges",
    "/rest/products/search?q=apple",
    "/rest/products/search?q=orange",
    "/rest/products/search?q=juice",
    "/rest/products/search?q=banana",
    "/rest/products/search?q=green",
    "/api/Quantitys",
    "/api/BasketItems",
    "/socket.io/?EIO=3&transport=polling&t=N8K8_1z",
    "/assets/public/images/products/apple_juice.jpg",
    "/assets/public/images/products/orange_juice.jpg",
    "/assets/public/favicon_1.ico",
    "/assets/public/images/carousel/1.jpg",
    "/assets/public/images/carousel/2.jpg"
]

def generate_traffic(count=200, output_file="benign_traffic.txt"):
    print(f"Starting ADVANCED traffic generation: {count} requests...")
    
    session = requests.Session()
    
    with open(output_file, "w") as f:
        for i in range(count):
            path = random.choice(PATHS)
            url = f"{BASE_URL}{path}"
            method = "GET"
            body = ""
            
            headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive"
            }
            
            try:
                if random.random() < 0.9:
                    # GET Request
                    response = session.get(url, headers=headers)
                else:
                    # POST Request (Login or Basket)
                    method = "POST"
                    if "login" in path:
                         payload = {"email": f"user{i}@test.com", "password": "password123"}
                    elif "basket" in path:
                         payload = {"ProductId": random.randint(1, 10), "quantity": 1}
                    else:
                         payload = {"test": "data", "id": i}
                    
                    body = json.dumps(payload)
                    response = session.post(url, json=payload, headers=headers)
                
                # Log format: METHOD <TAB> PATH <TAB> HEADERS_JSON <TAB> BODY
                # We normalize/simplify to help the model learn the structure.
                # For WAF, the full path including query params is critical.
                
                # Simplified Log Entry for Training:
                # We want the model to see the "Request Line" and "Body".
                # Format: [CLS] METHOD path [SEP] body [SEP]
                
                log_content = f"{method} {path} {body}"
                f.write(log_content + "\n")
                
                sys.stdout.write(f"\r[{i+1}/{count}] {response.status_code} {method} {path[:30]}...")
                sys.stdout.flush()
                
                time.sleep(random.uniform(0.05, 0.3))
                
            except Exception as e:
                # If server is not up yet, we might fail
                pass

    print(f"\nTraffic generation complete. Logs saved to {output_file}")

if __name__ == "__main__":
    count = 200
    if len(sys.argv) > 1:
        count = int(sys.argv[1])
    generate_traffic(count)
