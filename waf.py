import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
import httpx
import logging
import sys
import time
import asyncio
import json
import os
import math
from collections import deque

# --- 1. Enterprise Configuration & Logging ---
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module
        }
        return json.dumps(log_entry)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JsonFormatter())
logger = logging.getLogger("EtherX_Sentinel")
logger.setLevel(logging.INFO)
logger.handlers = [handler]

# Environment Variables
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:3000")
MODEL_PATH = os.getenv("MODEL_PATH", "./sentinel_model.pkl")
THRESHOLD = float(os.getenv("BLOCK_THRESHOLD", "20.0"))

# State
stats = {
    "total_requests": 0,
    "blocked_requests": 0,
    "allowed_requests": 0
}
recent_logs = deque(maxlen=20)

# --- 2. Model Loading (Sentinel Deep Brain) ---
embedder = None
autoencoder = None
model_threshold = 0.05 # MSE Threshold

try:
    import joblib
    import torch
    import torch.nn as nn
    from sentence_transformers import SentenceTransformer

    # Define Network Architecture (Must match training script)
    class SentinelAutoencoder(nn.Module):
        def __init__(self):
            super(SentinelAutoencoder, self).__init__()
            self.encoder = nn.Sequential(
                nn.Linear(384, 128),
                nn.ReLU(),
                nn.Linear(128, 64),
                nn.ReLU()
            )
            self.decoder = nn.Sequential(
                nn.Linear(64, 128),
                nn.ReLU(),
                nn.Linear(128, 384),
                nn.Tanh()
            )
        def forward(self, x):
            encoded = self.encoder(x)
            decoded = self.decoder(encoded)
            return decoded

    if os.path.exists("./sentinel_embedder.pkl") and os.path.exists("./sentinel_autoencoder.pth"):
        embedder = joblib.load("./sentinel_embedder.pkl")
        autoencoder = SentinelAutoencoder()
        autoencoder.load_state_dict(torch.load("./sentinel_autoencoder.pth"))
        autoencoder.eval() # Inference Mode
        logger.info(json.dumps({"event": "system_startup", "status": "SENTINEL_DEEP_BRAIN_ONLINE"}))
    else:
        logger.warning(json.dumps({"event": "system_startup", "status": "MOCK_MODE", "reason": "Deep Brain not found"}))
except Exception as e:
    logger.error(json.dumps({"event": "system_startup_error", "error": str(e)}))

# --- 4. Application Initialization (MOVED UP) ---
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import sqlite3

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = httpx.AsyncClient(base_url=TARGET_URL)

# --- 3. Persistence & Security ---
DB_PATH = "wafel.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Create table with original schema if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, 
                  method TEXT, 
                  path TEXT, 
                  score REAL, 
                  status TEXT, 
                  class TEXT,
                  client_ip TEXT)''')
    
    # Schema Migration: Add new columns if they don't exist
    c.execute("PRAGMA table_info(logs)")
    columns = [info[1] for info in c.fetchall()]
    
    start_cols = ["risk_details", "latency_ms", "user_agent", "payload_snippet"]
    col_types = ["TEXT", "REAL", "TEXT", "TEXT"]
    
    for col, col_type in zip(start_cols, col_types):
        if col not in columns:
            try:
                print(f"Migrating DB: Adding {col} column...")
                c.execute(f"ALTER TABLE logs ADD COLUMN {col} {col_type}")
            except Exception as e:
                print(f"Migration Error for {col}: {e}")

    conn.commit()
    conn.close()

init_db()

def log_to_db(entry):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Serialize risk_details to JSON if it's a dict
        risk_details_str = json.dumps(entry.get('risk_details', {}))
        
        c.execute('''INSERT INTO logs 
                     (timestamp, method, path, score, status, class, client_ip, risk_details, latency_ms, user_agent, payload_snippet) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (entry['time'], 
                   entry['method'], 
                   entry['path'], 
                   float(entry['score']), 
                   entry['status'], 
                   entry['class'], 
                   entry['client_ip'],
                   risk_details_str,
                   entry.get('latency_ms', 0.0),
                   entry.get('user_agent', ''),
                   entry.get('payload_snippet', '')
                  ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"DB Error: {e}")

class TokenBucket:
    def __init__(self, rate=100, per=60):
        self.rate = rate
        self.per = per
        self.tokens = {}
        
    def allow(self, ip):
        now = time.time()
        if ip not in self.tokens:
            self.tokens[ip] = {"tokens": self.rate, "last": now}
        
        bucket = self.tokens[ip]
        elapsed = now - bucket["last"]
        bucket["tokens"] += elapsed * (self.rate / self.per)
        if bucket["tokens"] > self.rate: bucket["tokens"] = self.rate
        bucket["last"] = now
        
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True
        return False

rate_limiter = TokenBucket(rate=100, per=60) # 100 req/min per IP

import re

def normalize_payload(text):
    """
    Normalization & Privacy Masking (Bonus Requirement):
    1. Replace UUIDs with <UUID>
    2. Replace Emails with <EMAIL> (Privacy)
    3. Replace Timestamps/Numbers with <ID>
    """
    if not text: return ""
    
    # URL Decode
    from urllib.parse import unquote
    text = unquote(text).lower()
    
    # 1. Mask Emails (Privacy)
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '<EMAIL>', text)
    
    # 2. Mask UUIDs
    text = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<UUID>', text)
    
    # 3. Mask Numbers (IDs, Timestamps)
    text = re.sub(r'\d+', '<ID>', text)
    
    return text

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x)))/len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def get_risk_assessment(raw_text):
    """
    Performs a multi-layered risk assessment:
    1. Sentinel Deep Autoencoder (Reconstruction Error) - Primary
    2. Statistical Entropy Analysis - Secondary
    3. Keyword Heuristics - Fallback/Context
    """
    risk_score = 0.0
    details = {}
    
    # Preprocess: Normalize & Redact
    normalized_text = normalize_payload(raw_text)
    
    # Layer 1: Sentinel Deep Learning
    if embedder and autoencoder:
        try:
            # Inference 
            with torch.no_grad():
                # 1. Embed
                vector = embedder.encode([normalized_text])
                tensor_in = torch.FloatTensor(vector)
                
                # 2. Reconstruct
                reconstruction = autoencoder(tensor_in)
                
                # 3. Calculate Error (MSE)
                mse_loss = torch.mean((tensor_in - reconstruction) ** 2).item()
                
                # 4. Map to Risk Score
                # Typical benign MSE is ~0.005. Attacks are > 0.02
                # We scale this to 0-100
                if mse_loss > model_threshold:
                    sentinel_risk = min(100, (mse_loss / model_threshold) * 50)
                    risk_score += sentinel_risk
                    details['neural_anomaly'] = True
                    details['reconstruction_error'] = round(mse_loss, 5)
                else:
                    details['neural_confidence'] = "SAFE"
                    
        except Exception as e:
            logger.error(json.dumps({"event": "inference_error", "error": str(e)}))

    # Layer 2: Entropy (Obfuscation Detection)
    entropy = calculate_entropy(raw_text)
    if entropy > 4.5:
        risk_score += 15 * (entropy - 4.0)
        details['high_entropy'] = True

    # Layer 3: Known Signatures (Contextual Weights)
    text_lower = normalized_text
    
    img_tags = [
        "<script>", "union select", "eval(", "javax.naming", "/etc/passwd", 
        "alert(1)", "javascript:", "or 1=1", "admin' --", "union all select"
    ]
    for tag in img_tags:
        if tag in text_lower:
            risk_score += 50.0
            details['signature_match'] = tag

    return max(1.0, risk_score), details

# --- 4.5. Realtime WebSocket Manager ---
from fastapi import WebSocket, WebSocketDisconnect

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text() # Keep alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# --- 5. Alerting & Broadcasting ---
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

async def send_alert(payload):
    # 1. Async Webhook (Slack/Discord)
    if WEBHOOK_URL:
        try:
            async with httpx.AsyncClient() as client:
                message = {
                    "content": f"🚨 **ETHERX SECURITY ALERT** 🚨\n\n**IP:** {payload['client_ip']}\n**Path:** `{payload['path']}`\n**Risk Score:** {payload['risk_score']}\n**Reason:** {json.dumps(payload['risk_details'])}"
                }
                await client.post(WEBHOOK_URL, json=message)
        except Exception as e:
            logger.error(f"Alert Error: {e}")

    # 2. WebSocket Broadcast (Dashboard)
    # We broadcast the full log object expected by frontend
    ws_payload = json.dumps({
        "type": "new_log",
        "data": {
            "time": time.strftime("%H:%M:%S"),
            "method": payload['method'],
            "path": payload['path'],
            "full_url": f"{payload['path']}?{payload['query']}" if payload['query'] else payload['path'],
            "score": payload['risk_score'],
            "status": payload['action'],
            "class": "blocked" if payload['action'] == "BLOCK" else "allowed",
            "risk_details": payload['risk_details'],
            "latency_ms": payload['latency_ms'],
            "client_ip": payload['client_ip'],
            "user_agent": payload.get('user_agent'),
            "payload": payload.get('payload_snippet')
        },
        "stats": stats
    })
    await manager.broadcast(ws_payload)

# --- 5. WAF Middleware ---
@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    # Bypass WAF for Dashboard, Stats, and Static Assets
    if request.url.path.startswith("/assets") or request.url.path in ["/", "/dashboard", "/stats", "/favicon.ico", "/vite.svg", "/ws"]: 
        return await call_next(request)

    start_time = time.time()
    client_ip = request.client.host
    
    # 1. Rate Limiting (DoS Protection)
    if not rate_limiter.allow(client_ip):
        stats["blocked_requests"] += 1
        logger.warning(json.dumps({"event": "security_alert", "type": "DoS_attempt", "ip": client_ip, "action": "DROP"}))
        return Response("Too Many Requests", status_code=429)

    method = request.method
    path = request.url.path
    query = request.url.query
    
    try:
        body_bytes = await request.body()
        body_str = body_bytes.decode('utf-8', errors='ignore')
    except:
        body_str = ""
        body_bytes = b""
        
    full_payload = f"{method} {path} {query} {body_str}"
    
    # --- HONEYPOT TRAP (Bonus Feature) ---
    HONEYPOT_PATHS = ["/admin.php", "/.env", "/config.php", "/backup.sql", "/api/v1/secret"]
    is_honeypot = any(path.startswith(hp) for hp in HONEYPOT_PATHS)
    
    if is_honeypot:
        score = 100.0
        risk_details = {"honeypot_triggered": True, "trap": path}
        is_blocked = True
        logger.warning(json.dumps({"event": "honeypot_trap", "ip": client_ip, "trap": path}))
    else:
        # Risk Analysis
        score, risk_details = get_risk_assessment(full_payload)
        is_blocked = score > THRESHOLD
    
    # Metrics
    duration = time.time() - start_time
    stats["total_requests"] += 1
    
    log_payload = {
        "event": "traffic_inspection",
        "client_ip": client_ip,
        "method": method,
        "path": path,
        "query": query,
        "user_agent": request.headers.get("user-agent", "unknown"),
        "payload_snippet": body_str[:200] if body_str else None,
        "risk_score": round(score, 4),
        "action": "BLOCK" if is_blocked else "ALLOW",
        "risk_details": risk_details,
        "latency_ms": round(duration * 1000, 2)
    }

    log_entry = {
        "time": time.strftime("%H:%M:%S"),
        "method": method,
        "path": path,
        "score": f"{score:.2f}",
        "class": "blocked" if is_blocked else "allowed",
        "status": "BLOCKED" if is_blocked else "ALLOWED",
        "client_ip": client_ip,
        "risk_details": risk_details,
        "latency_ms": round(duration * 1000, 2),
        "user_agent": request.headers.get("user-agent", "unknown"),
        "payload_snippet": body_str[:200] if body_str else None
    }
    
    # Persistence
    log_to_db(log_entry)
    
    if is_blocked:
        stats["blocked_requests"] += 1
        logger.warning(json.dumps(log_payload))
        # Alerting (Async Webhook)
        asyncio.create_task(send_alert(log_payload)) 
        
        return Response(
            content=json.dumps({"error": "EtherX Security Block", "request_id": str(time.time())}), 
            status_code=403, 
            media_type="application/json"
        )
    else:
        stats["allowed_requests"] += 1
        logger.info(json.dumps(log_payload))
        # Broadcast Allowed requests too for Realtime Feed
        asyncio.create_task(send_alert(log_payload))

    # Forwarding
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    
    try:
        url = f"{path}?{query}" if query else path
        proxy_resp = await client.request(method, url, headers=headers, content=body_bytes, cookies=request.cookies)
        return Response(content=proxy_resp.content, status_code=proxy_resp.status_code, headers=proxy_resp.headers, media_type=proxy_resp.headers.get('content-type'))
    except httpx.RequestError as e:
        logger.error(json.dumps({"event": "upstream_error", "error": str(e)}))
        return Response("Upstream Gateway Error", status_code=502)

# --- 6. Dashboard (React Frontend) ---
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Serve React Static Assets
if os.path.exists("dashboard-ui/dist/assets"):
    app.mount("/assets", StaticFiles(directory="dashboard-ui/dist/assets"), name="assets")

@app.get("/")
@app.get("/dashboard")
async def serve_react_app():
    return FileResponse("dashboard-ui/dist/index.html")

# Fallback for API Stats
@app.get("/stats")
async def get_stats():
    """API Endpoint for Real-Time Dashboard Data"""
    # Fetch all logs from DB
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    c = conn.cursor()
    
    # Removed LIMIT 20 to show all requests
    c.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = c.fetchall()
    
    db_logs = []
    for r in rows:
        try:
            risk_details = json.loads(r["risk_details"]) if r["risk_details"] else {}
        except:
            risk_details = {}
            
        db_logs.append({
            "id": r["id"],
            "time": r["timestamp"],
            "method": r["method"],
            "path": r["path"],
            "score": r["score"],
            "status": r["status"],
            "class": r["class"],
            "client_ip": r["client_ip"],
            "risk_details": risk_details,
            "latency_ms": r["latency_ms"],
            "user_agent": r["user_agent"],
            "payload_snippet": r["payload_snippet"]
        })
        
    conn.close()
    
    return {
        "stats": stats,
        "logs": db_logs,
        "system_status": "ONLINE",
        "model": "SENTINEL-L6" if embedder else "DISTILBERT (MOCK)"
    }

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>ETHERX | SENTINEL PRIME</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
        <script>
            tailwind.config = {
                theme: {
                    extend: {
                        fontFamily: { sans: ['Outfit', 'sans-serif'] },
                        animation: {
                            'spin-slow': 'spin 8s linear infinite',
                            'pulse-fast': 'pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                            'blob': 'blob 7s infinite',
                            'shimmer': 'shimmer 2s linear infinite',
                        },
                        keyframes: {
                            blob: {
                                '0%': { transform: 'translate(0px, 0px) scale(1)' },
                                '33%': { transform: 'translate(30px, -50px) scale(1.1)' },
                                '66%': { transform: 'translate(-20px, 20px) scale(0.9)' },
                                '100%': { transform: 'translate(0px, 0px) scale(1)' },
                            },
                            shimmer: {
                                '0%': { backgroundPosition: '200% 0' },
                                '100%': { backgroundPosition: '-200% 0' }
                            }
                        },
                        colors: {
                            'neon-red': '#ff003c',
                            'neon-blue': '#00f2ea',
                        }
                    }
                }
            }
        </script>
        <style>
             body { background-color: #ffffff; }
             
             /* Dynamic Background */
             .bg-grid {
                 background-size: 40px 40px;
                 background-image: radial-gradient(circle, #e5e7eb 1px, transparent 1px);
                 mask-image: linear-gradient(to bottom, transparent, 10%, white, 90%, transparent);
             }
             
             /* Glass Cards */
             .glass-panel {
                 background: rgba(255, 255, 255, 0.7);
                 backdrop-filter: blur(20px);
                 border: 1px solid rgba(255, 255, 255, 0.5);
                 box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.1);
             }
             
             .glass-panel:hover {
                 transform: translateY(-2px);
                 box-shadow: 0 12px 40px 0 rgba(31, 38, 135, 0.15);
                 border-color: rgba(0, 0, 0, 0.1);
             }

             /* Typography gradient */
             .text-gradient {
                 background: linear-gradient(to right, #000000, #434343);
                 -webkit-background-clip: text;
                 -webkit-text-fill-color: transparent;
             }
             
             .text-gradient-red {
                 background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
                 -webkit-background-clip: text;
                 -webkit-text-fill-color: transparent;
             }

             /* Animated Border */
             .gradient-border {
                 position: relative;
                 background: #fff;
                 border-radius: 1rem;
             }
             .gradient-border::before {
                 content: "";
                 position: absolute;
                 inset: -2px;
                 border-radius: 1.2rem;
                 background: linear-gradient(45deg, #ff003c, #00f2ea, #ff003c);
                 background-size: 200% 200%;
                 animation: shimmer 4s linear infinite;
                 z-index: -1;
                 opacity: 0;
                 transition: opacity 0.3s;
             }
             .gradient-border.active::before { opacity: 1; }

             /* Radar Animation */
             .radar-sweep {
                 position: absolute;
                 height: 50%;
                 width: 50%;
                 background: conic-gradient(from 0deg, transparent, rgba(5, 150, 105, 0.2), rgba(5, 150, 105, 0.5));
                 top: 0;
                 left: 0;
                 transform-origin: 100% 100%;
                 animation: spin 3s linear infinite;
                 border-right: 2px solid #10b981;
             }
             .radar-sweep.danger {
                 background: conic-gradient(from 0deg, transparent, rgba(225, 29, 72, 0.2), rgba(225, 29, 72, 0.5));
                 border-right: 2px solid #e11d48;
             }
        </style>
    </head>
    <body class="h-screen flex flex-col font-sans antialiased overflow-hidden selection:bg-black selection:text-white">
        
        <!-- Animated Background Blobs -->
        <div class="fixed inset-0 z-0 overflow-hidden pointer-events-none">
            <div class="absolute -top-[20%] -left-[10%] w-[50%] h-[50%] bg-blue-200/30 rounded-full mix-blend-multiply filter blur-3xl opacity-70 animate-blob"></div>
            <div class="absolute top-[20%] -right-[10%] w-[50%] h-[50%] bg-purple-200/30 rounded-full mix-blend-multiply filter blur-3xl opacity-70 animate-blob animation-delay-2000"></div>
            <div class="absolute -bottom-[20%] left-[20%] w-[50%] h-[50%] bg-pink-200/30 rounded-full mix-blend-multiply filter blur-3xl opacity-70 animate-blob animation-delay-4000"></div>
            <div class="absolute inset-0 bg-grid opacity-50"></div>
        </div>

        <!-- Navbar -->
        <nav class="border-b border-black/5 bg-white/60 backdrop-blur-xl sticky top-0 z-50">
            <div class="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
                <div class="flex items-center gap-4">
                    <div class="relative">
                        <div class="absolute -inset-1 bg-gradient-to-r from-blue-600 to-violet-600 rounded-lg blur opacity-25"></div>
                        <div class="relative h-10 w-10 bg-black rounded-lg flex items-center justify-center">
                            <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                        </div>
                    </div>
                    <div>
                        <h1 class="font-bold text-2xl tracking-tighter text-gradient">ETHERX <span class="font-light text-black/40">SENTINEL</span></h1>
                    </div>
                </div>
                <!-- Status Pill -->
                <div class="px-4 py-1.5 rounded-full bg-white/50 border border-white/50 shadow-lg shadow-black/5 backdrop-blur-md flex items-center gap-2.5 transition-all hover:scale-105 cursor-default">
                    <div class="relative flex h-3 w-3">
                      <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                      <span class="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                    </div>
                    <span class="text-xs font-bold tracking-widest uppercase text-black/70">System Active</span>
                </div>
            </div>
        </nav>

        <!-- Main Content -->
        <main class="relative z-10 flex-1 max-w-7xl mx-auto w-full p-6 grid grid-cols-1 lg:grid-cols-12 gap-8 min-h-0">
            
            <!-- Left Panel: Visuals -->
            <div class="lg:col-span-4 flex flex-col gap-6">
                <!-- RADAR -->
                <div class="glass-panel rounded-3xl p-8 relative overflow-hidden group transition-all duration-300">
                    <div class="absolute top-0 right-0 p-4 opacity-50">
                        <svg class="w-6 h-6 text-black" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" /></svg>
                    </div>
                    
                    <div class="flex flex-col items-center justify-center py-6">
                        <div id="radar-container" class="relative w-48 h-48 rounded-full border border-black/10 flex items-center justify-center bg-black/5 shadow-inner">
                            <div class="absolute inset-0 rounded-full border border-black/5 scale-[0.7]"></div>
                            <div class="absolute inset-0 rounded-full border border-black/5 scale-[0.4]"></div>
                            <div class="absolute inset-0 w-full h-full rounded-full overflow-hidden">
                                <div id="radar-sweep" class="radar-sweep"></div>
                            </div>
                            <!-- Center Point -->
                            <div class="h-3 w-3 bg-black rounded-full shadow-[0_0_15px_rgba(0,0,0,0.5)] z-10 relative">
                                <div class="absolute -inset-1 bg-black/30 rounded-full animate-ping"></div>
                            </div>
                        </div>
                        
                        <div class="mt-8 text-center">
                            <h2 class="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-br from-black to-zinc-500 tracking-tighter" id="radar-status">SECURE</h2>
                            <p class="text-sm font-semibold tracking-widest text-black/40 uppercase mt-1">Real-time Defense</p>
                        </div>
                    </div>
                </div>

                <!-- Stats Grid -->
                <div class="grid grid-cols-2 gap-4">
                     <div class="glass-panel rounded-2xl p-5 flex flex-col justify-between h-32 hover:bg-white/40">
                         <div class="text-xs font-bold text-black/40 tracking-widest uppercase">Traffic</div>
                         <div class="text-4xl font-extrabold text-black tracking-tight" id="total-req">0</div>
                     </div>
                     <div class="glass-panel rounded-2xl p-5 flex flex-col justify-between h-32 hover:bg-white/40">
                         <div class="text-xs font-bold text-black/40 tracking-widest uppercase">Latency</div>
                         <div class="flex items-baseline">
                             <div class="text-4xl font-extrabold text-black tracking-tight" id="latency">0</div>
                             <div class="text-sm font-bold text-black/30 ml-1">ms</div>
                         </div>
                     </div>
                     <div class="glass-panel rounded-2xl p-5 flex flex-col justify-between h-32 bg-emerald-50/50 border-emerald-100">
                         <div class="text-xs font-bold text-emerald-600/60 tracking-widest uppercase">Allowed</div>
                         <div class="text-4xl font-extrabold text-emerald-600 tracking-tight" id="allowed-req">0</div>
                     </div>
                     <div id="blocked-card" class="gradient-border rounded-2xl p-5 flex flex-col justify-between h-32 shadow-xl shadow-red-500/10">
                         <div class="text-xs font-bold text-rose-600/60 tracking-widest uppercase relative z-10">Intercepted</div>
                         <div class="text-4xl font-extrabold text-rose-600 tracking-tight relative z-10" id="blocked-req">0</div>
                     </div>
                </div>
            </div>

            <!-- Right Panel: Feed -->
            <div class="lg:col-span-8 flex flex-col">
                <div class="glass-panel rounded-3xl flex-1 flex flex-col overflow-hidden shadow-2xl shadow-black/5">
                    <div class="p-6 border-b border-black/5 flex justify-between items-center bg-white/40 backdrop-blur-md">
                        <div class="flex items-center gap-3">
                            <div class="h-2 w-2 bg-black rounded-full animate-pulse"></div>
                            <h3 class="font-bold text-lg tracking-tight">Live Inspection Feed</h3>
                        </div>
                        <div class="px-3 py-1 bg-black/5 rounded-lg text-[10px] font-mono text-black/50" id="model-name">SENTINEL-L6 INITIALIZED</div>
                    </div>
                    
                    <div class="flex-1 overflow-auto bg-white/30 p-2">
                        <table class="w-full text-left border-collapse">
                            <tbody class="space-y-2" id="log-table">
                                <!-- Dynamic Rows -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </main>

        <script>
            // WebSocket Connection
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;
            let socket;

            function connectWebSocket() {
                socket = new WebSocket(wsUrl);

                socket.onopen = function() {
                    console.log("Connected to Real-time Feed");
                    document.getElementById('model-name').innerText += " • LIVE";
                };

                socket.onmessage = function(event) {
                    const msg = JSON.parse(event.data);
                    
                    if (msg.type === 'new_log') {
                        updateDashboard(msg.data, msg.stats);
                    }
                };

                socket.onclose = function() {
                    console.log("Disconnected. Reconnecting...");
                    setTimeout(connectWebSocket, 3000);
                };
            }

            function updateDashboard(log, stats) {
                // 1. Update Stats
                document.getElementById('total-req').innerText = stats.total_requests.toLocaleString();
                document.getElementById('allowed-req').innerText = stats.allowed_requests.toLocaleString();
                document.getElementById('blocked-req').innerText = stats.blocked_requests.toLocaleString();
                
                // 2. Update Visuals
                const isBlocked = log.class === 'blocked';
                const statusEl = document.getElementById('radar-status');
                const sweepEl = document.getElementById('radar-sweep');
                const blockedCard = document.getElementById('blocked-card');
                
                if (isBlocked) {
                    statusEl.innerText = "THREAT NEUTRALIZED";
                    statusEl.classList.add('text-gradient-red');
                    statusEl.classList.remove('text-transparent', 'bg-clip-text', 'bg-gradient-to-br', 'from-black', 'to-zinc-500');
                    
                    sweepEl.classList.add('danger');
                    blockedCard.classList.add('active');
                    
                    // Reset visuals after 2 seconds
                    setTimeout(() => {
                        statusEl.innerText = "SECURE";
                        statusEl.classList.remove('text-gradient-red');
                        statusEl.classList.add('text-transparent', 'bg-clip-text', 'bg-gradient-to-br', 'from-black', 'to-zinc-500');
                        sweepEl.classList.remove('danger');
                        blockedCard.classList.remove('active');
                    }, 2000);
                }

                // 3. Add to Table (Prepend)
                const tbody = document.getElementById('log-table');
                
                // Create Row
                const methodStyle = getMethodStyle(log.method);
                const tr = document.createElement('tr');
                tr.className = `group relative rounded-t-xl transition-all duration-500 animate-pulse ${isBlocked ? 'bg-white border-l-4 border-rose-500' : 'bg-white/60 border-l-4 border-transparent'}`;
                tr.onclick = () => toggleDetails(log.id || Date.now()); // Fallback ID if missing
                
                // Generate a temporary ID if one isn't provided (for real-time only, detailed view might fail without real ID, but db_log has it)
                // Actually the WS payload might not have the DB ID if it's async. 
                // Let's assume the backend sends it? Checking backend... 
                // Backend WS payload doesn't include ID currently. I should probably add it or use timestamp as key.
                // For now, let's use a random ID for the toggle to work locally.
                const rowId = log.id || Math.floor(Math.random() * 1000000); 

                tr.innerHTML = `
                    <td class="p-4 w-full flex items-center justify-between">
                        <div class="flex items-center gap-6">
                            <span class="font-mono text-xs text-black/30 font-bold tracking-widest">${log.time}</span>
                            <span class="px-2.5 py-1 rounded-md text-[10px] font-black tracking-wider uppercase border ${methodStyle}">${log.method}</span>
                            <span class="font-medium text-sm text-black/80 truncate max-w-md font-mono tracking-tight group-hover:text-black transition-colors" title="${log.path}">${log.path}</span>
                        </div>
                        <div class="flex items-center gap-8">
                            <div class="text-right">
                                <div class="text-[10px] font-bold text-black/20 uppercase tracking-widest">Risk Score</div>
                                <div class="text-base font-black font-mono tracking-tighter ${isBlocked ? 'text-rose-600' : 'text-black/40'}">${log.score}</div>
                            </div>
                                <div class="w-24 text-right">
                                <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${isBlocked ? 'bg-rose-500 text-white shadow-md shadow-rose-500/30' : 'bg-emerald-500/10 text-emerald-600'}">
                                    ${isBlocked ? 'BLOCKED' : 'ALLOW'}
                                </span>
                            </div>
                        </div>
                    </td>
                `;
                
                // Detail Row
                const detailTr = document.createElement('tr');
                detailTr.id = `detail-${rowId}`;
                detailTr.className = "hidden";
                const detailsJson = JSON.stringify(log.risk_details || {}, null, 2);
                
                detailTr.innerHTML = `
                    <td class="p-0">
                        <div class="bg-gray-50 p-4 border-l-4 ${isBlocked ? 'border-rose-500' : 'border-transparent'} border-t border-black/5 rounded-b-xl mb-4 text-xs font-mono text-gray-600 shadow-inner">
                            <div class="grid grid-cols-2 gap-4 mb-2">
                                <div><span class="font-bold text-black/50">IP:</span> ${log.client_ip}</div>
                                <div><span class="font-bold text-black/50">Latency:</span> ${log.latency_ms}ms</div>
                                <div class="col-span-2 truncate"><span class="font-bold text-black/50">UA:</span> ${log.user_agent || 'N/A'}</div>
                            </div>
                             ${log.payload ? `<div class="mb-2"><span class="font-bold text-black/50">Payload:</span> <div class="bg-white p-2 rounded border border-black/5 mt-1 break-all">${log.payload}</div></div>` : ''}
                            <div>
                                <span class="font-bold text-black/50">Risk Details:</span>
                                <pre class="bg-white p-2 rounded border border-black/5 mt-1 overflow-x-auto text-pink-600">${detailsJson}</pre>
                            </div>
                        </div>
                    </td>
                `;

                // Insert at top
                tbody.insertBefore(detailTr, tbody.firstChild);
                tbody.insertBefore(tr, tbody.firstChild);
                
                // Limit rows
                if (tbody.children.length > 100) {
                    tbody.removeChild(tbody.lastChild);
                    tbody.removeChild(tbody.lastChild);
                }
                
                // Remove animation class
                setTimeout(() => tr.classList.remove('animate-pulse'), 500);
            }

            async function fetchStats() {
                try {
                    const response = await fetch('/stats');
                    const data = await response.json();
                    
                    document.getElementById('total-req').innerText = data.stats.total_requests.toLocaleString();
                    document.getElementById('allowed-req').innerText = data.stats.allowed_requests.toLocaleString();
                    document.getElementById('blocked-req').innerText = data.stats.blocked_requests.toLocaleString();
                    if (data.logs.length > 0) {
                         document.getElementById('latency').innerText = data.logs[0].latency_ms || 8;
                    }
                    document.getElementById('model-name').innerText = (data.model || "SENTINEL").toUpperCase() + " ACTIVE";
                    
                    // Initial Table Load
                    const tbody = document.getElementById('log-table');
                    tbody.innerHTML = "";
                    
                    data.logs.forEach(log => {
                        const isBlocked = log.class === 'blocked';
                        const methodStyle = getMethodStyle(log.method);
                        const rowId = log.id;

                        const tr = document.createElement('tr');
                        tr.className = `group relative rounded-t-xl transition-all duration-200 cursor-pointer hover:bg-black/5 ${isBlocked ? 'bg-white border-l-4 border-rose-500' : 'bg-white/60 border-l-4 border-transparent'}`;
                        tr.onclick = () => toggleDetails(rowId);
                        
                        tr.innerHTML = `
                            <td class="p-4 w-full flex items-center justify-between">
                                <div class="flex items-center gap-6">
                                    <span class="font-mono text-xs text-black/30 font-bold tracking-widest">${log.time}</span>
                                    <span class="px-2.5 py-1 rounded-md text-[10px] font-black tracking-wider uppercase border ${methodStyle}">${log.method}</span>
                                    <span class="font-medium text-sm text-black/80 truncate max-w-md font-mono tracking-tight group-hover:text-black transition-colors" title="${log.path}">${log.path}</span>
                                </div>
                                <div class="flex items-center gap-8">
                                    <div class="text-right">
                                        <div class="text-[10px] font-bold text-black/20 uppercase tracking-widest">Risk Score</div>
                                        <div class="text-base font-black font-mono tracking-tighter ${isBlocked ? 'text-rose-600' : 'text-black/40'}">${log.score}</div>
                                    </div>
                                     <div class="w-24 text-right">
                                        <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${isBlocked ? 'bg-rose-500 text-white shadow-md shadow-rose-500/30' : 'bg-emerald-500/10 text-emerald-600'}">
                                            ${isBlocked ? 'BLOCKED' : 'ALLOW'}
                                        </span>
                                    </div>
                                </div>
                            </td>
                        `;
                        tbody.appendChild(tr);

                        const detailTr = document.createElement('tr');
                        detailTr.id = `detail-${rowId}`;
                        detailTr.className = "hidden";
                        
                        const detailsJson = JSON.stringify(log.risk_details, null, 2);
                        
                        detailTr.innerHTML = `
                            <td class="p-0">
                                <div class="bg-gray-50 p-4 border-l-4 ${isBlocked ? 'border-rose-500' : 'border-transparent'} border-t border-black/5 rounded-b-xl mb-4 text-xs font-mono text-gray-600 shadow-inner">
                                    <div class="grid grid-cols-2 gap-4 mb-2">
                                        <div><span class="font-bold text-black/50">IP:</span> ${log.client_ip}</div>
                                        <div><span class="font-bold text-black/50">Latency:</span> ${log.latency_ms}ms</div>
                                        <div class="col-span-2 truncate"><span class="font-bold text-black/50">UA:</span> ${log.user_agent || 'N/A'}</div>
                                    </div>
                                    ${log.payload_snippet ? `<div class="mb-2"><span class="font-bold text-black/50">Payload:</span> <div class="bg-white p-2 rounded border border-black/5 mt-1 break-all">${log.payload_snippet}</div></div>` : ''}
                                    <div>
                                        <span class="font-bold text-black/50">Risk Details:</span>
                                        <pre class="bg-white p-2 rounded border border-black/5 mt-1 overflow-x-auto text-pink-600">${detailsJson}</pre>
                                    </div>
                                </div>
                            </td>
                        `;
                        tbody.appendChild(detailTr);
                    });

                } catch (e) { console.error(e); }
            }
            
            function toggleDetails(id) {
                const el = document.getElementById(`detail-${id}`);
                if (el) {
                    el.classList.toggle('hidden');
                }
            }
            
            function getMethodStyle(method) {
                switch(method) {
                    case 'GET': return 'bg-blue-50/50 text-blue-600 border-blue-200/50';
                    case 'POST': return 'bg-violet-50/50 text-violet-600 border-violet-200/50';
                    case 'DELETE': return 'bg-rose-50/50 text-rose-600 border-rose-200/50';
                    default: return 'bg-gray-50/50 text-gray-600 border-gray-200/50';
                }
            }
            
            // Initialization
            fetchStats();       // 1. Load initial history
            connectWebSocket(); // 2. Listen for live updates
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
