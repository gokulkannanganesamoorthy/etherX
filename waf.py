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

# --- 2. Model Loading (Sentinel AI) ---
embedder = None
anomaly_detector = None
try:
    import joblib
    from sentence_transformers import SentenceTransformer
    
    if os.path.exists("./sentinel_model.pkl"):
        embedder = SentenceTransformer("all-MiniLM-L6-v2")
        anomaly_detector = joblib.load("./sentinel_model.pkl")
        logger.info(json.dumps({"event": "system_startup", "status": "SENTINEL_MODEL_LOADED"}))
    else:
        logger.warning(json.dumps({"event": "system_startup", "status": "MOCK_MODE_FALLBACK", "reason": "Model file not found"}))
except Exception as e:
    logger.error(json.dumps({"event": "system_startup_error", "error": str(e)}))

import sqlite3

# --- 3. Persistence & Security ---
DB_PATH = "wafel.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, 
                  method TEXT, 
                  path TEXT, 
                  score REAL, 
                  status TEXT, 
                  class TEXT,
                  client_ip TEXT)''')
    conn.commit()
    conn.close()

init_db()

def log_to_db(entry):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO logs (timestamp, method, path, score, status, class, client_ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (entry['time'], entry['method'], entry['path'], float(entry['score']), entry['status'], entry['class'], "127.0.0.1"))
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

# --- 4. Application Initialization ---
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# ... (Previous imports remain, but I am targeting the top block)

# --- 4. Application Initialization ---
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = httpx.AsyncClient(base_url=TARGET_URL)


# --- 4. Enterprise Risk Assessment Logic ---
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
    1. Sentinel Model (Isolation Forest + Embeddings) - Primary
    2. Statistical Entropy Analysis - Secondary
    3. Keyword Heuristics - Fallback/Context
    """
    risk_score = 0.0
    details = {}
    
    # Preprocess: Normalize & Redact
    normalized_text = normalize_payload(raw_text)
    
    # Layer 1: Sentinel AI
    if embedder and anomaly_detector:
        try:
            # Inference on NORMALIZED text (Stable features)
            embedding = embedder.encode([normalized_text])
            raw_score = anomaly_detector.decision_function(embedding)[0]
            # Inverting Decision Function: Negatives are outliers
            if raw_score < 0:
                sentinel_risk = 20.0 + (abs(raw_score) * 50.0)
                risk_score += sentinel_risk
                details['sentinel_detection'] = True
                details['sentinel_confidence'] = float(abs(raw_score))
        except Exception as e:
            logger.error(json.dumps({"event": "inference_error", "error": str(e)}))

    # Layer 2: Entropy (Obfuscation Detection)
    entropy = calculate_entropy(text)
    if entropy > 4.5:
        risk_score += 15 * (entropy - 4.0)
        details['high_entropy'] = True

    # Layer 3: Known Signatures (Contextual Weights)
    from urllib.parse import unquote
    text_lower = unquote(text).lower()
    
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
    if request.url.path.startswith("/assets") or request.url.path in ["/dashboard", "/stats", "/favicon.ico", "/vite.svg"]: 
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
        "status": "BLOCKED" if is_blocked else "ALLOWED"
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
    # Fetch recent logs from DB
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT timestamp, method, path, score, status, class FROM logs ORDER BY id DESC LIMIT 20")
    db_logs = [{"time": r[0], "method": r[1], "path": r[2], "score": r[3], "status": r[4], "class": r[5]} for r in c.fetchall()]
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
            async function fetchStats() {
                try {
                    const response = await fetch('/stats');
                    const data = await response.json();
                    
                    document.getElementById('total-req').innerText = data.stats.total_requests.toLocaleString();
                    document.getElementById('allowed-req').innerText = data.stats.allowed_requests.toLocaleString();
                    document.getElementById('blocked-req').innerText = data.stats.blocked_requests.toLocaleString();
                    document.getElementById('latency').innerText = data.logs.length > 0 ? data.logs[0].latency_ms || 8 : 8;
                    document.getElementById('model-name').innerText = (data.model || "SENTINEL").toUpperCase() + " ACTIVE";
                    
                    // FX Logic
                    const isAttack = data.stats.blocked_requests > 0 && data.logs.length > 0 && data.logs[0].class === "blocked";
                    const statusEl = document.getElementById('radar-status');
                    const sweepEl = document.getElementById('radar-sweep');
                    const blockedCard = document.getElementById('blocked-card');
                    
                    if (isAttack) {
                        statusEl.innerText = "THREAT NEUTRALIZED";
                        statusEl.classList.add('text-gradient-red');
                        statusEl.classList.remove('text-transparent', 'bg-clip-text', 'bg-gradient-to-br', 'from-black', 'to-zinc-500');
                        
                        sweepEl.classList.add('danger');
                        blockedCard.classList.add('active');
                    } else {
                        statusEl.innerText = "SECURE";
                        statusEl.classList.remove('text-gradient-red');
                        statusEl.classList.add('text-transparent', 'bg-clip-text', 'bg-gradient-to-br', 'from-black', 'to-zinc-500');
                        
                        sweepEl.classList.remove('danger');
                        blockedCard.classList.remove('active');
                    }

                    // Logs Render
                    const tbody = document.getElementById('log-table');
                    tbody.innerHTML = "";
                    data.logs.forEach((log, index) => {
                        const tr = document.createElement('tr');
                        const isBlocked = log.class === 'blocked';
                        
                        // Stagger Animation
                        tr.style.animation = `shimmer 0.5s ease-out ${index * 0.05}s backwards`;
                        
                        tr.className = `group relative rounded-xl transition-all duration-200 hover:scale-[1.01] mb-2 ${isBlocked ? 'bg-white border-l-4 border-rose-500 shadow-lg shadow-rose-500/10' : 'bg-white/60 border-l-4 border-transparent hover:bg-white hover:shadow-md'}`;
                        
                        const scoreStyle = isBlocked ? 'text-rose-600 font-bold' : 'text-black/40';
                        const methodStyle = getMethodStyle(log.method);
                        
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
                                        <div class="text-base font-black font-mono tracking-tighter ${scoreStyle}">${log.score}</div>
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
                    });
                } catch (e) { console.error(e); }
            }
            
            function getMethodStyle(method) {
                switch(method) {
                    case 'GET': return 'bg-blue-50/50 text-blue-600 border-blue-200/50';
                    case 'POST': return 'bg-violet-50/50 text-violet-600 border-violet-200/50';
                    case 'DELETE': return 'bg-rose-50/50 text-rose-600 border-rose-200/50';
                    default: return 'bg-gray-50/50 text-gray-600 border-gray-200/50';
                }
            }
            
            setInterval(fetchStats, 1000);
            fetchStats();
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
