#!/bin/bash

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}    EtherX AI WAF - Bare Metal Production      ${NC}"
echo -e "${BLUE}===============================================${NC}"

# Clear previous instances
echo -e "${GREEN}[+] Cleaning up old processes...${NC}"
lsof -ti:8000 | xargs kill -9 2>/dev/null
lsof -ti:3000 | xargs kill -9 2>/dev/null
sleep 1

# 1. Environment Check
echo -e "\n${GREEN}[1/4] Checking Environment...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is not installed.${NC}"
    exit 1
fi

# 2. Virtual Environment
echo -e "\n${GREEN}[2/4] Setting up Virtual Environment...${NC}"
if [ ! -d "venv" ]; then
    echo " -> Creating new venv..."
    python3 -m venv venv
fi
source venv/bin/activate
echo " -> Installing dependencies from requirements.txt..."
pip install -r requirements.txt > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Dependency installation failed.${NC}"
    exit 1
fi

# 3. Model Verification
echo -e "\n${GREEN}[3/4] Verifying Sentinel AI Model...${NC}"
if [ ! -f "sentinel_model.pkl" ]; then
    echo " -> Model not found. Training new model (this may take 30s)..."
    python3 train_sentinel.py
else
    echo " -> Sentinel Model found."
fi

# 4. Launch
echo -e "\n${GREEN}[4/5] Building React Frontend...${NC}"
if [ -d "dashboard-ui" ]; then
    cd dashboard-ui
    npm install &> /dev/null
    npm run build
    cd ..
else
    echo " -> Dashboard directory not found, skipping build."
fi

echo -e "\n${GREEN}[5/5] Starting WAF Service...${NC}"

# Set Production Environment Variables
export TARGET_URL="${TARGET_URL:-http://localhost:3000}"
export BLOCK_THRESHOLD="${BLOCK_THRESHOLD:-20.0}"
export MODEL_PATH="./sentinel_model.pkl"

echo -e " -> Configuration:"
echo -e "    TARGET_URL:      $TARGET_URL"
echo -e "    BLOCK_THRESHOLD: $BLOCK_THRESHOLD"
echo -e "    MODEL_PATH:      $MODEL_PATH"
echo -e "\n${BLUE}[+] WAF is Launching... (Press Ctrl+C to stop)${NC}"

# Start Mock Upstream Server
echo " -> Starting Mock Upstream App (Port 3000)..."
python3 mock_server.py > /dev/null 2>&1 &
PID_APP=$!
echo "    [PID: $PID_APP]"
sleep 2

# Using exec to replace the shell process with python
exec python3 waf.py
