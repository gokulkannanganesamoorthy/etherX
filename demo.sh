#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    EtherX AI WAF - Hackathon Demo      ${NC}"
echo -e "${BLUE}========================================${NC}"

echo -e "\n${GREEN}[+] Starting Components...${NC}"
echo -e "\n${GREEN}[+] Killing old processes...${NC}"
# Kill python processes related to our apps
lsof -ti:8000 | xargs kill -9 2>/dev/null
lsof -ti:3000 | xargs kill -9 2>/dev/null
pkill -f "python waffle.py" 2>/dev/null
pkill -f "python benign_app.py" 2>/dev/null
sleep 2

source venv/bin/activate
python benign_app.py > /dev/null 2>&1 &
PID_APP=$!
echo -e " -> Benign App Started (Port 3000) [PID: $PID_APP]"
sleep 2

python waf.py > /dev/null 2>&1 &
PID_WAF=$!
echo -e " -> WAF Engine Started (Port 8000) [PID: $PID_WAF]"

echo -e "\n${BLUE}[i] WAF Dashboard available at: http://localhost:8000/dashboard${NC}"
sleep 3

echo -e "\n${GREEN}[+] Test 1: Normal User Traffic (Allow)${NC}"
echo "Sending: GET /products"
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/products
if [ $? -eq 0 ]; then echo -e " -> ${GREEN}200 OK${NC}"; fi

echo -e "\n${RED}[+] Test 2: SQL Injection Attack (Block)${NC}"
echo "Sending: POST /search 'UNION SELECT * FROM Users'"
response=$(curl -s -w "\n%{http_code}" -d "UNION SELECT * FROM Users" http://localhost:8000/search)
code=$(echo "$response" | tail -n1)
if [ "$code" == "403" ]; then 
    echo -e " -> ${GREEN}BLOCKED (403 Forbidden)${NC}"
else
    echo -e " -> ${RED}FAILED ($code)${NC}"
fi

echo -e "\n${RED}[+] Test 3: XSS Attack (Block)${NC}"
echo "Sending: POST /feedback '<script>alert(1)</script>'"
response=$(curl -s -w "\n%{http_code}" -d "<script>alert(1)</script>" http://localhost:8000/feedback)
code=$(echo "$response" | tail -n1)
if [ "$code" == "403" ]; then 
    echo -e " -> ${GREEN}BLOCKED (403 Forbidden)${NC}"
else
    echo -e " -> ${RED}FAILED ($code)${NC}"
fi

echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}    Demo Complete! Check Dashboard.     ${NC}"
echo -e "${BLUE}========================================${NC}"
