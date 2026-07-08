#!/bin/bash

# VulnSightAI v2.0 Start Script
# This script starts both the Golang backend and Next.js frontend

echo -e "\033[0;34m=====================================================\033[0m"
echo -e "\033[1;36m 🛡️  Starting VulnSightAI v2.0 (Military Grade) 🛡️\033[0m"
echo -e "\033[0;34m=====================================================\033[0m"

# Ensure Ollama is running (non-blocking)
echo -e "\033[1;33m[+] Checking local AI Engine (Ollama)...\033[0m"
if pgrep -x "ollama" > /dev/null
then
    echo -e "\033[0;32m[✓] Ollama is running.\033[0m"
else
    echo -e "\033[1;31m[!] Ollama is not running! Starting ollama serve in background...\033[0m"
    ollama serve >/dev/null 2>&1 &
    sleep 2
fi

# 1. Start Go Backend
echo -e "\033[1;33m[+] Starting High-Concurrency Go Backend Engine...\033[0m"
cd backend
go run cmd/vulnsight/main.go > ../backend.log 2>&1 &
BACKEND_PID=$!
echo -e "\033[0;32m[✓] Backend Engine started (Port 8080) [PID: $BACKEND_PID]\033[0m"

# 2. Wait a moment to ensure database is created
sleep 2

# 3. Start Next.js Frontend
echo -e "\033[1;33m[+] Starting Next.js interactive Matrix Dashboard...\033[0m"
cd ../frontend
npm run dev > ../frontend.log 2>&1 &
FRONTEND_PID=$!
echo -e "\033[0;32m[✓] Dashboard started (Port 3000) [PID: $FRONTEND_PID]\033[0m"

echo -e "\033[0;34m=====================================================\033[0m"
echo -e "\033[1;36m All systems engaged.\033[0m"
echo -e " 🌍 Dashboard URL: \033[1;32mhttp://localhost:3000\033[0m"
echo -e " 📡 Engine URL: \033[1;32mhttp://localhost:8080\033[0m"
echo -e "\033[0;34m=====================================================\033[0m"
echo -e "\033[1;31mPress CTRL+C to stop all services.\033[0m"

# Trap CTRL+C to kill both background processes
trap "echo -e '\n\033[1;31m[!] Shutting down down VulnSightAI...\033[0m'; kill $BACKEND_PID $FRONTEND_PID; exit 0" SIGINT SIGTERM

# Wait indefinitely until interrupted
wait
