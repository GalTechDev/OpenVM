@echo off
echo Starting OpenVM Services...
echo This script requires Python 3 and Docker Desktop to be running.

REM 1. Start SSH Server in background
echo Starting SSH Server on port 2222...
start /B python server.py
set SERVER_PID=%!

REM 2. Start Web App
echo Starting Web Interface on http://localhost:5000...
python web_app.py
