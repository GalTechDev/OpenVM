
#!/bin/bash
echo "Starting OpenVM Services..."
echo "This script assumes you have sudo privileges for docker."

# 1. Start SSH Server in background
echo "Starting SSH Server on port 2222..."
python3 server.py &
SERVER_PID=$!
echo "SSH Server PID: $SERVER_PID"

# 2. Start Web App
echo "Starting Web Interface on http://localhost:5000..."
python3 web_app.py

# Cleanup on exit
kill $SERVER_PID
