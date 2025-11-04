#!/bin/bash

# Start the static analysis server
cd "$(dirname "$0")"

# Check if server is already running
if curl -s http://localhost:7082/v1/health >/dev/null 2>&1; then
    echo "Static analysis server is already running on port 7082"
    exit 0
fi

echo "Starting static analysis server..."
nohup go run cmd/server/main.go > server.log 2>&1 &

# Wait a moment and check if it started successfully
sleep 3
if curl -s http://localhost:7082/v1/health >/dev/null 2>&1; then
    echo "Static analysis server started successfully on port 7082"
else
    echo "Failed to start static analysis server. Check server.log for details."
    tail -20 server.log
    exit 1
fi