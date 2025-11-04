#!/bin/bash

# Stop the static analysis server
echo "Stopping static analysis server..."

# Find and kill the go process running the server
pkill -f "go run cmd/server/main.go" && echo "Static analysis server stopped" || echo "No server process found"

# Verify it's stopped
sleep 2
if curl -s http://localhost:7082/v1/health >/dev/null 2>&1; then
    echo "Warning: Server may still be running on port 7082"
else
    echo "Server stopped successfully"
fi