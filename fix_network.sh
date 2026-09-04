#!/bin/bash
echo "🔧 Fixing SSH Honeypot Network Settings"
echo "========================================="

# Get current IP
CURRENT_IP=$(hostname -I | awk '{print $1}')
echo "📡 Current IP: $CURRENT_IP"

# Kill existing processes
echo "🛑 Stopping existing services..."
pkill -f "python3 honeypot.py" 2>/dev/null
pkill -f "python3 interface.py" 2>/dev/null
pkill -f "python3 web_interface.py" 2>/dev/null

# Wait a moment
sleep 2

# Start honeypot
echo "🔐 Starting SSH Honeypot..."
python3 honeypot.py &
HONEYPOT_PID=$!

# Wait for honeypot to start
sleep 2

# Start web interface
echo "🌐 Starting Web Interface..."
python3 interface.py &
WEB_PID=$!

echo ""
echo "✅ Services started!"
echo "📡 Honeypot PID: $HONEYPOT_PID"
echo "🌐 Web PID: $WEB_PID"
echo "🌐 Web Interface: http://$CURRENT_IP:5000"
echo "📡 SSH Honeypot: ssh root@$CURRENT_IP"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for Ctrl+C
trap "echo ''; echo '🛑 Stopping services...'; kill $HONEYPOT_PID $WEB_PID 2>/dev/null; exit" INT
wait