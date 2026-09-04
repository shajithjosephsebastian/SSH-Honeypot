#!/bin/bash

# =============================================
# SSH Honeypot - Launcher Script
# =============================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
HONEYPOT_SCRIPT="honeypot.py"
INTERFACE_SCRIPT="interface.py"
HONEYPOT_PORT=22
WEB_PORT=5000
LOG_FILE="honeypot.log"
REQUIREMENTS_FILE="requirements.txt"
VENV_DIR="honeypot-env"

# =============================================
# Functions
# =============================================

print_banner() {
    echo -e "${BLUE}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║   🛡️  SSH Honeypot - Security Monitoring System          ║"
    echo "║                                                            ║"
    echo "║   ${CYAN}🔐 Honeypot     : Port ${HONEYPOT_PORT}${BLUE}                        ║"
    echo "║   ${CYAN}🌐 Web Interface : http://localhost:${WEB_PORT}${BLUE}              ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_python() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python3 is not installed. Please install Python3 first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Python3 found: $(python3 --version)${NC}"
}

create_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        echo -e "${YELLOW}📦 Creating virtual environment...${NC}"
        python3 -m venv "$VENV_DIR"
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Failed to create virtual environment. Installing python3-venv...${NC}"
            sudo apt update && sudo apt install -y python3-venv
            python3 -m venv "$VENV_DIR"
        fi
        echo -e "${GREEN}✅ Virtual environment created in ${VENV_DIR}${NC}"
    fi
}

activate_venv() {
    if [ -d "$VENV_DIR" ]; then
        source "$VENV_DIR/bin/activate"
        echo -e "${GREEN}✅ Virtual environment activated${NC}"
    else
        echo -e "${RED}❌ Virtual environment not found. Run create_venv first.${NC}"
        exit 1
    fi
}

check_requirements() {
    echo -e "${YELLOW}📦 Checking Python dependencies...${NC}"
    
    # Create and activate virtual environment
    create_venv
    activate_venv
    
    if [ -f "$REQUIREMENTS_FILE" ]; then
        echo -e "${BLUE}📄 Found requirements.txt${NC}"
        
        # Check if all requirements are installed
        MISSING=0
        while IFS= read -r line || [ -n "$line" ]; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            PACKAGE=$(echo "$line" | sed -E 's/([^>=<~!]+).*/\1/' | xargs)
            if ! python -c "import $PACKAGE" 2>/dev/null; then
                echo -e "${YELLOW}⚠️  Missing: $PACKAGE${NC}"
                MISSING=1
            fi
        done < "$REQUIREMENTS_FILE"
        
        if [ $MISSING -eq 1 ]; then
            echo -e "${YELLOW}📦 Installing missing dependencies...${NC}"
            pip install -r "$REQUIREMENTS_FILE"
            if [ $? -ne 0 ]; then
                echo -e "${RED}❌ Failed to install dependencies. Please install manually:${NC}"
                echo -e "${YELLOW}   source ${VENV_DIR}/bin/activate${NC}"
                echo -e "${YELLOW}   pip install -r $REQUIREMENTS_FILE${NC}"
                exit 1
            fi
            echo -e "${GREEN}✅ All dependencies installed successfully${NC}"
        else
            echo -e "${GREEN}✅ All dependencies are installed${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  requirements.txt not found${NC}"
        echo -e "${YELLOW}📦 Installing basic dependencies...${NC}"
        pip install flask paramiko requests 2>/dev/null
    fi
}

# =============================================
# NETWORK FIX FUNCTIONS
# =============================================

get_current_ip() {
    # Get the primary IP address
    IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -z "$IP" ]; then
        IP=$(ip route get 1 2>/dev/null | awk '{print $NF;exit}' 2>/dev/null)
    fi
    if [ -z "$IP" ]; then
        IP=$(ifconfig 2>/dev/null | grep -E 'inet [0-9]' | grep -v 127.0.0.1 | awk '{print $2}' | head -1)
    fi
    if [ -z "$IP" ]; then
        IP="127.0.0.1"
    fi
    echo "$IP"
}

get_network_info() {
    echo -e "${YELLOW}🌐 Network Information:${NC}"
    
    # Get current IP
    CURRENT_IP=$(get_current_ip)
    echo -e "   ${BLUE}▶${NC} Current IP: ${GREEN}${CURRENT_IP}${NC}"
    
    # Get interface name
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -n "$INTERFACE" ]; then
        echo -e "   ${BLUE}▶${NC} Interface: ${GREEN}${INTERFACE}${NC}"
    fi
    
    # Check if connected to network
    if ping -c 1 -W 1 8.8.8.8 &>/dev/null; then
        echo -e "   ${BLUE}▶${NC} Internet: ${GREEN}Connected${NC}"
    else
        echo -e "   ${BLUE}▶${NC} Internet: ${YELLOW}No connection${NC}"
    fi
    
    echo ""
}

fix_network() {
    echo -e "${YELLOW}🔧 Fixing network configuration...${NC}"
    
    # Get current IP
    CURRENT_IP=$(get_current_ip)
    echo -e "${BLUE}📡 Current IP: ${CURRENT_IP}${NC}"
    
    # Check if honeypot is configured to listen on all interfaces
    if grep -q "HOST = '0.0.0.0'" "$HONEYPOT_SCRIPT" 2>/dev/null; then
        echo -e "${GREEN}✅ Honeypot configured to listen on all interfaces (0.0.0.0)${NC}"
    else
        echo -e "${YELLOW}⚠️  Updating honeypot to listen on all interfaces...${NC}"
        sed -i "s/HOST = .*/HOST = '0.0.0.0'/" "$HONEYPOT_SCRIPT"
    fi
    
    # Check if web interface is configured to listen on all interfaces
    if grep -q "host='0.0.0.0'" "$INTERFACE_SCRIPT" 2>/dev/null; then
        echo -e "${GREEN}✅ Web interface configured to listen on all interfaces (0.0.0.0)${NC}"
    else
        echo -e "${YELLOW}⚠️  Updating web interface to listen on all interfaces...${NC}"
        sed -i "s/host='.*'/host='0.0.0.0'/" "$INTERFACE_SCRIPT"
    fi
    
    # Update the HOST variable in honeypot.py if it's set to a specific IP
    if grep -q "HOST = '[0-9]" "$HONEYPOT_SCRIPT" 2>/dev/null; then
        echo -e "${YELLOW}⚠️  Updating HOST to 0.0.0.0...${NC}"
        sed -i "s/HOST = '[0-9.]*'/HOST = '0.0.0.0'/" "$HONEYPOT_SCRIPT"
    fi
    
    # Restart networking (if needed)
    if [ "$1" == "--restart-networking" ]; then
        echo -e "${YELLOW}🔄 Restarting networking service...${NC}"
        if command -v systemctl &> /dev/null; then
            sudo systemctl restart networking 2>/dev/null || sudo systemctl restart NetworkManager 2>/dev/null
        else
            sudo service networking restart 2>/dev/null || sudo service network-manager restart 2>/dev/null
        fi
        echo -e "${GREEN}✅ Networking restarted${NC}"
    fi
    
    # Show updated network info
    echo ""
    echo -e "${GREEN}✅ Network configuration fixed!${NC}"
    echo -e "${BLUE}📡 Services will listen on: ${GREEN}0.0.0.0 (all interfaces)${NC}"
    echo -e "${BLUE}🌐 Access web interface from other devices at:${NC}"
    echo -e "   ${GREEN}http://${CURRENT_IP}:${WEB_PORT}${NC}"
    echo ""
}

check_ports() {
    echo -e "${YELLOW}🔍 Checking ports...${NC}"
    
    # Check if port 22 is in use
    if lsof -Pi :$HONEYPOT_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Port $HONEYPOT_PORT is already in use${NC}"
        echo -e "${BLUE}   This might be your system's SSH service.${NC}"
        echo -e "${BLUE}   Options:${NC}"
        echo -e "${BLUE}   1. Stop system SSH: sudo systemctl stop ssh${NC}"
        echo -e "${BLUE}   2. Change HONEYPOT_PORT in run.sh${NC}"
        echo -e "${BLUE}   3. Keep both running (honeypot on different port)${NC}"
        echo ""
        read -p "Do you want to continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        echo -e "${GREEN}✅ Port $HONEYPOT_PORT is available${NC}"
    fi
    
    # Check if port 5000 is in use
    if lsof -Pi :$WEB_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Port $WEB_PORT is already in use${NC}"
        echo -e "${BLUE}   This might be another Flask application.${NC}"
        read -p "Do you want to kill the process using port $WEB_PORT? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            PID=$(lsof -ti :$WEB_PORT)
            kill -9 $PID 2>/dev/null
            echo -e "${GREEN}✅ Killed process $PID using port $WEB_PORT${NC}"
        else
            echo -e "${RED}❌ Cannot continue. Please free port $WEB_PORT${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}✅ Port $WEB_PORT is available${NC}"
    fi
}

check_files() {
    echo -e "${YELLOW}📁 Checking files...${NC}"
    
    if [ ! -f "$HONEYPOT_SCRIPT" ]; then
        echo -e "${RED}❌ $HONEYPOT_SCRIPT not found!${NC}"
        exit 1
    fi
    
    if [ ! -f "$INTERFACE_SCRIPT" ]; then
        echo -e "${RED}❌ $INTERFACE_SCRIPT not found!${NC}"
        exit 1
    fi
    
    if [ ! -d "templates" ]; then
        echo -e "${YELLOW}⚠️  templates directory not found${NC}"
        echo -e "${BLUE}   Creating templates directory...${NC}"
        mkdir -p templates
    fi
    
    if [ ! -f "templates/index.html" ]; then
        echo -e "${YELLOW}⚠️  templates/index.html not found${NC}"
        echo -e "${BLUE}   Please place index.html in the templates directory${NC}"
    else
        echo -e "${GREEN}✅ All files are present${NC}"
    fi
}

check_log_file() {
    if [ ! -f "$LOG_FILE" ]; then
        echo -e "${YELLOW}📝 Creating log file: $LOG_FILE${NC}"
        touch "$LOG_FILE"
    fi
}

check_host_key() {
    if [ ! -f "host_rsa_key" ]; then
        echo -e "${YELLOW}🔑 Generating host SSH key...${NC}"
        ssh-keygen -t rsa -f host_rsa_key -N '' 2>/dev/null
        echo -e "${GREEN}✅ Host key generated${NC}"
    else
        echo -e "${GREEN}✅ Host key exists${NC}"
    fi
}

kill_services() {
    echo -e "${YELLOW}🛑 Stopping existing services...${NC}"
    pkill -f "python.* $HONEYPOT_SCRIPT" 2>/dev/null
    pkill -f "python.* $INTERFACE_SCRIPT" 2>/dev/null
    sleep 1
    echo -e "${GREEN}✅ Services stopped${NC}"
}

start_services() {
    # Activate virtual environment
    activate_venv
    
    echo -e "${GREEN}🚀 Starting services...${NC}"
    echo ""
    
    # Start honeypot
    echo -e "${BLUE}🔐 Starting SSH Honeypot on port $HONEYPOT_PORT...${NC}"
    python "$HONEYPOT_SCRIPT" > honeypot_output.log 2>&1 &
    HONEYPOT_PID=$!
    echo -e "${GREEN}   ✅ Honeypot started (PID: $HONEYPOT_PID)${NC}"
    
    # Wait for honeypot to initialize
    sleep 2
    
    # Check if honeypot is running
    if ! kill -0 $HONEYPOT_PID 2>/dev/null; then
        echo -e "${RED}❌ Honeypot failed to start. Check honeypot_output.log${NC}"
        exit 1
    fi
    
    # Start web interface
    echo -e "${BLUE}🌐 Starting Web Interface on port $WEB_PORT...${NC}"
    python "$INTERFACE_SCRIPT" > web_output.log 2>&1 &
    WEB_PID=$!
    echo -e "${GREEN}   ✅ Web Interface started (PID: $WEB_PID)${NC}"
    
    # Wait for web interface to initialize
    sleep 2
    
    # Check if web interface is running
    if ! kill -0 $WEB_PID 2>/dev/null; then
        echo -e "${RED}❌ Web Interface failed to start. Check web_output.log${NC}"
        kill $HONEYPOT_PID 2>/dev/null
        exit 1
    fi
    
    echo ""
}

show_status() {
    clear
    print_banner
    
    # Show network info
    get_network_info
    
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ All services are running!${NC}"
    echo ""
    echo -e "${CYAN}📡 SSH Honeypot:${NC}"
    echo -e "   ${BLUE}▶${NC} Listening on port ${BOLD}${HONEYPOT_PORT}${NC}"
    echo -e "   ${BLUE}▶${NC} Log file: ${BOLD}${LOG_FILE}${NC}"
    echo -e "   ${BLUE}▶${NC} PID: ${BOLD}${HONEYPOT_PID}${NC}"
    echo ""
    echo -e "${CYAN}🌐 Web Interface:${NC}"
    echo -e "   ${BLUE}▶${NC} Local URL: ${BOLD}http://localhost:${WEB_PORT}${NC}"
    echo -e "   ${BLUE}▶${NC} Network URL: ${BOLD}http://$(get_current_ip):${WEB_PORT}${NC}"
    echo -e "   ${BLUE}▶${NC} PID: ${BOLD}${WEB_PID}${NC}"
    echo ""
    echo -e "${YELLOW}📝 Fake Credentials:${NC}"
    echo -e "   ${BLUE}▶${NC} root:password123"
    echo -e "   ${BLUE}▶${NC} admin:admin123"
    echo -e "   ${BLUE}▶${NC} user:user123"
    echo -e "   ${BLUE}▶${NC} test:test123"
    echo ""
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}💡 Quick Commands:${NC}"
    echo -e "   ${BLUE}▶${NC} View logs: ${CYAN}tail -f ${LOG_FILE}${NC}"
    echo -e "   ${BLUE}▶${NC} Test connection: ${CYAN}ssh root@localhost${NC}"
    echo -e "   ${BLUE}▶${NC} Test from network: ${CYAN}ssh root@$(get_current_ip)${NC}"
    echo -e "   ${BLUE}▶${NC} Stop services: ${CYAN}Press Ctrl+C${NC}"
    echo ""
    echo -e "${YELLOW}📊 Monitoring:${NC}"
    echo -e "   ${BLUE}▶${NC} Local Dashboard: ${CYAN}http://localhost:${WEB_PORT}${NC}"
    echo -e "   ${BLUE}▶${NC} Network Dashboard: ${CYAN}http://$(get_current_ip):${WEB_PORT}${NC}"
    echo -e "   ${BLUE}▶${NC} API Endpoint: ${CYAN}http://$(get_current_ip):${WEB_PORT}/api/logs${NC}"
    echo ""
    echo -e "${RED}${BOLD}Press Ctrl+C to stop all services${NC}"
    echo ""
}

cleanup() {
    echo ""
    echo -e "${YELLOW}🛑 Shutting down services...${NC}"
    
    # Kill honeypot
    if kill -0 $HONEYPOT_PID 2>/dev/null; then
        kill $HONEYPOT_PID 2>/dev/null
        echo -e "${GREEN}   ✅ Honeypot stopped${NC}"
    fi
    
    # Kill web interface
    if kill -0 $WEB_PID 2>/dev/null; then
        kill $WEB_PID 2>/dev/null
        echo -e "${GREEN}   ✅ Web Interface stopped${NC}"
    fi
    
    # Kill any remaining processes
    pkill -f "python.* $HONEYPOT_SCRIPT" 2>/dev/null
    pkill -f "python.* $INTERFACE_SCRIPT" 2>/dev/null
    
    # Deactivate virtual environment
    deactivate 2>/dev/null
    
    echo -e "${GREEN}✅ All services stopped${NC}"
    echo -e "${BLUE}👋 Goodbye!${NC}"
    exit 0
}

show_help() {
    echo -e "${BLUE}${BOLD}SSH Honeypot Launcher${NC}"
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo -e "  ./run.sh              Start the honeypot and web interface"
    echo -e "  ./run.sh --help       Show this help message"
    echo -e "  ./run.sh --stop       Stop all running services"
    echo -e "  ./run.sh --restart    Restart all services"
    echo -e "  ./run.sh --status     Show service status"
    echo -e "  ./run.sh --fix-network Fix network configuration"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  --help                Display this help message"
    echo -e "  --stop                Stop all running services"
    echo -e "  --restart             Restart all services"
    echo -e "  --status              Show current service status"
    echo -e "  --fix-network         Fix network configuration and show IP info"
    echo -e "  --fix-network-restart Fix network and restart networking service"
    echo ""
    echo -e "${YELLOW}Files:${NC}"
    echo -e "  ${HONEYPOT_SCRIPT}        Main SSH honeypot"
    echo -e "  ${INTERFACE_SCRIPT}       Flask web interface"
    echo -e "  ${LOG_FILE}               Log file for honeypot"
    echo -e "  ${VENV_DIR}/              Virtual environment directory"
    echo -e "  honeypot_output.log       Honeypot output log"
    echo -e "  web_output.log            Web interface output log"
    echo ""
}

show_status_only() {
    echo -e "${BLUE}${BOLD}Service Status${NC}"
    echo ""
    
    # Show network info
    get_network_info
    
    # Check honeypot
    HONEYPOT_RUNNING=$(pgrep -f "python.* $HONEYPOT_SCRIPT" | head -1)
    if [ -n "$HONEYPOT_RUNNING" ]; then
        echo -e "  ${GREEN}✅${NC} Honeypot is running (PID: $HONEYPOT_RUNNING)"
    else
        echo -e "  ${RED}❌${NC} Honeypot is not running"
    fi
    
    # Check web interface
    WEB_RUNNING=$(pgrep -f "python.* $INTERFACE_SCRIPT" | head -1)
    if [ -n "$WEB_RUNNING" ]; then
        echo -e "  ${GREEN}✅${NC} Web Interface is running (PID: $WEB_RUNNING)"
    else
        echo -e "  ${RED}❌${NC} Web Interface is not running"
    fi
    
    # Check ports
    echo ""
    echo -e "${YELLOW}Port Status:${NC}"
    if lsof -Pi :$HONEYPOT_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "  ${GREEN}✅${NC} Port $HONEYPOT_PORT is listening"
    else
        echo -e "  ${RED}❌${NC} Port $HONEYPOT_PORT is not listening"
    fi
    
    if lsof -Pi :$WEB_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "  ${GREEN}✅${NC} Port $WEB_PORT is listening"
    else
        echo -e "  ${RED}❌${NC} Port $WEB_PORT is not listening"
    fi
    
    # Show log file size
    if [ -f "$LOG_FILE" ]; then
        SIZE=$(du -h "$LOG_FILE" | cut -f1)
        LINES=$(wc -l < "$LOG_FILE")
        echo ""
        echo -e "${YELLOW}Log File:${NC}"
        echo -e "  ${BLUE}▶${NC} Size: $SIZE"
        echo -e "  ${BLUE}▶${NC} Lines: $LINES"
    fi
    
    # Show access URLs
    echo ""
    echo -e "${YELLOW}Access URLs:${NC}"
    CURRENT_IP=$(get_current_ip)
    echo -e "  ${BLUE}▶${NC} Local: ${CYAN}http://localhost:${WEB_PORT}${NC}"
    echo -e "  ${BLUE}▶${NC} Network: ${CYAN}http://${CURRENT_IP}:${WEB_PORT}${NC}"
}

# =============================================
# Main Script
# =============================================

# Handle command line arguments
case "$1" in
    --help|-h)
        show_help
        exit 0
        ;;
    --stop)
        kill_services
        exit 0
        ;;
    --restart)
        kill_services
        # Continue to start
        ;;
    --status)
        show_status_only
        exit 0
        ;;
    --fix-network)
        clear
        print_banner
        fix_network
        echo ""
        echo -e "${GREEN}Network fix complete! You can now run ./run.sh to start services${NC}"
        exit 0
        ;;
    --fix-network-restart)
        clear
        print_banner
        fix_network "--restart-networking"
        echo ""
        echo -e "${GREEN}Network fix complete! You can now run ./run.sh to start services${NC}"
        exit 0
        ;;
    *)
        # Normal start
        ;;
esac

# Trap Ctrl+C
trap cleanup SIGINT SIGTERM

# Run checks
clear
print_banner
echo -e "${YELLOW}🔍 Performing system checks...${NC}"
echo ""

check_python
check_requirements
check_ports
check_files
check_log_file
check_host_key

# Check and fix network configuration
echo ""
echo -e "${YELLOW}🔧 Checking network configuration...${NC}"
CURRENT_IP=$(get_current_ip)
echo -e "${BLUE}📡 Current IP: ${GREEN}${CURRENT_IP}${NC}"

# Ensure services listen on all interfaces
fix_network

# Kill existing services
kill_services

# Start services
start_services

# Show status and keep running
show_status

# Wait for Ctrl+C
wait
