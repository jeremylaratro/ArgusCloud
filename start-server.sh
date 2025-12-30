#!/bin/bash
#
# CloudHound Server Startup Script
# Starts Neo4j database, API server, and UI
#
# Usage: ./start-server.sh [--api-port PORT] [--ui-port PORT] [--no-auth] [--stop]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration
API_PORT=9847
UI_PORT=9848
NEO4J_HTTP_PORT=7474
NEO4J_BOLT_PORT=7687
NEO4J_URI="bolt://localhost:${NEO4J_BOLT_PORT}"
NEO4J_USER="neo4j"
NEO4J_CONTAINER="cloudhound-neo4j"
AUTH="--no-auth"
STOP=false
SKIP_NEO4J=false

# Password management
# Priority: 1. Environment variable  2. Password file  3. Auto-generate
PASSWORD_FILE="${SCRIPT_DIR}/.neo4j_password"

get_neo4j_password() {
    # Check environment variable first
    if [[ -n "${CLOUDHOUND_NEO4J_PASSWORD:-}" ]]; then
        echo "$CLOUDHOUND_NEO4J_PASSWORD"
        return 0
    fi

    # Check password file
    if [[ -f "$PASSWORD_FILE" ]]; then
        cat "$PASSWORD_FILE"
        return 0
    fi

    # Generate secure password (32 chars, mixed case, numbers, special chars)
    local password
    password=$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)

    # Store it securely
    echo "$password" > "$PASSWORD_FILE"
    chmod 600 "$PASSWORD_FILE"

    echo "$password"
    return 0
}

NEO4J_PASSWORD=$(get_neo4j_password)

# Python environment - use pyenv if available
if [[ -f ~/.pyenv/versions/main/bin/activate ]]; then
    source ~/.pyenv/versions/main/bin/activate
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        --api-port)
            API_PORT="$2"
            shift 2
            ;;
        --ui-port)
            UI_PORT="$2"
            shift 2
            ;;
        --auth)
            AUTH=""
            shift
            ;;
        --no-auth)
            AUTH="--no-auth"
            shift
            ;;
        --skip-neo4j)
            SKIP_NEO4J=true
            shift
            ;;
        --stop)
            STOP=true
            shift
            ;;
        --reset-password)
            rm -f "$PASSWORD_FILE"
            NEO4J_PASSWORD=$(get_neo4j_password)
            echo "New Neo4j password generated and saved to $PASSWORD_FILE"
            echo "Password: $NEO4J_PASSWORD"
            echo ""
            echo "IMPORTANT: You must also update Neo4j with this password!"
            echo "If using Docker, recreate the container with:"
            echo "  docker rm -f cloudhound-neo4j"
            echo "  ./start-server.sh"
            exit 0
            ;;
        --show-password)
            echo "Neo4j password: $NEO4J_PASSWORD"
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --api-port PORT    API server port (default: 9847)"
            echo "  --ui-port PORT     UI server port (default: 9848)"
            echo "  --auth             Enable API authentication"
            echo "  --no-auth          Disable API authentication (default)"
            echo "  --skip-neo4j       Skip starting Neo4j (use existing instance)"
            echo "  --stop             Stop all running services"
            echo "  --reset-password   Generate a new Neo4j password"
            echo "  --show-password    Display current Neo4j password"
            echo ""
            echo "Environment Variables:"
            echo "  CLOUDHOUND_NEO4J_PASSWORD   Override Neo4j password"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# PID files stored in script directory for user access
PID_DIR="${SCRIPT_DIR}/.pids"
mkdir -p "$PID_DIR"

# Stop all services
if $STOP; then
    echo "Stopping CloudHound services..."

    # Stop API server
    if [[ -f "${PID_DIR}/api.pid" ]]; then
        kill $(cat "${PID_DIR}/api.pid") 2>/dev/null && echo "  Stopped API server" || true
        rm -f "${PID_DIR}/api.pid"
    else
        # Fallback: kill by process name
        pkill -f "cloudhound.py serve" 2>/dev/null && echo "  Stopped API server" || true
    fi

    # Stop UI server
    if [[ -f "${PID_DIR}/ui.pid" ]]; then
        kill $(cat "${PID_DIR}/ui.pid") 2>/dev/null && echo "  Stopped UI server" || true
        rm -f "${PID_DIR}/ui.pid"
    else
        # Fallback: kill by process name
        pkill -f "http.server.*${UI_PORT}" 2>/dev/null && echo "  Stopped UI server" || true
    fi

    # Stop Neo4j container
    if docker ps -q -f name="${NEO4J_CONTAINER}" 2>/dev/null | grep -q .; then
        docker stop "${NEO4J_CONTAINER}" >/dev/null && echo "  Stopped Neo4j container"
    fi

    echo "All services stopped."
    exit 0
fi

# Update UI to point to correct API port
sed -i "s|value=\"http://127.0.0.1:[0-9]*\"|value=\"http://127.0.0.1:${API_PORT}\"|g" ui/index.html 2>/dev/null || true

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    CloudHound Server                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Start Neo4j database
if ! $SKIP_NEO4J; then
    echo "[1/3] Starting Neo4j database..."

    # Check if container exists
    if docker ps -a -q -f name="${NEO4J_CONTAINER}" 2>/dev/null | grep -q .; then
        # Container exists, check if running
        if docker ps -q -f name="${NEO4J_CONTAINER}" 2>/dev/null | grep -q .; then
            echo "  Neo4j already running"
        else
            # Container exists but stopped, start it
            docker start "${NEO4J_CONTAINER}" >/dev/null
            echo "  Neo4j container started"
        fi
    else
        # Create and start new container
        docker run -d --name "${NEO4J_CONTAINER}" \
            -p ${NEO4J_HTTP_PORT}:7474 \
            -p ${NEO4J_BOLT_PORT}:7687 \
            -e NEO4J_AUTH=${NEO4J_USER}/${NEO4J_PASSWORD} \
            -v "${SCRIPT_DIR}/neo4j/data:/data" \
            -v "${SCRIPT_DIR}/neo4j/logs:/logs" \
            neo4j:latest >/dev/null
        echo "  Neo4j container created and started"
    fi

    # Wait for Neo4j to be ready
    echo "  Waiting for Neo4j to be ready..."
    for i in {1..30}; do
        if curl -s "http://localhost:${NEO4J_HTTP_PORT}" >/dev/null 2>&1; then
            echo "  Neo4j is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            echo "  Warning: Neo4j may not be fully ready yet"
        fi
        sleep 1
    done
else
    echo "[1/3] Skipping Neo4j (--skip-neo4j specified)"
fi

# Log directory
LOG_DIR="${SCRIPT_DIR}/.logs"
mkdir -p "$LOG_DIR"

# Start API server
echo "[2/3] Starting API server on port ${API_PORT}..."
nohup python "${SCRIPT_DIR}/cloudhound.py" serve --port $API_PORT --neo4j-uri $NEO4J_URI --neo4j-user $NEO4J_USER --neo4j-password $NEO4J_PASSWORD $AUTH > "${LOG_DIR}/api.log" 2>&1 &
echo $! > "${PID_DIR}/api.pid"
sleep 2

# Verify API started
if ! kill -0 $(cat "${PID_DIR}/api.pid") 2>/dev/null; then
    echo "  ERROR: API server failed to start. Check ${LOG_DIR}/api.log"
    cat "${LOG_DIR}/api.log" | tail -10
    exit 1
fi

# Start UI server
echo "[3/3] Starting UI server on port ${UI_PORT}..."
nohup python -m http.server $UI_PORT --directory "${SCRIPT_DIR}/ui" > "${LOG_DIR}/ui.log" 2>&1 &
echo $! > "${PID_DIR}/ui.pid"

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  CloudHound is running!                                          ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  UI:     http://localhost:${UI_PORT}                                  ║"
echo "║  API:    http://localhost:${API_PORT}                                  ║"
echo "║  Neo4j:  http://localhost:${NEO4J_HTTP_PORT} (browser)                       ║"
echo "║  Auth:   $([ -z "$AUTH" ] && printf "enabled " || printf "disabled")                                             ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  Logs:   ${LOG_DIR}/                                  ║"
echo "║  PIDs:   ${PID_DIR}/                                  ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  Commands:                                                       ║"
echo "║    Stop:           ./start-server.sh --stop                      ║"
echo "║    Show password:  ./start-server.sh --show-password             ║"
echo "║    View API logs:  tail -f ${LOG_DIR}/api.log          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
