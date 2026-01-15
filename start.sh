#!/usr/bin/env bash
#
# ArgusCloud Startup Script
# Usage: ./start.sh [dev|prod]
#
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
ENV_EXAMPLE="${SCRIPT_DIR}/.env.example"

# Default values for development
DEFAULT_NEO4J_USER="neo4j"
DEFAULT_NEO4J_PASSWORD="letmein123"
DEFAULT_AUTH_ENABLED="false"
DEFAULT_JWT_SECRET="dev-secret-change-in-production"
DEFAULT_CORS_ORIGINS="http://localhost:8080,http://127.0.0.1:8080,http://localhost:3000"
DEFAULT_LOG_LEVEL="DEBUG"

print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║     ▄▀█ █▀█ █▀▀ █ █ █▀   █▀▀ █   █▀█ █ █ █▀▄              ║"
    echo "║     █▀█ █▀▄ █▄█ █▄█ ▄█   █▄▄ █▄▄ █▄█ █▄█ █▄▀              ║"
    echo "║                                                            ║"
    echo "║        Cloud Security Graph Analytics Platform             ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${BOLD}${BLUE}═══ $1 ═══${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

check_dependencies() {
    print_section "Checking Dependencies"

    local missing_deps=0

    # Check Docker
    if command -v docker &> /dev/null; then
        local docker_version=$(docker --version | cut -d' ' -f3 | tr -d ',')
        print_success "Docker installed (v${docker_version})"
    else
        print_error "Docker is not installed"
        echo "  Install: https://docs.docker.com/get-docker/"
        missing_deps=1
    fi

    # Check Docker Compose
    if docker compose version &> /dev/null; then
        local compose_version=$(docker compose version --short 2>/dev/null || echo "unknown")
        print_success "Docker Compose installed (v${compose_version})"
    else
        print_error "Docker Compose is not installed"
        echo "  Install: https://docs.docker.com/compose/install/"
        missing_deps=1
    fi

    # Check if Docker daemon is running
    if docker info &> /dev/null; then
        print_success "Docker daemon is running"
    else
        print_error "Docker daemon is not running"
        echo "  Start with: sudo systemctl start docker"
        missing_deps=1
    fi

    if [ $missing_deps -eq 1 ]; then
        echo ""
        print_error "Please install missing dependencies and try again."
        exit 1
    fi
}

setup_env_file() {
    local mode=$1

    print_section "Environment Configuration"

    if [ "$mode" == "prod" ]; then
        # Production mode - require .env file with secure values
        if [ ! -f "$ENV_FILE" ]; then
            print_warning ".env file not found. Creating from template..."
            cp "$ENV_EXAMPLE" "$ENV_FILE"

            echo ""
            print_error "Production mode requires secure configuration!"
            echo ""
            echo -e "  ${BOLD}Required steps:${NC}"
            echo "  1. Edit .env file: ${CYAN}nano .env${NC}"
            echo "  2. Set a strong NEO4J_PASSWORD"
            echo "  3. Generate JWT_SECRET: ${CYAN}openssl rand -base64 32${NC}"
            echo "  4. Set AUTH_ENABLED=true"
            echo "  5. Set CORS_ORIGINS to your domain"
            echo ""
            exit 1
        fi

        # Validate production .env
        source "$ENV_FILE"
        local errors=0

        if [ "$NEO4J_PASSWORD" == "letmein123" ] || [ -z "$NEO4J_PASSWORD" ]; then
            print_error "NEO4J_PASSWORD must be changed from default"
            errors=1
        fi

        if [ "$AUTH_ENABLED" != "true" ]; then
            print_warning "AUTH_ENABLED should be 'true' in production"
        fi

        if [ ${#JWT_SECRET} -lt 32 ]; then
            print_error "JWT_SECRET must be at least 32 characters"
            echo "  Generate with: openssl rand -base64 32"
            errors=1
        fi

        if [ $errors -eq 1 ]; then
            echo ""
            print_error "Please fix the above issues in .env and try again."
            exit 1
        fi

        print_success "Production .env validated"

    else
        # Development mode - use defaults or existing .env
        if [ -f "$ENV_FILE" ]; then
            print_info "Using existing .env file"
            source "$ENV_FILE"
        else
            print_info "Using development defaults (no .env file needed)"
        fi

        # Export development defaults
        export NEO4J_USER="${NEO4J_USER:-$DEFAULT_NEO4J_USER}"
        export NEO4J_PASSWORD="${NEO4J_PASSWORD:-$DEFAULT_NEO4J_PASSWORD}"
        export AUTH_ENABLED="${AUTH_ENABLED:-$DEFAULT_AUTH_ENABLED}"
        export JWT_SECRET="${JWT_SECRET:-$DEFAULT_JWT_SECRET}"
        export CORS_ORIGINS="${CORS_ORIGINS:-$DEFAULT_CORS_ORIGINS}"
        export LOG_LEVEL="${LOG_LEVEL:-$DEFAULT_LOG_LEVEL}"

        print_success "Development environment configured"
    fi
}

show_config() {
    local mode=$1

    print_section "Current Configuration"

    echo -e "  ${BOLD}Mode:${NC}           ${CYAN}${mode}${NC}"
    echo -e "  ${BOLD}Neo4j User:${NC}     ${NEO4J_USER:-$DEFAULT_NEO4J_USER}"

    if [ "$mode" == "prod" ]; then
        echo -e "  ${BOLD}Neo4j Pass:${NC}     ******* (hidden)"
    else
        echo -e "  ${BOLD}Neo4j Pass:${NC}     ${NEO4J_PASSWORD:-$DEFAULT_NEO4J_PASSWORD}"
    fi

    echo -e "  ${BOLD}Auth Enabled:${NC}   ${AUTH_ENABLED:-$DEFAULT_AUTH_ENABLED}"
    echo -e "  ${BOLD}Log Level:${NC}      ${LOG_LEVEL:-$DEFAULT_LOG_LEVEL}"
    echo -e "  ${BOLD}CORS Origins:${NC}   ${CORS_ORIGINS:-$DEFAULT_CORS_ORIGINS}"
}

start_services() {
    local mode=$1

    print_section "Starting Services"

    cd "$SCRIPT_DIR"

    if [ "$mode" == "prod" ]; then
        print_info "Building and starting production containers..."
        docker compose -f docker-compose.prod.yml up -d --build
    else
        print_info "Building and starting development containers..."
        docker compose up -d --build
    fi

    echo ""
    print_success "Containers started!"
}

wait_for_services() {
    print_section "Waiting for Services"

    local max_attempts=30
    local attempt=1

    # Wait for Neo4j
    echo -n "  Neo4j: "
    while [ $attempt -le $max_attempts ]; do
        if docker exec arguscloud-neo4j wget -q --spider http://localhost:7474 2>/dev/null; then
            echo -e "${GREEN}Ready${NC}"
            break
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done

    if [ $attempt -gt $max_attempts ]; then
        echo -e "${RED}Timeout${NC}"
    fi

    # Wait for API
    attempt=1
    echo -n "  API:   "
    while [ $attempt -le $max_attempts ]; do
        if curl -sf http://localhost:9847/health > /dev/null 2>&1; then
            echo -e "${GREEN}Ready${NC}"
            break
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done

    if [ $attempt -gt $max_attempts ]; then
        echo -e "${RED}Timeout${NC}"
    fi

    # Wait for UI
    attempt=1
    echo -n "  UI:    "
    while [ $attempt -le $max_attempts ]; do
        if curl -sf http://localhost:8080 > /dev/null 2>&1; then
            echo -e "${GREEN}Ready${NC}"
            break
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done

    if [ $attempt -gt $max_attempts ]; then
        echo -e "${RED}Timeout${NC}"
    fi
}

show_access_info() {
    local mode=$1

    print_section "Access Information"

    echo -e "  ${BOLD}ArgusCloud UI:${NC}      ${GREEN}http://localhost:8080${NC}"
    echo -e "  ${BOLD}ArgusCloud API:${NC}     ${GREEN}http://localhost:9847${NC}"
    echo -e "  ${BOLD}API Health Check:${NC}   ${GREEN}http://localhost:9847/health${NC}"

    if [ "$mode" == "dev" ]; then
        echo -e "  ${BOLD}Neo4j Browser:${NC}      ${GREEN}http://localhost:7474${NC}"
        echo -e "  ${BOLD}Neo4j Credentials:${NC}  ${NEO4J_USER:-neo4j} / ${NEO4J_PASSWORD:-letmein123}"
    fi
}

show_next_steps() {
    local mode=$1

    print_section "Next Steps"

    echo -e "  ${BOLD}1. Open the UI:${NC}"
    echo -e "     ${CYAN}xdg-open http://localhost:8080${NC}  (Linux)"
    echo -e "     ${CYAN}open http://localhost:8080${NC}      (macOS)"
    echo ""

    echo -e "  ${BOLD}2. Collect AWS Data:${NC}"
    echo -e "     Using the CLI:"
    echo -e "     ${CYAN}arguscloud collect --profile your-aws-profile${NC}"
    echo ""
    echo -e "     Or via the UI:"
    echo -e "     Go to Data Management → Enter AWS credentials"
    echo ""

    echo -e "  ${BOLD}3. View Logs:${NC}"
    echo -e "     ${CYAN}docker compose logs -f${NC}"
    echo ""

    echo -e "  ${BOLD}4. Stop Services:${NC}"
    echo -e "     ${CYAN}docker compose down${NC}"
    echo ""

    if [ "$mode" == "dev" ]; then
        echo -e "  ${BOLD}5. Access Neo4j Browser:${NC}"
        echo -e "     ${CYAN}http://localhost:7474${NC}"
        echo -e "     Connect with: bolt://localhost:7687"
        echo ""
    fi
}

show_documentation() {
    print_section "Documentation"

    echo -e "  ${BOLD}Project README:${NC}"
    echo -e "     ${CYAN}https://github.com/jeremylaratro/cloudhound#readme${NC}"
    echo ""
    echo -e "  ${BOLD}API Reference:${NC}"
    echo -e "     ${CYAN}docs/api-reference.md${NC}"
    echo ""
    echo -e "  ${BOLD}Deployment Guide:${NC}"
    echo -e "     ${CYAN}docs/deployment.md${NC}"
    echo ""
    echo -e "  ${BOLD}Security Best Practices:${NC}"
    echo -e "     ${CYAN}docs/security.md${NC}"
    echo ""
    echo -e "  ${BOLD}Neo4j Integration:${NC}"
    echo -e "     ${CYAN}docs/neo4j.md${NC}"
    echo ""
    echo -e "  ${BOLD}Development Roadmap:${NC}"
    echo -e "     ${CYAN}docs/ROADMAP.md${NC}"
    echo ""
}

show_help() {
    echo "ArgusCloud Startup Script"
    echo ""
    echo "Usage: $0 [OPTIONS] [MODE]"
    echo ""
    echo "Modes:"
    echo "  dev     Start in development mode (default)"
    echo "          - Uses default credentials"
    echo "          - Auth disabled"
    echo "          - Neo4j browser exposed"
    echo "          - Hot reload enabled"
    echo ""
    echo "  prod    Start in production mode"
    echo "          - Requires .env with secure values"
    echo "          - Auth enabled"
    echo "          - Neo4j browser not exposed"
    echo "          - Resource limits enforced"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -s, --status   Show container status"
    echo "  -l, --logs     Follow container logs"
    echo "  --stop         Stop all containers"
    echo "  --clean        Stop and remove all data"
    echo ""
    echo "Examples:"
    echo "  $0              # Start in development mode"
    echo "  $0 dev          # Start in development mode"
    echo "  $0 prod         # Start in production mode"
    echo "  $0 --logs       # View logs"
    echo "  $0 --stop       # Stop services"
    echo ""
}

show_status() {
    print_banner
    print_section "Container Status"
    docker compose ps
}

show_logs() {
    docker compose logs -f
}

stop_services() {
    print_section "Stopping Services"
    docker compose down
    print_success "Services stopped"
}

clean_all() {
    print_section "Cleaning Up"
    print_warning "This will remove all containers and data volumes!"
    read -p "Are you sure? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker compose down -v --remove-orphans
        print_success "All containers and volumes removed"
    else
        print_info "Cancelled"
    fi
}

# Main script
main() {
    local mode="dev"

    # Parse arguments
    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;
        -s|--status)
            show_status
            exit 0
            ;;
        -l|--logs)
            show_logs
            exit 0
            ;;
        --stop)
            stop_services
            exit 0
            ;;
        --clean)
            clean_all
            exit 0
            ;;
        prod|production)
            mode="prod"
            ;;
        dev|development|"")
            mode="dev"
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac

    # Run startup sequence
    print_banner
    check_dependencies
    setup_env_file "$mode"
    show_config "$mode"
    start_services "$mode"
    wait_for_services
    show_access_info "$mode"
    show_next_steps "$mode"
    show_documentation

    echo -e "${GREEN}${BOLD}ArgusCloud is ready!${NC}"
    echo ""
}

main "$@"
