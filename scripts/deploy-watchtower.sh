#!/bin/bash
# Soul Watchtower Deployment Script
# Deploys the anomaly detection watchtower infrastructure

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MONITORING_DIR="$PROJECT_ROOT/monitoring"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Soul Watchtower Deployment Script                    ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to print step
step() {
    echo -e "${GREEN}[✓]${NC} $1"
}

# Function to print warning
warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Function to print error
error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

if ! command -v docker &> /dev/null; then
    error "Docker is not installed. Please install Docker first."
    exit 1
fi
step "Docker is installed"

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi
step "Docker Compose is installed"

# Check if .env file exists
if [ ! -f "$MONITORING_DIR/.env" ]; then
    warn ".env file not found. Creating from template..."
    cp "$MONITORING_DIR/.env.example" "$MONITORING_DIR/.env"
    warn "Please edit $MONITORING_DIR/.env with your configuration"
    warn "At minimum, set RPC_ENDPOINTS and SLACK_WEBHOOK_URL"
    echo ""
    read -p "Press Enter to continue after editing .env, or Ctrl+C to abort..."
fi
step "Environment file exists"

# Source environment
set -a
source "$MONITORING_DIR/.env"
set +a

# Validate required environment variables
if [ -z "$RPC_ENDPOINTS" ]; then
    error "RPC_ENDPOINTS is not set in .env"
    exit 1
fi
step "RPC_ENDPOINTS configured"

if [ -z "$SLACK_WEBHOOK_URL" ]; then
    warn "SLACK_WEBHOOK_URL is not set. Alerts will only be logged."
fi

# Create required directories
echo ""
echo -e "${BLUE}Creating directories...${NC}"
mkdir -p "$MONITORING_DIR/data/prometheus"
mkdir -p "$MONITORING_DIR/data/grafana"
mkdir -p "$MONITORING_DIR/data/redis"
mkdir -p "$MONITORING_DIR/logs"
step "Directories created"

# Build watchtower image
echo ""
echo -e "${BLUE}Building watchtower image...${NC}"
docker build -t soul-watchtower:latest -f "$PROJECT_ROOT/docker/Dockerfile.watchtower" "$PROJECT_ROOT"
step "Watchtower image built"

# Stop existing containers
echo ""
echo -e "${BLUE}Stopping existing containers...${NC}"
cd "$MONITORING_DIR"
docker compose -f docker-compose.watchtower.yml down 2>/dev/null || true
step "Existing containers stopped"

# Start the stack
echo ""
echo -e "${BLUE}Starting watchtower stack...${NC}"
docker compose -f docker-compose.watchtower.yml up -d
step "Watchtower stack started"

# Wait for services to be healthy
echo ""
echo -e "${BLUE}Waiting for services to be healthy...${NC}"
sleep 5

# Check service status
echo ""
echo -e "${BLUE}Service Status:${NC}"

check_service() {
    local service=$1
    local url=$2
    if curl -s "$url" > /dev/null 2>&1; then
        step "$service is healthy"
        return 0
    else
        warn "$service is not yet healthy"
        return 1
    fi
}

# Give services more time to start
MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    HEALTHY=true
    
    if ! docker ps | grep -q soul-watchtower-1; then
        HEALTHY=false
    fi
    
    if ! docker ps | grep -q pil-prometheus; then
        HEALTHY=false
    fi
    
    if $HEALTHY; then
        break
    fi
    
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo -ne "\rWaiting for services... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 2
done
echo ""

# Final status check
docker compose -f docker-compose.watchtower.yml ps

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            Deployment Complete!                           ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Access the services at:"
echo -e "  ${BLUE}Watchtower 1 Metrics:${NC} http://localhost:${PROMETHEUS_PORT_1:-9090}/metrics"
echo -e "  ${BLUE}Watchtower 2 Metrics:${NC} http://localhost:${PROMETHEUS_PORT_2:-9091}/metrics"
echo -e "  ${BLUE}Prometheus:${NC}           http://localhost:${PROMETHEUS_SERVER_PORT:-9092}"
echo -e "  ${BLUE}Grafana:${NC}              http://localhost:${GRAFANA_PORT:-3001}"
echo -e "  ${BLUE}AlertManager:${NC}         http://localhost:${ALERTMANAGER_PORT:-9093}"
echo ""
echo -e "Grafana login: admin / ${GF_SECURITY_ADMIN_PASSWORD:-changeme}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo -e "  1. Import the Grafana dashboard from:"
echo -e "     $MONITORING_DIR/config/grafana/dashboards/watchtower.json"
echo -e "  2. Check watchtower logs:"
echo -e "     docker logs -f soul-watchtower-1"
echo -e "  3. Verify chain connections in Prometheus targets"
echo ""
