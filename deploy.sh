#!/bin/bash

set -e

echo "=========================================="
echo "  VulnScope Build Script (Optimized)"
echo "=========================================="

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Default services - only essential ones by default
SERVICES="${@:-api frontend}"

# Parse arguments
FORCE_BUILD=false
STOP_SERVICES=false
SKIP_ELASTICSEARCH=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --stop|-s)
      STOP_SERVICES=true
      shift
      ;;
    --force|-f)
      FORCE_BUILD=true
      shift
      ;;
    --all)
      SERVICES="api frontend db redis minio elasticsearch"
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [options] [services...]"
      echo ""
      echo "Options:"
      echo "  --stop, -s    Stop existing services before building"
      echo "  --force, -f   Force rebuild (no cache)"
      echo "  --all         Deploy all services (including db, redis, minio, elasticsearch)"
      echo "  --help, -h    Show this help"
      echo ""
      echo "Services (default: api frontend): api frontend db redis minio elasticsearch"
      echo ""
      echo "Examples:"
      echo "  $0                    # Build only api and frontend (fastest)"
      echo "  $0 --all              # Build all services"
      echo "  $0 --stop             # Stop and rebuild"
      echo "  $0 -s -f api          # Force rebuild api only"
      exit 0
      ;;
    *)
      SERVICES="$@"
      break
      ;;
  esac
done

# Vérifier si uv est installé
if ! command -v uv &> /dev/null; then
    echo -e "${YELLOW}Installing uv...${NC}"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

# Stop services if requested
if [ "$STOP_SERVICES" = true ]; then
    echo -e "${YELLOW}Stopping existing services...${NC}"
    docker compose down 2>/dev/null || true
fi

# Build Docker
echo -e "${GREEN}Building Docker images: $SERVICES${NC}"
if [ "$FORCE_BUILD" = true ]; then
    docker compose build --no-cache $SERVICES
else
    docker compose build $SERVICES
fi

# Démarrer les services
echo -e "${GREEN}Starting services: $SERVICES${NC}"
docker compose up -d $SERVICES

# Wait for services with health checks
echo -e "${YELLOW}Waiting for services to be ready...${NC}"

# Wait for API (max 30 seconds)
echo -e "${YELLOW}Waiting for API...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:8000/health >/dev/null 2>&1; then
        echo -e "${GREEN}API is ready!${NC}"
        break
    fi
    sleep 1
done

# Wait for Frontend (max 30 seconds)
echo -e "${YELLOW}Waiting for Frontend...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:3000 >/dev/null 2>&1; then
        echo -e "${GREEN}Frontend is ready!${NC}"
        break
    fi
    sleep 1
done

# Vérifier le statut
echo -e "${GREEN}Services status:${NC}"
docker compose ps

echo -e "${GREEN}=========================================="
echo -e "  VulnScope is ready!"
echo -e "=========================================="
echo -e "Frontend:  ${YELLOW}http://localhost:3000${NC}"
echo -e "API:       ${YELLOW}http://localhost:8000${NC}"
echo -e "=========================================="
