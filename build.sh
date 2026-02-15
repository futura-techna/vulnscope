#!/bin/bash

set -e

echo "=========================================="
echo "  VulnScope Build Script"
echo "=========================================="

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Default services
SERVICES="${@:-api dashboard db redis minio elasticsearch}"

# Parse arguments
FORCE_BUILD=false
STOP_SERVICES=false

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
    --help|-h)
      echo "Usage: $0 [options] [services...]"
      echo ""
      echo "Options:"
      echo "  --stop, -s    Stop existing services before building"
      echo "  --force, -f   Force rebuild (no cache)"
      echo "  --help, -h    Show this help"
      echo ""
      echo "Services (default: all): api dashboard db redis minio elasticsearch"
      echo ""
      echo "Examples:"
      echo "  $0                    # Build all services"
      echo "  $0 api dashboard       # Build only api and dashboard"
      echo "  $0 --stop             # Stop and rebuild all"
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
    docker compose down
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

# Attendre que les services soient prêts
echo -e "${YELLOW}Waiting for services to be ready...${NC}"
sleep 10

# Vérifier le statut
echo -e "${GREEN}Services status:${NC}"
docker compose ps

echo -e "${GREEN}=========================================="
echo -e "  VulnScope is ready!"
echo -e "=========================================="
echo -e "Dashboard: ${YELLOW}http://localhost:8501${NC}"
echo -e "API:       ${YELLOW}http://localhost:8000${NC}"
echo -e "MinIO:     ${YELLOW}http://localhost:9001${NC}"
echo -e "=========================================="
