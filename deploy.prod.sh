#!/bin/bash

set -e

echo "=========================================="
echo "  VulnScope Production Deployment"
echo "=========================================="

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Domain from nginx.conf
DOMAIN="vulnscope.example.com"

# Parse arguments
FORCE_BUILD=false
STOP_SERVICES=false
SKIP_SSL=false

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
    --skip-ssl)
      SKIP_SSL=true
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [options]"
      echo ""
      echo "Options:"
      echo "  --stop, -s       Stop existing services before deploying"
      echo "  --force, -f     Force rebuild (no cache)"
      echo "  --skip-ssl      Skip SSL certificate generation"
      echo "  --help, -h      Show this help"
      echo ""
      echo "Examples:"
      echo "  $0                    # Deploy all services"
      echo "  $0 --stop             # Stop and redeploy"
      echo "  $0 -s -f              # Force rebuild all services"
      echo "  $0 --skip-ssl         # Deploy without SSL"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Check if .env exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚠️  .env not found. Generating...${NC}"
    if [ -f "generate_env.sh" ]; then
        chmod +x generate_env.sh
        ./generate_env.sh
    else
        echo -e "${RED}❌ generate_env.sh not found. Please create .env manually.${NC}"
        exit 1
    fi
fi

# Check for SSL certificates
if [ "$SKIP_SSL" = false ] && [ ! -d "ssl/live/$DOMAIN" ]; then
    echo -e "${YELLOW}⚠️  SSL certificates not found for $DOMAIN.${NC}"
    read -p "Generate SSL certificates now? (y/n): " generate_ssl
    if [ "$generate_ssl" = "y" ]; then
        if [ -f "generate_ssl.sh" ]; then
            chmod +x generate_ssl.sh
            ./generate_ssl.sh
        else
            echo -e "${RED}❌ generate_ssl.sh not found.${NC}"
            exit 1
        fi
    fi
fi

# Stop services if requested
if [ "$STOP_SERVICES" = true ]; then
    echo -e "${YELLOW}Stopping existing services...${NC}"
    docker compose -f docker-compose.prod.yml down
fi

# Build and start services
echo -e "${GREEN}Building and starting services...${NC}"
if [ "$FORCE_BUILD" = true ]; then
    docker compose -f docker-compose.prod.yml up -d --build --no-cache
else
    docker compose -f docker-compose.prod.yml up -d --build
fi

# Wait for services to be ready
echo -e "${YELLOW}Waiting for services to be ready...${NC}"
sleep 10

# Check health
echo -e "${GREEN}Services status:${NC}"
docker compose -f docker-compose.prod.yml ps

echo -e "${GREEN}=========================================="
echo -e "  VulnScope is ready!"
echo -e "=========================================="
echo -e "Dashboard: ${YELLOW}http://${DOMAIN}${NC}"
echo -e "API:       ${YELLOW}http://${DOMAIN}/api${NC}"
echo -e "Adminer:   ${YELLOW}http://${DOMAIN}:8080${NC}"
echo -e "MinIO:     ${YELLOW}http://${DOMAIN}:9001${NC}"
echo -e "=========================================="
