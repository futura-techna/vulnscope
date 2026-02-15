#!/bin/bash

set -e

echo "=========================================="
echo " 🚀 VulnScope Production Deployment"
echo "=========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
if [ ! -d "ssl/live" ]; then
    echo -e "${YELLOW}⚠️  SSL certificates not found.${NC}"
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

# Stop existing containers
echo -e "${YELLOW}🛑 Stopping existing containers...${NC}"
docker compose -f docker-compose.prod.yml down 2>/dev/null || true

# Build and start services
echo -e "${YELLOW}🔨 Building and starting services...${NC}"
docker compose -f docker-compose.prod.yml up -d --build

# Wait for services to be healthy
echo -e "${YELLOW}⏳ Waiting for services to be healthy...${NC}"
sleep 10

# Check health
echo -e "${YELLOW}🏥 Checking services health...${NC}"

# API Health
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ API: healthy${NC}"
else
    echo -e "${RED}❌ API: unhealthy${NC}"
fi

# Dashboard
if curl -s http://localhost:8501 > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Dashboard: up${NC}"
else
    echo -e "${RED}❌ Dashboard: down${NC}"
fi

# Nginx
if curl -s http://localhost:80 > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Nginx: up${NC}"
else
    echo -e "${RED}❌ Nginx: down${NC}"
fi

echo ""
echo -e "${GREEN}=========================================="
echo " ✅ Deployment Complete!"
echo "==========================================${NC}"
echo ""
echo "🌐 Access Points:"
echo "   - API: http://localhost:8000"
echo "   - API Docs: http://localhost:8000/docs"
echo "   - Dashboard: http://localhost:8501"
echo "   - Adminer: http://localhost:8080"
echo ""
