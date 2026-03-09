.PHONY: help build up down logs test clean install local-install local-up local-down tunnel-setup tunnel-start tunnel-stop tunnel-status

help:
	@echo "VulnScope Deployment Commands"
	@echo "=============================="
	@echo ""
	@echo "Development:"
	@echo "  make install      - Install Python dependencies"
	@echo "  make build        - Build Docker images"
	@echo "  make up           - Start all services (dev)"
	@echo "  make down         - Stop all services"
	@echo "  make logs         - View logs"
	@echo "  make test         - Run tests"
	@echo "  make clean        - Clean up"
	@echo ""
	@echo "Production (GCP/Free Tier):"
	@echo "  make deploy       - Deploy to production"
	@echo "  make scale-api    - Scale API instances"
	@echo "  make health       - Health check"
	@echo ""
	@echo "Local Cloud (Coolify + Cloudflare):"
	@echo "  make local-install   - Install Docker + Coolify + cloudflared"
	@echo "  make local-up        - Start local VulnScope stack"
	@echo "  make local-down      - Stop local VulnScope stack"
	@echo "  make local-logs      - View local stack logs"
	@echo ""
	@echo "Cloudflare Tunnel:"
	@echo "  make tunnel-setup    - Configure Cloudflare tunnel"
	@echo "  make tunnel-start    - Start tunnel"
	@echo "  make tunnel-stop     - Stop tunnel"
	@echo "  make tunnel-status   - Check tunnel status"
	@echo "  make tunnel-logs     - View tunnel logs"

install:
	pip install -r requirements.txt

build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

logs:
	docker-compose logs -f

test:
	python3 -m pytest tests/ -v

clean:
	docker-compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# Deploy to production
deploy:
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Scale services
scale-api:
	docker-compose up -d --scale api=3

# Health check
health:
	@echo "Checking services..."
	@curl -s http://localhost:8000/health || echo "API not ready"
	@curl -s http://localhost:8501 || echo "Dashboard not ready"

# ==============================================
# Local Cloud (Coolify + Cloudflare Tunnel)
# ==============================================

# Install local cloud infrastructure (Docker + Coolify + cloudflared)
local-install:
	@echo "Installing local cloud infrastructure..."
	@chmod +x setup-local-cloud.sh
	@./setup-local-cloud.sh

# Install with domain (for Cloudflare tunnel setup)
local-install-domain:
	@echo "Installing with domain configuration..."
	@chmod +x setup-local-cloud.sh
	@if [ -z "$(DOMAIN)" ]; then \
		echo "Usage: make local-install-domain DOMAIN=yourdomain.com"; \
		exit 1; \
	fi
	@./setup-local-cloud.sh --domain $(DOMAIN)

# Start local VulnScope stack
local-up:
	@echo "Starting local VulnScope stack..."
	@if [ ! -f .env ]; then \
		echo "Generating .env file..."; \
		echo "POSTGRES_PASSWORD=$$(openssl rand -hex 16)" > .env; \
		echo "REDIS_PASSWORD=$$(openssl rand -hex 16)" >> .env; \
		echo "VULNSCOPE_SECRET_KEY=$$(openssl rand -hex 32)" >> .env; \
		echo "VULNSCOPE_API_KEY=$$(openssl rand -base64 32)" >> .env; \
	fi
	docker-compose -f docker-compose.local.yml up -d

# Stop local VulnScope stack
local-down:
	@echo "Stopping local VulnScope stack..."
	docker-compose -f docker-compose.local.yml down

# View local stack logs
local-logs:
	docker-compose -f docker-compose.local.yml logs -f

# Rebuild local stack
local-rebuild:
	@echo "Rebuilding local stack..."
	docker-compose -f docker-compose.local.yml build --no-cache
	docker-compose -f docker-compose.local.yml up -d

# ==============================================
# Cloudflare Tunnel Management
# ==============================================

# Setup Cloudflare tunnel (requires DOMAIN)
tunnel-setup:
	@chmod +x tunnel-manager.sh
	@if [ -z "$(DOMAIN)" ]; then \
		./tunnel-manager.sh setup; \
	else \
		./tunnel-manager.sh setup $(DOMAIN); \
	fi

# Start tunnel
tunnel-start:
	@chmod +x tunnel-manager.sh
	@./tunnel-manager.sh start

# Stop tunnel
tunnel-stop:
	@chmod +x tunnel-manager.sh
	@./tunnel-manager.sh stop

# Check tunnel status
tunnel-status:
	@chmod +x tunnel-manager.sh
	@./tunnel-manager.sh status

# View tunnel logs
tunnel-logs:
	@chmod +x tunnel-manager.sh
	@./tunnel-manager.sh logs

# Follow tunnel logs in real-time
tunnel-logs-follow:
	@chmod +x tunnel-manager.sh
	@./tunnel-manager.sh logs-follow

# Test tunnel connectivity
tunnel-test:
	@chmod +x tunnel-manager.sh
	@./tunnel-manager.sh test

# Add route to tunnel
tunnel-add-route:
	@chmod +x tunnel-manager.sh
	@if [ -z "$(HOST)" ] || [ -z "$(PORT)" ]; then \
		echo "Usage: make tunnel-add-route HOST=app.domain.com PORT=8080"; \
		exit 1; \
	fi
	@./tunnel-manager.sh add-route $(HOST) $(PORT)

# List all tunnels
tunnel-list:
	@chmod +x tunnel-manager.sh
	@./tunnel-manager.sh list

# ==============================================
# Coolify Management
# ==============================================

# Open Coolify dashboard
coolify-open:
	@echo "Opening Coolify dashboard..."
	@xdg-open http://localhost:8000 2>/dev/null || open http://localhost:8000 2>/dev/null || echo "Open http://localhost:8000 in your browser"

# Check Coolify status
coolify-status:
	@echo "Checking Coolify status..."
	@docker ps --filter "name=coolify" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Restart Coolify
coolify-restart:
	@echo "Restarting Coolify..."
	@docker restart coolify 2>/dev/null || echo "Coolify container not found"

# View Coolify logs
coolify-logs:
	@docker logs coolify -f

# ==============================================
# Quick Start (All-in-one)
# ==============================================

# Full setup: install + start everything
quickstart: local-install local-up tunnel-start
	@echo ""
	@echo "=========================================="
	@echo "  VulnScope Local Cloud is ready!"
	@echo "=========================================="
	@echo ""
	@echo "Access your services:"
	@echo "  Coolify:   http://localhost:8000"
	@echo "  VulnScope: http://localhost:3000"
	@echo "  API:       http://localhost:8001"
	@echo ""
