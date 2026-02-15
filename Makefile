.PHONY: help build up down logs test clean install

help:
	@echo "VulnScope Deployment Commands"
	@echo "=============================="
	@echo "make install    - Install dependencies"
	@echo "make build     - Build Docker images"
	@echo "make up        - Start all services"
	@echo "make down      - Stop all services"
	@echo "make logs      - View logs"
	@echo "make test      - Run tests"
	@echo "make clean     - Clean up"

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
