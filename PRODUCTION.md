# VulnScope Production Deployment Guide

## Overview

VulnScope is a comprehensive security vulnerability scanning platform. This guide covers production deployment, including security hardening, configuration, and monitoring.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      VulnScope Stack                        │
├─────────────────────────────────────────────────────────────┤
│  Nginx (Reverse Proxy)  │  Port 80/443                     │
├─────────────────────────┴───────────────────────────────────┤
│  API (FastAPI)           │  Port 8000                       │
│  Dashboard (Streamlit)   │  Port 8501                       │
├─────────────────────────┼───────────────────────────────────┤
│  Adminer (DB Manager)    │  Port 8080                       │
├─────────────────────────┴───────────────────────────────────┤
│  PostgreSQL 15          │  Port 5432                        │
│  Redis 7               │  Port 6379                        │
│  MinIO                  │  Port 9000/9001                   │
│  Elasticsearch          │  Port 9200                        │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Docker 20.10+
- Docker Compose v2
- 4GB RAM minimum
- 20GB disk space

## Quick Start

```bash
# Clone and navigate to project
cd /home/cisse/vulnscope

# Start all services
docker compose up -d

# Verify services
curl http://localhost:8000/health
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| API | 8000 | VulnScope REST API |
| Swagger UI | 8000/docs | API Documentation |
| Dashboard | 8501 | Streamlit Web UI |
| Adminer | 8080 | Database Management |
| PostgreSQL | 5432 | Primary Database |
| Redis | 6379 | Cache & Sessions |
| MinIO | 9000 | S3-compatible Storage |
| MinIO Console | 9001 | Storage Management |
| Elasticsearch | 9200 | SIEM Integration |

## Security Configuration

### 1. Generate Secure Keys

```bash
# Generate JWT secret key (32 bytes minimum)
python3 -c "import secrets; print('VULNSCOPE_SECRET_KEY=' + secrets.token_hex(32))"

# Generate API key
python3 -c "import secrets; print('VULNSCOPE_API_KEY=' + secrets.token_urlsafe(32))"

# Generate secure passwords
python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(16))"
python3 -c "import secrets; print('REDIS_PASSWORD=' + secrets.token_hex(16))"
```

### 2. Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
# Edit .env with your secure values
```

| Variable | Description | Required |
|----------|-------------|----------|
| `VULNSCOPE_SECRET_KEY` | JWT signing key | Yes |
| `VULNSCOPE_API_KEY` | API authentication key | Yes |
| `VULNSCOPE_DATABASE__URL` | PostgreSQL connection string | Yes |
| `VULNSCOPE_REDIS__PASSWORD` | Redis password | Yes |
| `POSTGRES_PASSWORD` | PostgreSQL password | Yes |
| `MINIO_ROOT_USER` | MinIO access key | No |
| `MINIO_ROOT_PASSWORD` | MinIO secret key | No |

### 3. SSL/TLS Configuration

For production HTTPS:

1. Place certificates in `ssl/` directory:
   - `ssl/cert.pem` - SSL certificate
   - `ssl/key.pem` - Private key

2. Update `nginx.conf` with your domain

## Database Management (Adminer)

Access Adminer at http://localhost:8080

### Connection Details

| Field | Value |
|-------|-------|
| System | PostgreSQL |
| Server | db |
| Port | 5432 |
| Username | vulnscope |
| Password | (from .env) |
| Database | vulnscope |

### Alternative: Connect via CLI

```bash
# Connect to PostgreSQL
docker exec -it vulnscope-db-1 psql -U vulnscope -d vulnscope

# Run SQL queries
SELECT * FROM scans LIMIT 10;
```

## Deployment Commands

### Start Services

```bash
# Development
docker compose up -d

# Production
docker compose -f docker-compose.prod.yml up -d
```

### Check Status

```bash
# All services
docker compose ps

# Specific service
docker compose ps api
docker compose ps db
```

### View Logs

```bash
# API logs
docker compose logs -f api

# All logs
docker compose logs -f
```

### Stop Services

```bash
docker compose down
```

## Health Checks

```bash
# API health
curl http://localhost:8000/health
# {"status":"healthy","service":"vulnscope-api","version":"1.0.0"}

# Nginx
curl http://localhost:80

# Dashboard
curl http://localhost:8501
```

## Backup & Restore

### Database Backup

```bash
# Backup PostgreSQL
docker exec vulnscope-db-1 pg_dump -U vulnscope vulnscope > backup_$(date +%Y%m%d).sql

# Restore
docker exec -i vulnscope-db-1 psql -U vulnscope vulnscope < backup_20240101.sql
```

### Evidence Backup

```bash
docker exec vulnscope-api-1 tar -czf evidence_backup.tar.gz /var/vulnscope/evidence
```

## Monitoring

### Check Service Health

```bash
# PostgreSQL
docker exec vulnscope-db-1 pg_isready -U vulnscope

# Redis
docker exec vulnscope-redis-1 redis-cli ping
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   ```bash
   # Check PostgreSQL logs
   docker compose logs db
   
   # Verify connection
   docker exec vulnscope-db-1 psql -U vulnscope -d vulnscope -c "SELECT 1;"
   ```

2. **Redis Connection Failed**
   ```bash
   # Check Redis logs
   docker compose logs redis
   
   # Verify connection
   docker exec vulnscope-redis-1 redis-cli -a your_password ping
   ```

3. **API Returns 401**
   - Verify `VULNSCOPE_API_KEY` is set in .env
   - Check JWT secret key configuration

4. **Adminer Cannot Connect to Database**
   - Use container IP: `docker inspect vulnscope-db-1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'`
   - Or use `host.docker.internal` on some systems

## Maintenance

### Update Application

```bash
# Pull latest images
docker compose pull

# Restart services
docker compose up -d
```

### Run Tests

```bash
python3 -m pytest -v
```

## CI/CD Integration

### GitHub Actions

See `.github/workflows/vulnscope.yml`

### GitLab CI

See `.gitlab-ci.yml`

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/scan` | POST | Start scan |
| `/api/v1/scans` | GET | List scans |
| `/api/v1/targets` | GET | List targets |
| `/docs` | GET | Swagger UI |

## Default Credentials (Development Only)

⚠️ **Change in production!**

| Service | Username | Password |
|---------|----------|----------|
| PostgreSQL | vulnscope | (from .env) |
| MinIO | minioadmin | minioadmin |
| Redis | (none) | (from .env) |
