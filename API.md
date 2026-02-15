# VulnScope API Documentation

## Endpoints Overview

### Targets

#### GET /api/v1/targets
Liste toutes les cibles.

**Réponse:**
```json
{
  "targets": [
    {
      "id": "uuid",
      "name": "Production App",
      "url": "https://app.example.com",
      "description": "Main application",
      "tags": ["production", "api"],
      "created_at": "2024-01-15T10:00:00Z"
    }
  ]
}
```

#### POST /api/v1/targets
Créer une nouvelle cible.

**Corps de la requête:**
```json
{
  "name": "New App",
  "url": "https://new.example.com",
  "description": "Test application",
  "tags": ["test"],
  "auth_type": "bearer",
  "auth_config": {
    "token": "your-token"
  }
}
```

### Scans

#### GET /api/v1/scans
Liste tous les scans.

#### POST /api/v1/scans
Lancer un nouveau scan.

**Corps de la requête:**
```json
{
  "target_id": "uuid",
  "name": "Full Scan",
  "scan_type": "full",
  "enable_crawler": true,
  "enable_dast": true,
  "enable_fuzzer": true
}
```

### Findings

#### GET /api/v1/findings
Liste les vulnérabilités avec filtres.

**Paramètres:**
- `severity` : CRITICAL, HIGH, MEDIUM, LOW
- `status` : PENDING, VERIFIED, REMEDIATED
- `target_id` : Filtrer par cible

#### PATCH /api/v1/findings/{id}
Mettre à jour un finding.

**Corps de la requête:**
```json
{
  "status": "VERIFIED",
  "false_positive": false,
  "notes": "Confirmed vulnerability"
}
```

### Compliance

#### GET /api/v1/compliance/{standard}
Vérifier la conformité.

**Standards disponibles:**
- PCI-DSS
- NIS2
- SOC2
- HIPAA
- ISO27001

### WebSocket

#### ws://localhost:8000/ws/scans/{scan_id}
Recevoir les mises à jour en temps réel du scan.

## Exemples cURL

```bash
# Créer une cible
curl -X POST http://localhost:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "url": "http://test.com"}'

# Lancer un scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_id": "uuid", "scan_type": "full"}'

# Obtenir les findings
curl http://localhost:8000/api/v1/findings?severity=CRITICAL
```
