# VulnScope - Security Vulnerability Scanner

VulnScope est une plateforme complète de sécurité applicative pour la détection et la gestion des vulnérabilités dans les applications web et APIs.

## Fonctionnalités

### 🔍 Scanner de Vulnérabilités
- **Détection automatique** : XSS, SQL Injection, SSRF, IDOR, CSRF, XXE, Command Injection, SSTI, Path Traversal
- **Analyse multi-vecteurs** : Crawler, OpenAPI, GraphQL
- **Fuzzing intelligent** : Génération de payloads automatisée

### 📊 Conformité
- PCI-DSS
- NIS2
- SOC 2
- HIPAA
- ISO 27001

### 🔧 Intégrations
- **CI/CD** : GitHub, GitLab, Jenkins, Azure DevOps
- **ITSM** : Jira, ServiceNow
- **SIEM** : Splunk, ELK, QRadar

### 🎨 Interface
- **Dashboard Next.js** en temps réel
- **API REST** complète (FastAPI)
- **GraphQL** pour les requêtes flexibles
- **WebSocket** pour les mises à jour live

## Installation

### Docker Compose (Recommandé)

```bash
# Cloner le projet
git clone https://github.com/vulnscope/vulnscope.git
cd vulnscope

# Démarrer les services
docker compose up -d

# Accéder au dashboard
# http://localhost:8501

# API disponible sur
# http://localhost:8000
```

### Configuration Manuelle

```bash
# Installer les dépendances
pip install -r requirements.txt

# Démarrer l'API
uvicorn src.api.main:app --reload

# Dans un autre terminal, démarrer le frontend Next.js
npm run dev --prefix frontend
```

## Architecture

```
VulnScope/
├── src/
│   ├── api/           # API REST & GraphQL
│   ├── scanner/       # Moteurs de détection
│   ├── discovery/     # Crawler & importeurs
│   ├── fuzzer/        # Module de fuzzing
│   ├── evidence/      # Gestion des preuves
│   ├── integrations/  # CI/CD, ITSM, SIEM
│   ├── core/          # Modèles de données
│   └── utils/         # Utilitaires
├── dashboard/         # Application Streamlit
├── tests/             # Tests unitaires et E2E
└── docs/             # Documentation
```

## API Endpoints

### Targets
- `GET /api/v1/targets` - Liste des cibles
- `POST /api/v1/targets` - Créer une cible
- `GET /api/v1/targets/{id}` - Détails d'une cible

### Scans
- `GET /api/v1/scans` - Liste des scans
- `POST /api/v1/scans` - Lancer un scan
- `GET /api/v1/scans/{id}` - Détails d'un scan

### Findings
- `GET /api/v1/findings` - Liste des vulnérabilités
- `PATCH /api/v1/findings/{id}` - Mettre à jour un finding

## Configuration

### Variables d'environnement

```env
DATABASE_URL=postgresql://user:pass@localhost:5432/vulnscope
REDIS_URL=redis://localhost:6379
API_SECRET=your-secret-key
```

### Configuration MinIO (S3)

```python
from src.evidence.s3_storage import S3EvidenceStorage, S3Config

config = S3Config(
    bucket="vulnscope-evidence",
    endpoint_url="http://localhost:9000",
    access_key="minioadmin",
    secret_key="minioadmin"
)
storage = S3EvidenceStorage(config)
```

## Développement

### Lancer les tests

```bash
# Tous les tests
pytest tests/

# Tests unitaires seulement
pytest tests/unit/

# Tests d'intégration
pytest tests/integration/

# Tests E2E
pytest tests/e2e/
```

### Commandes Makefile

```bash
make install    # Installer les dépendances
make build     # Construire les images Docker
make up        # Démarrer les services
make down      # Arrêter les services
make logs      # Voir les logs
make test      # Lancer les tests
make clean     # Nettoyer
```

## Contribution

1. Fork le projet
2. Créer une branche (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add AmazingFeature'`)
4. Push sur la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## Licence

MIT License - voir LICENSE pour plus de détails.
