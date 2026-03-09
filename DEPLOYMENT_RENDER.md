# Déploiement VulnScope sur Render

Ce guide détaille le déploiement de VulnScope sur [Render](https://render.com), une plateforme cloud moderne supportant Docker.

## 📋 Prérequis

- Compte GitHub ou GitLab avec le code VulnScope
- Compte Render (gratuit) : https://dashboard.render.com/register
- Carte bancaire (pour vérification, même en mode gratuit)

---

## 🏗️ Architecture sur Render

```
┌─────────────────────────────────────────────────────────────┐
│                        Render Cloud                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────┐     ┌──────────────────┐              │
│  │  vulnscope-api   │────▶│  vulnscope-db    │              │
│  │  (FastAPI)       │     │  (PostgreSQL)    │              │
│  │  Port: 8000      │     │  Port: 5432      │              │
│  └────────┬─────────┘     └──────────────────┘              │
│           │                                                  │
│           │           ┌──────────────────┐                   │
│           └──────────▶│ vulnscope-redis  │                   │
│                       │  (Redis Cache)   │                   │
│                       │  Port: 6379      │                   │
│                       └──────────────────┘                   │
│                                                              │
│  ┌──────────────────┐                                       │
│  │ vulnscope-frontend│                                      │
│  │  (Next.js)       │                                       │
│  │  Port: 3000      │                                       │
│  └──────────────────┘                                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Méthode 1: Déploiement via Blueprint (Recommandé)

Le fichier `render.yaml` à la racine du projet configure automatiquement tous les services.

### Étape 1: Pousser le code sur GitHub/GitLab

```bash
# Si ce n'est pas déjà fait
git add render.yaml
git commit -m "Add Render blueprint configuration"
git push origin main
```

### Étape 2: Créer un Blueprint sur Render

1. Connectez-vous à [Render Dashboard](https://dashboard.render.com)
2. Cliquez sur **"New"** → **" Blueprint"**
3. Connectez votre repository GitHub/GitLab
4. Sélectionnez le repository `vulnscope`
5. Render détecte automatiquement le fichier `render.yaml`
6. Cliquez sur **"Apply"**

### Étape 3: Attendre le déploiement

Render va créer automatiquement:
- ✅ Base de données PostgreSQL (`vulnscope-db`)
- ✅ Cache Redis (`vulnscope-redis`)
- ✅ API Backend (`vulnscope-api`)
- ✅ Frontend (`vulnscope-frontend`)

Le déploiement initial prend **5-10 minutes**.

---

## 🔧 Méthode 2: Déploiement Manuel

Si vous préférez créer chaque service manuellement:

### 1. Créer la base de données PostgreSQL

1. Dashboard → **New** → **PostgreSQL**
2. Configuration:
   - **Name**: `vulnscope-db`
   - **Database**: `vulnscope`
   - **User**: `vulnscope`
   - **Region**: Oregon (us-west) ou Frankfurt (eu-west)
   - **Plan**: Free (90 jours gratuits)
3. Cliquez sur **Create Database**
4. Notez l'URL de connexion (Internal Database URL)

### 2. Créer le cache Redis

1. Dashboard → **New** → **Redis**
2. Configuration:
   - **Name**: `vulnscope-redis`
   - **Region**: Même région que la DB
   - **Plan**: Free (25MB, 30 connexions)
   - **Maxmemory Policy**: `allkeys-lru`
3. Cliquez on **Create Redis**
4. Notez l'URL de connexion (Internal Redis URL)

### 3. Créer l'API Backend

1. Dashboard → **New** → **Web Service**
2. Configuration:
   - **Name**: `vulnscope-api`
   - **Runtime**: Docker
   - **Region**: Même région que la DB
   - **Branch**: `main`
   - **Dockerfile Path**: `./Dockerfile`
   - **Plan**: Free (ou Starter pour production)
   - **Health Check Path**: `/health`
3. Variables d'environnement:

```env
VULNSCOPE_ENVIRONMENT=production
VULNSCOPE_DEBUG=false
VULNSCOPE_SECRET_KEY=<générer avec: openssl rand -hex 32>
VULNSCOPE_API_KEY=<générer avec: openssl rand -base64 32>
VULNSCOPE_DATABASE__URL=<Internal Database URL de PostgreSQL>
VULNSCOPE_REDIS__HOST=<host Redis depuis Internal URL>
VULNSCOPE_REDIS__PORT=6379
VULNSCOPE_REDIS__PASSWORD=<password Redis>
VULNSCOPE_LOG_LEVEL=INFO
PORT=8000
```

4. Cliquez sur **Create Web Service**

### 4. Créer le Frontend

1. Dashboard → **New** → **Web Service**
2. Configuration:
   - **Name**: `vulnscope-frontend`
   - **Runtime**: Docker
   - **Region**: Même région
   - **Branch**: `main`
   - **Dockerfile Path**: `./frontend/Dockerfile`
   - **Docker Context**: `./frontend`
   - **Plan**: Free
3. Variables d'environnement:

```env
NEXT_PUBLIC_API_URL=https://vulnscope-api.onrender.com/api/v1
NEXT_TELEMETRY_DISABLED=1
NODE_ENV=production
PORT=3000
```

4. Cliquez sur **Create Web Service**

---

## 🔗 Configuration des URLs

Après déploiement, vos services seront accessibles aux URLs:

| Service | URL |
|---------|-----|
| **Frontend** | `https://vulnscope-frontend.onrender.com` |
| **API** | `https://vulnscope-api.onrender.com` |
| **API Docs** | `https://vulnscope-api.onrender.com/docs` |
| **API Health** | `https://vulnscope-api.onrender.com/health` |

### Personnaliser le domaine

Pour utiliser un domaine personnalisé:

1. Allez sur le service → **Settings** → **Custom Domain**
2. Ajoutez votre domaine (ex: `vulnscope.votredomaine.com`)
3. Configurez les DNS comme indiqué par Render
4. Mettez à jour `NEXT_PUBLIC_API_URL` dans le frontend

---

## ⚙️ Configuration Avancée

### Variables d'environnement complètes

Pour l'API (`vulnscope-api`):

```env
# Application
VULNSCOPE_APP_NAME=VulnScope
VULNSCOPE_ENVIRONMENT=production
VULNSCOPE_DEBUG=false

# Sécurité
VULNSCOPE_SECRET_KEY=<généré>
VULNSCOPE_API_KEY=<généré>

# Base de données
VULNSCOPE_DATABASE__URL=postgresql://vulnscope:password@hostname:5432/vulnscope

# Redis
VULNSCOPE_REDIS__HOST=hostname
VULNSCOPE_REDIS__PORT=6379
VULNSCOPE_REDIS__PASSWORD=password

# Scanner
VULNSCOPE_SCANNER__MODE=active
VULNSCOPE_SCANNER__MAX_CONCURRENT_REQUESTS=50
VULNSCOPE_SCANNER__VERIFY_SSL=true

# Logs
VULNSCOPE_LOG_LEVEL=INFO

# Port
PORT=8000
```

### Mise à l'échelle (Production)

Pour un environnement de production:

1. **Upgrader les plans**:
   - PostgreSQL: Starter ($7/mois) ou Standard ($20/mois)
   - Redis: Starter ($10/mois)
   - API: Starter ($7/mois) ou Standard ($25/mois)
   - Frontend: Starter ($7/mois)

2. **Activer l'autoscaling**:
   - Settings → Instance Type → Standard+
   - Activer "Autoscaling"
   - Min: 1, Max: 3 instances

---

## 🔄 Déploiement Continu

Render déploie automatiquement à chaque push sur la branche configurée.

### Désactiver le déploiement automatique

1. Service → Settings → "Build & Deploy"
2. Décocher "Auto-Deploy"

### Déclencher un déploiement manuel

1. Service → "Manual Deploy"
2. Sélectionner la branche
3. "Deploy"

---

## 📊 Monitoring et Logs

### Voir les logs

1. Sélectionnez un service
2. Cliquez sur l'onglet **"Logs"**
3. Les logs sont en temps réel

### Métriques

1. Sélectionnez un service
2. Cliquez sur l'onglet **"Metrics"**
3. Visualisez CPU, mémoire, réseau

### Alertes

1. Service → Settings → "Notifications"
2. Configurez les alertes Slack/Email

---

## 🔧 Résolution de problèmes

### L'API ne démarre pas

```bash
# Vérifier les logs
# Causes courantes:
# - Variable d'environnement manquante
# - Base de données non accessible
# - Port incorrect
```

### Base de données inaccessible

1. Vérifiez que la DB est dans la même région
2. Utilisez l'URL interne (Internal Database URL)
3. Vérifiez que le service a accès à la DB

### Erreur de build Docker

1. Vérifiez le Dockerfile
2. Assurez-vous que le contexte Docker est correct
3. Vérifiez les dépendances dans requirements.txt / package.json

### Mémoire insuffisante (Free tier)

Le plan gratuit a 512MB RAM. Solutions:
1. Réduire les workers uvicorn: `CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]`
2. Upgrader vers le plan Starter

---

## 💰 Coûts Estimatifs

### Plan Gratuit (Développement/Test)

| Service | Plan | Coût |
|---------|------|------|
| API | Free | 0€ |
| Frontend | Free | 0€ |
| PostgreSQL | Free | 0€ (90 jours) |
| Redis | Free | 0€ |
| **Total** | | **0€/mois** |

⚠️ **Note**: PostgreSQL gratuit expire après 90 jours.

### Plan Production (Recommandé)

| Service | Plan | Coût |
|---------|------|------|
| API | Starter | $7/mois |
| Frontend | Starter | $7/mois |
| PostgreSQL | Starter | $7/mois |
| Redis | Starter | $10/mois |
| **Total** | | **~$31/mois** |

---

## ✅ Checklist de déploiement

- [ ] Code poussé sur GitHub/GitLab
- [ ] Compte Render créé
- [ ] Blueprint appliqué OU services créés manuellement
- [ ] Base de données PostgreSQL opérationnelle
- [ ] Redis opérationnel
- [ ] API accessible sur `/health`
- [ ] Frontend accessible
- [ ] Variables d'environnement configurées
- [ ] Domaine personnalisé configuré (optionnel)
- [ ] Monitoring activé

---

## 📚 Ressources

- [Documentation Render](https://render.com/docs)
- [Render Blueprint Spec](https://render.com/docs/blueprint-spec)
- [Docker sur Render](https://render.com/docs/docker)
- [Variables d'environnement](https://render.com/docs/environment-variables)

---

## 🆘 Support

En cas de problème:
1. Consultez les logs du service
2. Vérifiez la documentation Render
3. Ouvrez une issue sur le repository GitHub