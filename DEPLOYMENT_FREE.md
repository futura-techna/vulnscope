# Guide de Déploiement Gratuit - VulnScope

## 📋 Vue d'ensemble

VulnScope peut être déployé gratuitement avec plusieurs solutions open source. Ce guide présente les meilleures options classées par facilité d'utilisation et fonctionnalités.

---

## 🏆 Top 5 des Solutions de Déploiement Gratuit

| Solution | Difficulté | Ressources | DNS inclus | SSL gratuit |
|----------|------------|------------|------------|-------------|
| **Coolify** | ⭐ Facile | VPS requis | ✅ | ✅ Auto |
| **CapRover** | ⭐ Facile | VPS requis | ✅ | ✅ Auto |
| **Portainer + Cloudflare Tunnel** | ⭐⭐ Moyen | VPS/Local | ✅ | ✅ Auto |
| **k3s (K8s léger)** | ⭐⭐⭐ Avancé | VPS requis | ❌ | ✅ Cert-Manager |
| **Docker Compose + Tailscale** | ⭐ Facile | Local/VPS | ✅ | ✅ |

---

## 🚀 Option 1: Coolify (RECOMMANDÉ)

**Coolify** est une plateforme open source (alternative à Heroku/Vercel) qui automatise le déploiement.

### Avantages
- ✅ 100% gratuit et open source
- ✅ Interface web intuitive
- ✅ SSL automatique avec Let's Encrypt
- ✅ Déploiement Git intégré
- ✅ Gestion des bases de données intégrée
- ✅ Reverse proxy automatique

### Prérequis
- Un VPS gratuit ou peu coûteux (voir section VPS gratuits)

### Installation de Coolify

```bash
# Sur votre VPS (Ubuntu/Debian)
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash
```

### Déploiement de VulnScope sur Coolify

1. **Accédez à l'interface Coolify** (https://votre-ip:3000)

2. **Créez un nouveau projet** → "VulnScope"

3. **Ajoutez les ressources** :

#### Base de données PostgreSQL
```yaml
Type: PostgreSQL
Name: vulnscope-db
User: vulnscope
Password: <généré automatiquement>
```

#### Redis
```yaml
Type: Redis
Name: vulnscope-redis
Password: <généré automatiquement>
```

#### Application API
```yaml
Type: Application (Git)
Repository: https://github.com/votre-repo/vulnscope.git
Build Pack: Dockerfile
Domain: api.vulnscope.votre-domaine.com
Environment:
  VULNSCOPE_DATABASE__URL: postgresql://vulnscope:password@vulnscope-db:5432/vulnscope
  REDIS_URL: redis://:password@vulnscope-redis:6379
  VULNSCOPE_SECRET_KEY: <générer avec openssl rand -hex 32>
  VULNSCOPE_API_KEY: <générer avec openssl rand -base64 32>
```

#### Application Frontend
```yaml
Type: Application (Git)
Repository: https://github.com/votre-repo/vulnscope.git
Build Pack: Nixpacks (Node.js)
Build Path: frontend
Domain: vulnscope.votre-domaine.com
Environment:
  NEXT_PUBLIC_API_URL: https://api.vulnscope.votre-domaine.com/api/v1
```

---

## 🐳 Option 2: CapRover

**CapRover** est un PaaS open source simple et puissant.

### Installation

```bash
# Sur votre VPS
docker run -p 80:80 -p 443:443 -p 3000:3000 -v /var/run/docker.sock:/var/run/docker.sock -v /captain:/captain caprover/caprover
```

### Configuration

1. Accédez à `http://votre-ip:3000`
2. Créez une application "vulnscope"
3. Connectez votre repo Git

### captain-definition (à ajouter à la racine)

```json
{
  "schemaVersion": 2,
  "dockerfileLines": [
    "FROM python:3.11-slim",
    "WORKDIR /app",
    "COPY requirements.txt .",
    "RUN pip install --no-cache-dir -r requirements.txt",
    "COPY . .",
    "EXPOSE 8000",
    "CMD [\"uvicorn\", \"src.api.main:app\", \"--host\", \"0.0.0.0\", \"--port\", \"8000\"]"
  ]
}
```

---

## 🌐 Option 3: Cloudflare Tunnel + Docker Compose

**Solution idéale pour déployer depuis votre machine locale ou un VPS sans ouvrir de ports.**

### Architecture
```
Internet → Cloudflare Tunnel → VulnScope (Docker)
```

### Prérequis
- Un domaine (gratuit avec Freenom ou DuckDNS)
- Compte Cloudflare gratuit

### Étapes

#### 1. Installer cloudflared

```bash
# Linux
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
chmod +x cloudflared
sudo mv cloudflared /usr/local/bin/

# macOS
brew install cloudflare/cloudflare/cloudflared
```

#### 2. Configurer le tunnel

```bash
# Authentification
cloudflared tunnel login

# Créer le tunnel
cloudflared tunnel create vulnscope

# Configurer le routage DNS
cloudflared tunnel route dns vulnscope vulnscope.votre-domaine.com
cloudflared tunnel route dns vulnscope api.vulnscope.votre-domaine.com
```

#### 3. Fichier de configuration `~/.cloudflared/config.yml`

```yaml
tunnel: <TUNNEL_ID>
credentials-file: /root/.cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: vulnscope.votre-domaine.com
    service: http://localhost:3000
  - hostname: api.vulnscope.votre-domaine.com
    service: http://localhost:8000
  - service: http_status:404
```

#### 4. Démarrer les services

```bash
# Démarrer VulnScope
docker compose -f docker-compose.prod.yml up -d

# Démarrer le tunnel
cloudflared tunnel run vulnscope
```

#### 5. Service systemd pour le tunnel

```bash
# /etc/systemd/system/cloudflared.service
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cloudflared tunnel run vulnscope
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable cloudflared
sudo systemctl start cloudflared
```

---

## ☸️ Option 4: k3s (Kubernetes Léger)

**Pour les utilisateurs avancés voulant une solution scalable.**

### Installation k3s

```bash
# Sur le VPS master
curl -sfL https://get.k3s.io | sh -

# Récupérer le kubeconfig
sudo cat /etc/rancher/k3s/k3s.yaml > ~/.kube/config
```

### Déploiement Kubernetes

Créer `k8s/namespace.yaml`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: vulnscope
```

Créer `k8s/secrets.yaml`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vulnscope-secrets
  namespace: vulnscope
type: Opaque
stringData:
  POSTGRES_PASSWORD: "votre-mot-de-passe"
  VULNSCOPE_SECRET_KEY: "votre-secret-key"
  VULNSCOPE_API_KEY: "votre-api-key"
  REDIS_PASSWORD: "votre-redis-password"
```

Créer `k8s/postgres.yaml`:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: vulnscope
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: vulnscope
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        env:
        - name: POSTGRES_USER
          value: "vulnscope"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: vulnscope-secrets
              key: POSTGRES_PASSWORD
        - name: POSTGRES_DB
          value: "vulnscope"
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: vulnscope
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
```

Créer `k8s/api.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnscope-api
  namespace: vulnscope
spec:
  replicas: 2
  selector:
    matchLabels:
      app: vulnscope-api
  template:
    metadata:
      labels:
        app: vulnscope-api
    spec:
      containers:
      - name: api
        image: vulnscope/api:latest
        imagePullPolicy: Never  # Pour développement local
        env:
        - name: VULNSCOPE_DATABASE__URL
          value: "postgresql://vulnscope:password@postgres:5432/vulnscope"
        - name: VULNSCOPE_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: vulnscope-secrets
              key: VULNSCOPE_SECRET_KEY
        ports:
        - containerPort: 8000
---
apiVersion: v1
kind: Service
metadata:
  name: vulnscope-api
  namespace: vulnscope
spec:
  selector:
    app: vulnscope-api
  ports:
  - port: 8000
    targetPort: 8000
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vulnscope-ingress
  namespace: vulnscope
  annotations:
    kubernetes.io/ingress.class: traefik
spec:
  rules:
  - host: api.vulnscope.votre-domaine.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: vulnscope-api
            port:
              number: 8000
```

### Déployer

```bash
kubectl apply -f k8s/
```

---

## 🏠 Option 5: Déploiement Local avec Tailscale

**Pour un accès sécurisé depuis n'importe où sans VPS.**

### Installation Tailscale

```bash
# Linux
curl -fsSL https://tailscale.com/install.sh | sh

# Connexion
tailscale up
```

### Démarrer VulnScope

```bash
# Démarrer les services
docker compose -f docker-compose.prod.yml up -d
```

### Accès

Votre machine sera accessible depuis n'importe où via le réseau Tailscale:
- Frontend: `http://100.x.y.z:3000`
- API: `http://100.x.y.z:8000`

---

## 🆓 VPS Gratuits Disponibles

| Provider | Specs | Durée | Restrictions |
|----------|-------|-------|--------------|
| **Oracle Cloud Free Tier** | 4 ARM CPU, 24GB RAM | Illimité | Carte crédit requise |
| **Google Cloud Free Tier** | e2-micro | Illimité | 1 instance max |
| **AWS Free Tier** | t2.micro | 12 mois | 750h/mois |
| **Azure Free Tier** | B1s | 12 mois | 750h/mois |
| **Fly.io** | 3 VMs partagées | Illimité | Crédit gratuit |
| **Railway** | $5/mois crédit | Illimité | Limité en ressources |

### Recommandation: Oracle Cloud Free Tier

C'est le plus généreux avec 4 CPU ARM et 24GB RAM gratuits à vie.

```bash
# Après création du compte Oracle Cloud
# Créer une instance ARM gratuite
# Se connecter en SSH
ssh opc@<instance-ip>

# Installer Docker
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker

# Cloner et déployer
git clone https://github.com/votre-repo/vulnscope.git
cd vulnscope
cp .env.example .env
# Éditer .env avec vos valeurs
docker compose -f docker-compose.prod.yml up -d
```

---

## 🔧 Script de Déploiement Automatisé

Créer `deploy-free.sh`:

```bash
#!/bin/bash
set -e

echo "🚀 Déploiement VulnScope - Option Gratuite"

# Vérifier Docker
if ! command -v docker &> /dev/null; then
    echo "📦 Installation de Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
fi

# Vérifier Docker Compose
if ! command -v docker compose &> /dev/null; then
    echo "📦 Installation de Docker Compose..."
    sudo apt install -y docker-compose-plugin
fi

# Générer les secrets
echo "🔐 Génération des secrets..."
export VULNSCOPE_SECRET_KEY=$(openssl rand -hex 32)
export VULNSCOPE_API_KEY=$(openssl rand -base64 32)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)
export VULNSCOPE_REDIS__PASSWORD=$(openssl rand -hex 16)
export MINIO_ROOT_USER="vulnscope"
export MINIO_ROOT_PASSWORD=$(openssl rand -hex 16)

# Créer .env
cat > .env << EOF
VULNSCOPE_SECRET_KEY=${VULNSCOPE_SECRET_KEY}
VULNSCOPE_API_KEY=${VULNSCOPE_API_KEY}
VULNSCOPE_DATABASE__URL=postgresql://vulnscope:${POSTGRES_PASSWORD}@db:5432/vulnscope
VULNSCOPE_REDIS__PASSWORD=${VULNSCOPE_REDIS__PASSWORD}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
MINIO_ROOT_USER=${MINIO_ROOT_USER}
MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}
EOF

echo "📝 Fichier .env créé"

# Démarrer les services
echo "🐳 Démarrage des conteneurs..."
docker compose -f docker-compose.prod.yml up -d

# Attendre que les services soient prêts
echo "⏳ Attente du démarrage des services..."
sleep 30

# Vérifier la santé
echo "🏥 Vérification de la santé..."
curl -f http://localhost:8000/health || echo "⚠️ L'API n'est pas encore prête"

echo ""
echo "✅ Déploiement terminé!"
echo ""
echo "📍 URLs d'accès:"
echo "   Frontend: http://localhost:3000"
echo "   API: http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"
echo "   MinIO Console: http://localhost:9001"
echo ""
echo "🔐 Identifiants générés dans .env"
echo "   Consultez avec: cat .env"
```

---

## 📊 Comparatif Final

| Solution | Meilleur pour | Effort | Maintenance |
|----------|--------------|--------|-------------|
| **Coolify** | Production simple | 1h | Faible |
| **CapRover** | Petites équipes | 1h | Faible |
| **Cloudflare Tunnel** | Local/VPS sans ports | 2h | Moyenne |
| **k3s** | Scalabilité | 4h+ | Élevée |
| **Tailscale** | Accès personnel | 30min | Faible |

---

## 🎯 Recommandation Finale

**Pour un déploiement gratuit optimal:**

1. **Obtenez un VPS gratuit Oracle Cloud** (4 CPU, 24GB RAM)
2. **Installez Coolify** pour une gestion simple
3. **Utilisez un domaine gratuit** (DuckDNS ou Freenom)
4. **SSL automatique** avec Let's Encrypt

**Commandes rapides:**

```bash
# Sur Oracle Cloud VPS
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash

# Puis configurer via l'interface web
# https://votre-ip:3000
```

---

## 📚 Ressources

- [Coolify Documentation](https://coolify.io/docs)
- [CapRover Documentation](https://caprover.com/docs/)
- [Cloudflare Tunnels](https://developers.cloudflare.com/cloudflare-one/connections/network/tunnels/)
- [k3s Documentation](https://docs.k3s.io/)
- [Tailscale](https://tailscale.com/kb/)
- [Oracle Cloud Free Tier](https://www.oracle.com/cloud/free/)