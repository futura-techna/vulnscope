# Déploiement VulnScope sur Google Cloud Free Tier avec Coolify et DuckDNS

## 🎯 Objectif

Déployer VulnScope gratuitement avec :
- **Google Cloud Free Tier** : e2-micro (illimité)
- **Coolify** : PaaS open source pour gestion simplifiée
- **DuckDNS** : DNS dynamique gratuit

## 📋 Prérequis

- Compte Google (Gmail)
- Carte bancaire (pour vérification Google Cloud - pas de débit)
- Un domaine (optionnel) ou utiliser DuckDNS gratuit

---

## Étape 1 : Créer le VPS Google Cloud (e2-micro gratuit)

### 1.1 Créer un compte Google Cloud

1. Allez sur https://cloud.google.com/free
2. Cliquez sur **"Essayer gratuitement"**
3. Connectez-vous avec votre compte Google
4. Acceptez les conditions et renseignez votre carte bancaire

> **Note** : Vous ne serez pas débité. Google demande une carte pour vérifier votre identité.

### 1.2 Créer un projet

```bash
# Via la console web :
# 1. Allez sur https://console.cloud.google.com
# 2. Cliquez sur "Sélectionner un projet" → "Nouveau projet"
# 3. Nom : vulnscope-project
# 4. Créer
```

### 1.3 Activer l'API Compute Engine

1. Dans la console, recherchez **"Compute Engine"**
2. Cliquez pour activer l'API
3. Patientez quelques minutes

### 1.4 Créer l'instance e2-micro gratuite

#### Via la console web :

1. Allez dans **Compute Engine** → **Instances de VM**
2. Cliquez sur **Créer une instance**
3. Configurez :

| Paramètre | Valeur |
|-----------|--------|
| **Nom** | vulnscope-server |
| **Région** | us-west1, us-central1, ou us-east1 (important pour le gratuit) |
| **Zone** | us-west1-a (ou équivalent) |
| **Machine** | e2-micro (2 vCPU, 1 GB RAM) |
| **Disque de démarrage** | Ubuntu 22.04 LTS |
| **Taille du disque** | 30 GB (standard persistant) |
| **Pare-feu** | ✅ Autoriser HTTP, ✅ Autoriser HTTPS |

4. Cliquez sur **Créer**

#### Via gcloud CLI (alternative) :

```bash
# Installer gcloud CLI
# Ubuntu/Debian : https://cloud.google.com/sdk/docs/install

# Authentification
gcloud auth login

# Définir le projet
gcloud config set project vulnscope-project

# Créer l'instance
gcloud compute instances create vulnscope-server \
    --machine-type=e2-micro \
    --zone=us-west1-a \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=30GB \
    --tags=http-server,https-server
```

### 1.5 Obtenir l'IP externe

```bash
# Via console : Compute Engine → Instances de VM
# L'IP externe est affichée dans la liste

# Via gcloud
gcloud compute instances list
```

Notez cette IP (ex: `35.123.45.67`)

---

## Étape 2 : Configurer DuckDNS

### 2.1 Créer un compte DuckDNS

1. Allez sur https://www.duckdns.org
2. Connectez-vous avec Google, GitHub, Twitter ou Reddit
3. Vous êtes redirigé vers votre page de gestion

### 2.2 Créer un sous-domaine

1. Dans le champ "subdomain", entrez : `vulnscope`
2. Entrez votre IP Google Cloud : `35.123.45.67`
3. Cliquez sur **"add domain"**

Votre domaine sera : `vulnscope.duckdns.org`

### 2.3 Noter votre token

Sur la page DuckDNS, notez votre token (ex: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`)

---

## Étape 3 : Configurer le serveur Google Cloud

### 3.1 Se connecter en SSH

```bash
# Via la console Google Cloud : cliquez sur "SSH" à côté de l'instance

# Ou via gcloud
gcloud compute ssh vulnscope-server --zone=us-west1-a
```

### 3.2 Mettre à jour le système

```bash
sudo apt update && sudo apt upgrade -y
```

### 3.3 Installer Docker

```bash
# Installer Docker
curl -fsSL https://get.docker.com | sudo sh

# Ajouter l'utilisateur au groupe docker
sudo usermod -aG docker $USER

# Recharger les groupes
newgrp docker

# Vérifier l'installation
docker --version
```

### 3.4 Installer Coolify

```bash
# Installer Coolify
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash
```

L'installation prend quelques minutes. À la fin, vous verrez :
```
Coolify is installed!
Visit: http://<your-ip>:8000
```

### 3.5 Configurer le pare-feu Google Cloud

```bash
# Via gcloud CLI
gcloud compute firewall-rules create allow-coolify \
    --allow tcp:8000,tcp:3000 \
    --source-ranges 0.0.0.0/0 \
    --target-tags http-server

# Ou via la console :
# VPC Network → Pare-feu → Créer une règle
# Nom : allow-coolify
# Cibles : Tags spécifiés : http-server
# Source : 0.0.0.0/0
# Ports : tcp:8000, tcp:3000
```

---

## Étape 4 : Configurer Coolify

### 4.1 Premier accès

1. Ouvrez votre navigateur : `http://35.123.45.67:8000`
2. Créez un compte administrateur
3. Connectez-vous

### 4.2 Configurer le domaine DuckDNS

1. Allez dans **Settings** → **Configuration**
2. Dans **Instance Domain**, entrez : `vulnscope.duckdns.org`
3. Cliquez sur **Save**

### 4.3 Configurer le DNS Dynamique (DuckDNS Update)

Sur le serveur, créez un script de mise à jour :

```bash
# Créer le script de mise à jour DuckDNS
cat > ~/duckdns.sh << 'EOF'
#!/bin/bash
# Remplacez par votre token et domaine
TOKEN="votre-token-duckdns"
DOMAIN="vulnscope"

# Obtenir l'IP actuelle
CURRENT_IP=$(curl -s https://api.ipify.org)

# Mettre à jour DuckDNS
curl -s "https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}&ip=${CURRENT_IP}"
EOF

chmod +x ~/duckdns.sh

# Tester
~/duckdns.sh

# Ajouter au crontab pour mise à jour automatique (toutes les 5 minutes)
(crontab -l 2>/dev/null; echo "*/5 * * * * $HOME/duckdns.sh > /dev/null 2>&1") | crontab -
```

---

## Étape 5 : Déployer VulnScope sur Coolify

### 5.1 Créer un projet

1. Dans Coolify, cliquez sur **+ New Project**
2. Nom : `VulnScope`
3. Créer

### 5.2 Ajouter PostgreSQL

1. Dans le projet, cliquez on **+ New Resource** → **Database**
2. Sélectionnez **PostgreSQL**
3. Configurez :

| Paramètre | Valeur |
|-----------|--------|
| **Name** | vulnscope-db |
| **PostgreSQL Username** | vulnscope |
| **PostgreSQL Password** | (généré automatiquement ou personnalisé) |
| **PostgreSQL Database** | vulnscope |

4. Cliquez sur **Deploy**

### 5.3 Ajouter Redis

1. Cliquez sur **+ New Resource** → **Database**
2. Sélectionnez **Redis**
3. Configurez :

| Paramètre | Valeur |
|-----------|--------|
| **Name** | vulnscope-redis |
| **Redis Password** | (généré automatiquement) |

4. Cliquez sur **Deploy**

### 5.4 Déployer l'API VulnScope

#### Option A : Depuis un repository Git

1. Cliquez on **+ New Resource** → **Application**
2. Sélectionnez **Git Repository**
3. Configurez :

| Paramètre | Valeur |
|-----------|--------|
| **Name** | vulnscope-api |
| **Repository URL** | https://github.com/votre-repo/vulnscope.git |
| **Branch** | main |
| **Build Pack** | Dockerfile |

4. Dans **Configuration** → **Environment Variables**, ajoutez :

```env
VULNSCOPE_SECRET_KEY=générer-avec-openssl-rand-hex-32
VULNSCOPE_API_KEY=générer-avec-openssl-rand-base64-32
VULNSCOPE_DATABASE__URL=postgresql://vulnscope:MOT_DE_PASSE@vulnscope-db:5432/vulnscope
VULNSCOPE_REDIS__HOST=vulnscope-redis
VULNSCOPE_REDIS__PORT=6379
VULNSCOPE_REDIS__PASSWORD=MOT_DE_PASSE_REDIS
VULNSCOPE_ENVIRONMENT=production
```

5. Dans **Domains**, ajoutez : `api.vulnscope.duckdns.org`
6. Activez **HTTPS** (Let's Encrypt)
7. Cliquez sur **Deploy**

#### Option B : Via Docker Compose

1. Cliquez on **+ New Resource** → **Docker Compose**
2. Nom : `vulnscope-stack`
3. Collez le contenu de votre `docker-compose.prod.yml` :

```yaml
version: '3.8'

services:
  api:
    image: ghcr.io/votre-repo/vulnscope-api:latest
    # ou build depuis Git
    environment:
      - VULNSCOPE_DATABASE__URL=postgresql://vulnscope:${POSTGRES_PASSWORD}@vulnscope-db:5432/vulnscope
      - VULNSCOPE_REDIS__HOST=vulnscope-redis
      - VULNSCOPE_REDIS__PASSWORD=${REDIS_PASSWORD}
      - VULNSCOPE_SECRET_KEY=${VULNSCOPE_SECRET_KEY}
    depends_on:
      - db
      - redis

  frontend:
    image: ghcr.io/votre-repo/vulnscope-frontend:latest
    environment:
      - NEXT_PUBLIC_API_URL=https://api.vulnscope.duckdns.org/api/v1
    depends_on:
      - api
```

### 5.5 Déployer le Frontend

1. Cliquez on **+ New Resource** → **Application**
2. Configurez :

| Paramètre | Valeur |
|-----------|--------|
| **Name** | vulnscope-frontend |
| **Repository URL** | https://github.com/votre-repo/vulnscope.git |
| **Branch** | main |
| **Build Pack** | Nixpacks |
| **Build Path** | frontend |
| **Domain** | vulnscope.duckdns.org |

3. Environment Variables :

```env
NEXT_PUBLIC_API_URL=https://api.vulnscope.duckdns.org/api/v1
API_URL=http://vulnscope-api:8000
```

4. Cliquez sur **Deploy**

---

## Étape 6 : Configurer SSL avec Let's Encrypt

### 6.1 Activer SSL dans Coolify

1. Allez dans **Settings** → **Configuration**
2. Activez **Automatic HTTPS**
3. Configurez Let's Encrypt :
   - Email : votre@email.com
   - Cochez **Use Let's Encrypt for SSL**

### 6.2 Appliquer SSL aux applications

Pour chaque application (API et Frontend) :

1. Allez dans l'application → **Configuration** → **Domains**
2. Vérifiez que le domaine est correct
3. Activez **HTTPS**
4. Sauvegardez et redéployez

---

## Étape 7 : Vérifier le déploiement

### 7.1 Tester l'accès

```bash
# Frontend
curl -I https://vulnscope.duckdns.org

# API
curl https://api.vulnscope.duckdns.org/health
```

### 7.2 Vérifier les logs

Dans Coolify :
1. Sélectionnez une application
2. Cliquez sur **Logs**
3. Vérifiez qu'il n'y a pas d'erreurs

### 7.3 Accéder aux services

| Service | URL |
|---------|-----|
| **Frontend** | https://vulnscope.duckdns.org |
| **API** | https://api.vulnscope.duckdns.org |
| **API Docs** | https://api.vulnscope.duckdns.org/docs |
| **Coolify Dashboard** | https://vulnscope.duckdns.org:8000 |

---

## 🔧 Configuration avancée

### Optimiser pour e2-micro (1GB RAM)

Le e2-micro a seulement 1GB de RAM, quelques optimisations sont nécessaires :

#### Créer un fichier swap

```bash
# Sur le serveur
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Rendre permanent
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

#### Optimiser PostgreSQL

```yaml
# Dans Coolify, ajoutez ces variables PostgreSQL :
POSTGRES_SHARED_BUFFERS: 128MB
POSTGRES_EFFECTIVE_CACHE_SIZE: 256MB
```

#### Limiter les ressources Docker

```yaml
# Dans docker-compose
services:
  api:
    deploy:
      resources:
        limits:
          memory: 512M
```

### Désactiver Elasticsearch (optionnel)

Elasticsearch consomme beaucoup de mémoire. Sur e2-micro, il est recommandé de le désactiver :

```yaml
# Commenter ou supprimer le service elasticsearch dans docker-compose
```

---

## 📊 Monitoring

### Vérifier l'utilisation des ressources

```bash
# Sur le serveur
htop
docker stats
```

### Logs Coolify

```bash
docker logs coolify
```

---

## 🔄 Mise à jour

### Mettre à jour VulnScope

1. Dans Coolify, allez sur l'application
2. Cliquez sur **Pull** (pour récupérer les derniers changements)
3. Cliquez sur **Deploy**

### Mettre à jour Coolify

```bash
# Sur le serveur
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash
```

---

## 🆘 Dépannage

### L'application ne démarre pas

```bash
# Vérifier les logs
docker logs vulnscope-api

# Vérifier les ressources
free -h
df -h
```

### Problème DNS DuckDNS

```bash
# Vérifier la mise à jour
~/duckdns.sh

# Vérifier la résolution DNS
nslookup vulnscope.duckdns.org
```

### Problème SSL

```bash
# Régénérer les certificats
# Dans Coolify : Settings → SSL → Regenerate Certificates
```

### Mémoire insuffisante

```bash
# Vérifier le swap
swapon --show

# Si pas de swap, le créer
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## 💰 Coût total

| Service | Coût |
|---------|------|
| Google Cloud e2-micro | **0€** (Free Tier) |
| Coolify | **0€** (Open Source) |
| DuckDNS | **0€** (Gratuit) |
| Let's Encrypt SSL | **0€** (Gratuit) |
| **TOTAL** | **0€/mois** |

---

## ✅ Checklist finale

- [ ] Compte Google Cloud créé
- [ ] Instance e2-micro créée dans une région éligible (us-west1/us-central1/us-east1)
- [ ] DuckDNS configuré avec le sous-domaine
- [ ] Docker installé sur le serveur
- [ ] Coolify installé et accessible
- [ ] PostgreSQL déployé dans Coolify
- [ ] Redis déployé dans Coolify
- [ ] API VulnScope déployée
- [ ] Frontend VulnScope déployé
- [ ] SSL activé avec Let's Encrypt
- [ ] Swap configuré (recommandé)
- [ ] Mise à jour DuckDNS en crontab

---

## 📚 Liens utiles

- [Google Cloud Free Tier](https://cloud.google.com/free)
- [Documentation Coolify](https://coolify.io/docs)
- [DuckDNS](https://www.duckdns.org)
- [Let's Encrypt](https://letsencrypt.org/)