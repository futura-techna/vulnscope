# 🏠 Déploiement VulnScope - Mini-Cloud Local avec Coolify + Cloudflare Tunnel

## 🎯 Objectif

Déployer VulnScope sur une machine locale (mini-PC, Raspberry Pi, serveur Proxmox) avec :
- **Coolify** : PaaS open source (alternative à Vercel/Render/Heroku)
- **Cloudflare Tunnel** : Accès public sécurisé sans ouvrir de ports
- **Cloudflare DNS** : DNS gratuit avec SSL automatique

### Avantages

| Avantage | Description |
|----------|-------------|
| ✅ **Gratuit** | Aucun coût d'hébergement |
| ✅ **Sécurisé** | Pas de ports ouverts, HTTPS automatique |
| ✅ **Sans IP fixe** | Fonctionne avec IP dynamique |
| ✅ **Sans VPS** | Tout tourne chez vous |
| ✅ **GitOps** | Déploiement automatique depuis Git |

---

## 🏗️ Architecture

```
                Internet
                    │
                    ▼
          ┌──────────────────┐
          │   Cloudflare      │
          │  (DNS + Tunnel)   │
          │   + SSL Auto      │
          └──────────────────┘
                    │
        Tunnel sécurisé (sortant)
                    │
                    ▼
      ┌──────────────────────────┐
      │  Machine locale (Docker) │
      │                          │
      │  ┌────────────────────┐  │
      │  │      Coolify       │  │
      │  │  (PaaS Dashboard)  │  │
      │  └────────────────────┘  │
      │           │              │
      │  ┌────────┴────────┐     │
      │  │                 │     │
      │  ▼                 ▼     │
      │ VulnScope API  Frontend  │
      │       │             │    │
      │       ▼             ▼    │
      │   PostgreSQL     Redis   │
      └──────────────────────────┘
```

---

## 📋 Prérequis

### Matériel

| Option | Spécifications minimales |
|--------|-------------------------|
| **Mini-PC** (recommandé) | 4+ GB RAM, 50+ GB SSD |
| **Raspberry Pi 4/5** | 4GB+ RAM, SSD USB |
| **PC fixe** | 4+ GB RAM disponible |
| **Serveur Proxmox** | VM avec 4GB RAM |

### Logiciel

- Ubuntu 22.04/24.04 LTS ou Debian 12
- Accès root/sudo

### Comptes requis

- [ ] Compte Cloudflare (gratuit) avec un domaine

---

## 🚀 Installation Rapide

### Option 1 : Installation automatisée

```bash
# Cloner le repo
git clone https://github.com/futura-techna/vulnscope.git
cd vulnscope

# Lancer l'installation
make local-install
```

### Option 2 : Installation manuelle

Suivez les étapes détaillées ci-dessous.

---

## Étape 1 : Préparer la machine locale

### 1.1 Mettre à jour le système

```bash
sudo apt update && sudo apt upgrade -y
```

### 1.2 Installer les dépendances

```bash
sudo apt install -y curl wget git jq htop
```

### 1.3 Optimiser pour Docker (recommandé)

```bash
# Créer un fichier swap si < 8GB RAM
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Optimiser sysctl
sudo tee /etc/sysctl.d/99-docker.conf << 'EOF'
vm.swappiness=10
vm.overcommit_memory=1
net.core.somaxconn=65535
net.ipv4.ip_local_port_range=1024 65535
EOF
sudo sysctl -p /etc/sysctl.d/99-docker.conf
```

---

## Étape 2 : Installer Docker

```bash
# Installer Docker
curl -fsSL https://get.docker.com | sudo sh

# Ajouter l'utilisateur au groupe docker
sudo usermod -aG docker $USER

# Activer les changements de groupe
newgrp docker

# Vérifier l'installation
docker --version
docker run hello-world
```

---

## Étape 3 : Installer Coolify

### 3.1 Installation

```bash
# Installer Coolify
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash
```

L'installation prend 3-5 minutes. À la fin, notez :
- L'URL d'accès : `http://<IP-LOCALE>:8000`
- Le mot de passe temporaire affiché

### 3.2 Premier accès

1. Ouvrez `http://<IP-LOCALE>:8000` dans votre navigateur
2. Créez un compte administrateur
3. Notez vos identifiants

### 3.3 Configurer Coolify

1. Allez dans **Settings** → **Configuration**
2. Configurez :
   - **Instance Domain** : `coolify.votredomaine.com`
   - **Instance Settings** : Activez les notifications souhaitées

---

## Étape 4 : Configurer Cloudflare

### 4.1 Prérequis Cloudflare

1. Avoir un domaine géré par Cloudflare
2. Les nameservers du domaine doivent pointer vers Cloudflare

### 4.2 Installer cloudflared

```bash
# Télécharger et installer cloudflared
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
sudo dpkg -i cloudflared.deb
sudo apt-get install -f -y  # Corriger les dépendances

# Vérifier l'installation
cloudflared --version
```

### 4.3 Authentifier cloudflared

```bash
# Connexion à Cloudflare
cloudflared tunnel login
```

Une fenêtre de navigateur s'ouvre. Sélectionnez votre domaine et autorisez l'accès.

### 4.4 Créer un tunnel

```bash
# Créer le tunnel
cloudflared tunnel create vulnscope-cloud

# Noter l'ID du tunnel affiché
# Exemple : Tunnel credentials written to /home/user/.cloudflared/<TUNNEL_ID>.json
```

### 4.5 Configurer le tunnel

Créez le fichier de configuration :

```bash
sudo mkdir -p /etc/cloudflared
sudo nano /etc/cloudflared/config.yml
```

Contenu (adaptez à votre domaine) :

```yaml
# Remplacez par l'ID de votre tunnel
tunnel: <TUNNEL_ID>
credentials-file: /home/<USER>/.cloudflared/<TUNNEL_ID>.json

ingress:
  # Coolify Dashboard
  - hostname: coolify.votredomaine.com
    service: http://localhost:8000

  # VulnScope Frontend
  - hostname: vulnscope.votredomaine.com
    service: http://localhost:3000

  # VulnScope API
  - hostname: api.votredomaine.com
    service: http://localhost:8001

  # Règle par défaut (obligatoire)
  - service: http_status:404
```

### 4.6 Créer les enregistrements DNS

```bash
# Créer les enregistrements DNS automatiquement
cloudflared tunnel route dns vulnscope-cloud coolify.votredomaine.com
cloudflared tunnel route dns vulnscope-cloud vulnscope.votredomaine.com
cloudflared tunnel route dns vulnscope-cloud api.votredomaine.com
```

### 4.7 Démarrer le tunnel

```bash
# Test
cloudflared tunnel run vulnscope-cloud

# Si OK, installer comme service
sudo cloudflared service install
sudo systemctl enable cloudflared
sudo systemctl start cloudflared

# Vérifier le statut
sudo systemctl status cloudflared
```

---

## Étape 5 : Déployer VulnScope sur Coolify

### 5.1 Créer un projet

1. Dans Coolify, cliquez sur **+ New Project**
2. Nom : `VulnScope`
3. Créer

### 5.2 Déployer avec Docker Compose

1. Dans le projet, **+ New Resource** → **Docker Compose**
2. Nom : `vulnscope-stack`
3. Collez le contenu suivant :

```yaml
version: '3.8'

services:
  # PostgreSQL Database
  db:
    image: postgres:15-alpine
    container_name: vulnscope-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: vulnscope
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: vulnscope
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vulnscope"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Redis Cache
  redis:
    image: redis:7-alpine
    container_name: vulnscope-redis
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # API Backend
  api:
    image: ghcr.io/futura-techna/vulnscope-api:latest
    # ou build depuis votre repo
    container_name: vulnscope-api
    restart: unless-stopped
    environment:
      - VULNSCOPE_SECRET_KEY=${VULNSCOPE_SECRET_KEY}
      - VULNSCOPE_API_KEY=${VULNSCOPE_API_KEY}
      - VULNSCOPE_DATABASE__URL=postgresql://vulnscope:${POSTGRES_PASSWORD}@db:5432/vulnscope
      - VULNSCOPE_REDIS__HOST=redis
      - VULNSCOPE_REDIS__PORT=6379
      - VULNSCOPE_REDIS__PASSWORD=${REDIS_PASSWORD}
      - VULNSCOPE_ENVIRONMENT=production
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    labels:
      - "coolify.managed=true"

  # Frontend
  frontend:
    image: ghcr.io/futura-techna/vulnscope-frontend:latest
    container_name: vulnscope-frontend
    restart: unless-stopped
    environment:
      - NEXT_PUBLIC_API_URL=https://api.votredomaine.com/api/v1
      - API_URL=http://api:8000
    depends_on:
      - api
    labels:
      - "coolify.managed=true"

volumes:
  postgres_data:
  redis_data:
```

4. Ajoutez les variables d'environnement :

```env
POSTGRES_PASSWORD=<mot-de-passe-postgres>
REDIS_PASSWORD=<mot-de-passe-redis>
VULNSCOPE_SECRET_KEY=<generer-avec-openssl-rand-hex-32>
VULNSCOPE_API_KEY=<generer-avec-openssl-rand-base64-32>
```

Générez les clés :

```bash
openssl rand -hex 32  # SECRET_KEY
openssl rand -base64 32  # API_KEY
```

5. Cliquez sur **Deploy**

### 5.3 Configurer les domaines

Dans Coolify, pour chaque service :

1. **API** : Ajoutez le domaine `api.votredomaine.com`
2. **Frontend** : Ajoutez le domaine `vulnscope.votredomaine.com`
3. Activez **HTTPS** (géré par Cloudflare)

---

## Étape 6 : Configurer le pare-feu local (optionnel mais recommandé)

```bash
# Installer UFW
sudo apt install -y ufw

# Autoriser SSH (important !)
sudo ufw allow ssh

# Autoriser les connexions locales seulement
sudo ufw allow from 192.168.0.0/16 to any port 8000  # Coolify (local only)
sudo ufw allow from 192.168.0.0/16 to any port 3000  # Frontend (local only)

# Activer le pare-feu
sudo ufw enable

# Vérifier
sudo ufw status
```

> **Note** : Cloudflare Tunnel n'a pas besoin de ports ouverts vers l'extérieur.

---

## 🔒 Sécurité

### Mesures automatiques

| Mesure | Implémentation |
|--------|----------------|
| **HTTPS** | Cloudflare SSL automatique |
| **Tunnel chiffré** | Cloudflare Tunnel (chiffrement de bout en bout) |
| **Pas de ports ouverts** | Tunnel sortant uniquement |
| **Protection DDoS** | Cloudflare inclut une protection DDoS |
| **WAF** | Cloudflare WAF (plan gratuit limité) |

### Mesures supplémentaires recommandées

```bash
# 1. Configurer fail2ban
sudo apt install -y fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# 2. Mettre à jour automatiquement
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# 3. Sauvegardes automatiques (via Coolify)
# Configurez les sauvegardes dans Settings → Backups
```

### Restreindre l'accès Cloudflare (recommandé)

Ajoutez dans **Cloudflare Dashboard** → **Security** → **WAF** :

1. **Règle 1** : Bloquer les pays non autorisés
2. **Règle 2** : Exiger une authentification pour `/admin`
3. **Règle 3** : Limiter le taux de requêtes API

---

## 🔄 Mise à jour

### Mettre à jour VulnScope

Dans Coolify :
1. Sélectionnez l'application
2. **Pull** pour récupérer les derniers changements
3. **Deploy**

### Mettre à jour Coolify

```bash
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash
```

### Mettre à jour cloudflared

```bash
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
sudo dpkg -i cloudflared.deb
sudo systemctl restart cloudflared
```

---

## 📊 Monitoring

### Logs

```bash
# Logs Coolify
docker logs coolify

# Logs VulnScope
docker logs vulnscope-api
docker logs vulnscope-frontend

# Logs Cloudflare Tunnel
sudo journalctl -u cloudflared -f
```

### Métriques système

```bash
# Utilisation des ressources
htop
docker stats

# Espace disque
df -h
```

### Dashboard Coolify

Coolify inclut un dashboard avec :
- Statut des services
- Utilisation des ressources
- Logs en temps réel
- Historique des déploiements

---

## 🆘 Dépannage

### Le tunnel ne fonctionne pas

```bash
# Vérifier le statut
sudo systemctl status cloudflared

# Tester manuellement
cloudflared tunnel run vulnscope-cloud

# Vérifier les logs
sudo journalctl -u cloudflared -n 50
```

### Coolify inaccessible

```bash
# Vérifier que Coolify tourne
docker ps | grep coolify

# Redémarrer Coolify
docker restart coolify

# Vérifier les logs
docker logs coolify
```

### Application ne démarre pas

```bash
# Vérifier les logs
docker logs vulnscope-api

# Vérifier les ressources
free -h
df -h

# Redémarrer les services
docker-compose restart
```

### Problème DNS

```bash
# Vérifier la résolution DNS
nslookup vulnscope.votredomaine.com

# Vérifier les enregistrements Cloudflare
cloudflared tunnel list
```

---

## 💰 Coût total

| Service | Coût |
|---------|------|
| Coolify | **0€** (Open Source) |
| Cloudflare DNS | **0€** (Gratuit) |
| Cloudflare Tunnel | **0€** (Gratuit) |
| Cloudflare SSL | **0€** (Let's Encrypt) |
| **TOTAL** | **0€/mois** |

---

## ✅ Checklist finale

- [ ] Machine locale prête (Docker installé)
- [ ] Coolify installé et configuré
- [ ] Cloudflare Tunnel configuré
- [ ] DNS Cloudflare configuré
- [ ] VulnScope déployé sur Coolify
- [ ] Domaines configurés dans Coolify
- [ ] HTTPS vérifié
- [ ] Pare-feu local configuré (optionnel)
- [ ] Sauvegardes configurées

---

## 📚 Liens utiles

- [Documentation Coolify](https://coolify.io/docs)
- [Cloudflare Tunnel Docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)
- [Cloudflare DNS](https://dash.cloudflare.com)
- [VulnScope Documentation](./README.md)

---

## 🎉 Résultat

Vous avez maintenant :

- ✅ Un cloud personnel complet (mini-Vercel/Render chez vous)
- ✅ Déploiement automatique GitOps
- ✅ HTTPS gratuit et automatique
- ✅ Aucun port ouvert vers l'extérieur
- ✅ Aucun VPS requis
- ✅ Aucun coût d'hébergement
- ✅ Accès public stable et sécurisé
- ✅ Gestion multi-applications et multi-bases de données

C'est littéralement un **mini-Heroku/Vercel/Render** qui tourne chez vous, gratuitement !