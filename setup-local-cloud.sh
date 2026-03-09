#!/bin/bash

#==============================================================================
# VulnScope - Installation Mini-Cloud Local avec Coolify + Cloudflare Tunnel
#==============================================================================
# Ce script installe :
# - Docker
# - Coolify (PaaS open source)
# - cloudflared (Cloudflare Tunnel)
#
# Usage: ./setup-local-cloud.sh [--domain votre-domaine.com]
#==============================================================================

set -e

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
DOMAIN=""
TUNNEL_NAME="vulnscope-cloud"

# Fonctions d'affichage
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Parser les arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --tunnel-name)
                TUNNEL_NAME="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --domain DOMAIN        Votre domaine Cloudflare (ex: mondomaine.com)"
                echo "  --tunnel-name NAME     Nom du tunnel Cloudflare (défaut: vulnscope-cloud)"
                echo "  --help, -h             Afficher cette aide"
                echo ""
                echo "Exemple:"
                echo "  $0 --domain mondomaine.com"
                exit 0
                ;;
            *)
                error "Option inconnue: $1. Utilisez --help pour voir les options disponibles."
                ;;
        esac
    done
}

# Vérifier si root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        warning "Ce script ne doit pas être exécuté en root directement."
        warning "Il utilisera sudo pour les commandes nécessitant des privilèges élevés."
    fi
}

# Vérifier le système
check_system() {
    info "Vérification du système..."
    
    if [[ ! -f /etc/os-release ]]; then
        error "Impossible de déterminer la distribution Linux."
    fi
    
    source /etc/os-release
    
    case "$ID" in
        ubuntu|debian)
            PKG_MANAGER="apt"
            success "Système détecté: $PRETTY_NAME"
            ;;
        *)
            warning "Distribution non testée: $PRETTY_NAME"
            warning "Le script est optimisé pour Ubuntu/Debian."
            read -p "Continuer quand même? (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            PKG_MANAGER="apt"
            ;;
    esac
    
    # Vérifier l'architecture
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]]; then
        error "Architecture non supportée: $ARCH. Seules x86_64 et aarch64 sont supportées."
    fi
    success "Architecture: $ARCH"
}

# Mettre à jour le système
update_system() {
    info "Mise à jour du système..."
    
    sudo $PKG_MANAGER update -y
    
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        sudo $PKG_MANAGER upgrade -y
    fi
    
    success "Système mis à jour"
}

# Installer les dépendances de base
install_dependencies() {
    info "Installation des dépendances..."
    
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        sudo $PKG_MANAGER install -y \
            curl \
            wget \
            git \
            jq \
            htop \
            ca-certificates \
            gnupg \
            lsb-release \
            ufw \
            fail2ban
    fi
    
    success "Dépendances installées"
}

# Optimiser le système pour Docker
optimize_system() {
    info "Optimisation du système pour Docker..."
    
    # Créer swap si moins de 8GB RAM
    TOTAL_MEM=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_MEM_GB=$((TOTAL_MEM / 1024 / 1024))
    
    if [[ $TOTAL_MEM_GB -lt 8 ]]; then
        info "Mémoire détectée: ${TOTAL_MEM_GB}GB - Création d'un fichier swap..."
        
        if [[ ! -f /swapfile ]]; then
            sudo fallocate -l 4G /swapfile
            sudo chmod 600 /swapfile
            sudo mkswap /swapfile
            sudo swapon /swapfile
            echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
            success "Fichier swap créé (4GB)"
        else
            info "Fichier swap déjà existant"
        fi
    fi
    
    # Optimiser sysctl
    if [[ ! -f /etc/sysctl.d/99-docker.conf ]]; then
        sudo tee /etc/sysctl.d/99-docker.conf << 'EOF'
# Optimisations pour Docker
vm.swappiness=10
vm.overcommit_memory=1
net.core.somaxconn=65535
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.ip_forward=1
EOF
        sudo sysctl -p /etc/sysctl.d/99-docker.conf
        success "Paramètres sysctl optimisés"
    fi
}

# Installer Docker
install_docker() {
    info "Installation de Docker..."
    
    if command -v docker &> /dev/null; then
        success "Docker est déjà installé: $(docker --version)"
        return 0
    fi
    
    # Installer Docker avec le script officiel
    curl -fsSL https://get.docker.com | sudo sh
    
    # Démarrer Docker
    sudo systemctl enable docker
    sudo systemctl start docker
    
    # Ajouter l'utilisateur au groupe docker
    if [[ $EUID -ne 0 ]]; then
        sudo usermod -aG docker $USER
        info "L'utilisateur $USER a été ajouté au groupe docker."
        warning "Vous devrez vous déconnecter/reconnecter ou exécuter 'newgrp docker' pour appliquer les changements."
    fi
    
    success "Docker installé: $(docker --version)"
}

# Installer Coolify
install_coolify() {
    info "Installation de Coolify..."
    
    # Vérifier si Coolify est déjà installé
    if docker ps -a --format '{{.Names}}' | grep -q "^coolify$"; then
        warning "Coolify semble déjà être installé."
        read -p "Réinstaller Coolify? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 0
        fi
        docker rm -f coolify 2>/dev/null || true
    fi
    
    # Installer Coolify
    curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash
    
    success "Coolify installé avec succès!"
    
    # Afficher les informations d'accès
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo "================================================"
    echo -e "${GREEN}Coolify est accessible à:${NC}"
    echo -e "  Local:   http://localhost:8000"
    echo -e "  Réseau:  http://${LOCAL_IP}:8000"
    echo ""
    echo -e "${YELLOW}Important:${NC}"
    echo "  1. Créez votre compte administrateur"
    echo "  2. Notez vos identifiants"
    echo "================================================"
    echo ""
}

# Installer cloudflared
install_cloudflared() {
    info "Installation de cloudflared..."
    
    if command -v cloudflared &> /dev/null; then
        success "cloudflared est déjà installé: $(cloudflared --version)"
        return 0
    fi
    
    # Télécharger et installer cloudflared
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)
            CLOUDFLARED_ARCH="amd64"
            ;;
        aarch64)
            CLOUDFLARED_ARCH="arm64"
            ;;
        *)
            error "Architecture non supportée pour cloudflared: $ARCH"
            ;;
    esac
    
    CLOUDFLARED_DEB="cloudflared-linux-${CLOUDFLARED_ARCH}.deb"
    
    info "Téléchargement de cloudflared pour ${ARCH}..."
    curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/${CLOUDFLARED_DEB}" -o /tmp/cloudflared.deb
    
    sudo dpkg -i /tmp/cloudflared.deb || sudo $PKG_MANAGER install -f -y
    
    rm /tmp/cloudflared.deb
    
    success "cloudflared installé: $(cloudflared --version)"
}

# Configurer le tunnel Cloudflare
configure_tunnel() {
    if [[ -z "$DOMAIN" ]]; then
        warning "Aucun domaine spécifié. La configuration du tunnel sera manuelle."
        echo ""
        echo "Pour configurer le tunnel Cloudflare, exécutez:"
        echo "  1. cloudflared tunnel login"
        echo "  2. cloudflared tunnel create vulnscope-cloud"
        echo "  3. Configurez /etc/cloudflared/config.yml"
        echo ""
        return 0
    fi
    
    info "Configuration du tunnel Cloudflare..."
    
    # Vérifier si déjà authentifié
    if [[ ! -d ~/.cloudflared ]]; then
        info "Authentification à Cloudflare..."
        info "Une fenêtre de navigateur va s'ouvrir pour l'authentification."
        cloudflared tunnel login
    else
        success "Déjà authentifié à Cloudflare"
    fi
    
    # Créer le tunnel
    info "Création du tunnel '$TUNNEL_NAME'..."
    TUNNEL_OUTPUT=$(cloudflared tunnel create "$TUNNEL_NAME" 2>&1) || true
    
    # Récupérer l'ID du tunnel
    TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
    
    if [[ -z "$TUNNEL_ID" ]]; then
        warning "Impossible de créer le tunnel. Il existe peut-être déjà."
        TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
    fi
    
    if [[ -n "$TUNNEL_ID" ]]; then
        success "Tunnel créé: $TUNNEL_NAME (ID: $TUNNEL_ID)"
        
        # Créer le fichier de configuration
        sudo mkdir -p /etc/cloudflared
        
        sudo tee /etc/cloudflared/config.yml << EOF
# Configuration du tunnel Cloudflare pour VulnScope
# Généré automatiquement par setup-local-cloud.sh

tunnel: $TUNNEL_ID
credentials-file: /home/$USER/.cloudflared/$TUNNEL_ID.json

ingress:
  # Coolify Dashboard
  - hostname: coolify.$DOMAIN
    service: http://localhost:8000

  # VulnScope Frontend
  - hostname: vulnscope.$DOMAIN
    service: http://localhost:3000

  # VulnScope API
  - hostname: api.$DOMAIN
    service: http://localhost:8001

  # Règle par défaut (obligatoire)
  - service: http_status:404
EOF
        
        success "Fichier de configuration créé: /etc/cloudflared/config.yml"
        
        # Créer les enregistrements DNS
        info "Création des enregistrements DNS..."
        cloudflared tunnel route dns "$TUNNEL_NAME" "coolify.$DOMAIN" || true
        cloudflared tunnel route dns "$TUNNEL_NAME" "vulnscope.$DOMAIN" || true
        cloudflared tunnel route dns "$TUNNEL_NAME" "api.$DOMAIN" || true
        
        success "Enregistrements DNS créés"
        
        # Installer comme service
        info "Installation du tunnel comme service système..."
        sudo cloudflared service install
        sudo systemctl enable cloudflared
        sudo systemctl start cloudflared
        
        success "Service cloudflared démarré"
        
        echo ""
        echo "================================================"
        echo -e "${GREEN}Tunnel Cloudflare configuré!${NC}"
        echo ""
        echo "Vos services sont accessibles via:"
        echo -e "  Coolify:   https://coolify.$DOMAIN"
        echo -e "  VulnScope: https://vulnscope.$DOMAIN"
        echo -e "  API:       https://api.$DOMAIN"
        echo "================================================"
        echo ""
    fi
}

# Configurer le pare-feu
configure_firewall() {
    info "Configuration du pare-feu (UFW)..."
    
    # Vérifier si UFW est actif
    if sudo ufw status | grep -q "Status: active"; then
        success "Pare-feu déjà actif"
    else
        # Configurer les règles de base
        sudo ufw default deny incoming
        sudo ufw default allow outgoing
        
        # SSH (important!)
        sudo ufw allow ssh
        
        # Ports locaux uniquement
        sudo ufw allow from 192.168.0.0/16 to any port 8000 comment 'Coolify (local)'
        sudo ufw allow from 192.168.0.0/16 to any port 3000 comment 'VulnScope Frontend (local)'
        
        # Activer le pare-feu
        echo "y" | sudo ufw enable
        
        success "Pare-feu configuré et activé"
    fi
    
    # Afficher le statut
    sudo ufw status
}

# Configurer fail2ban
configure_fail2ban() {
    info "Configuration de fail2ban..."
    
    if [[ ! -f /etc/fail2ban/jail.local ]]; then
        sudo tee /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
        
        sudo systemctl enable fail2ban
        sudo systemctl restart fail2ban
        
        success "fail2ban configuré"
    else
        success "fail2ban déjà configuré"
    fi
}

# Générer le docker-compose pour VulnScope
generate_docker_compose() {
    info "Génération du docker-compose pour VulnScope..."
    
    if [[ -n "$DOMAIN" ]]; then
        API_URL="https://api.$DOMAIN/api/v1"
    else
        API_URL="http://localhost:8001/api/v1"
    fi
    
    cat > docker-compose.local.yml << EOF
version: '3.8'

services:
  # PostgreSQL Database
  db:
    image: postgres:15-alpine
    container_name: vulnscope-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: vulnscope
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD:-changeme}
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
    command: redis-server --requirepass \${REDIS_PASSWORD:-changeme}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # API Backend
  api:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: vulnscope-api
    restart: unless-stopped
    ports:
      - "8001:8000"
    environment:
      - VULNSCOPE_SECRET_KEY=\${VULNSCOPE_SECRET_KEY}
      - VULNSCOPE_API_KEY=\${VULNSCOPE_API_KEY}
      - VULNSCOPE_DATABASE__URL=postgresql://vulnscope:\${POSTGRES_PASSWORD:-changeme}@db:5432/vulnscope
      - VULNSCOPE_REDIS__HOST=redis
      - VULNSCOPE_REDIS__PORT=6379
      - VULNSCOPE_REDIS__PASSWORD=\${REDIS_PASSWORD:-changeme}
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

  # Frontend (Next.js)
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: vulnscope-frontend
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=$API_URL
      - API_URL=http://api:8000
    depends_on:
      - api

volumes:
  postgres_data:
  redis_data:
EOF

    # Générer le fichier .env
    if [[ ! -f .env ]]; then
        POSTGRES_PASSWORD=$(openssl rand -hex 16)
        REDIS_PASSWORD=$(openssl rand -hex 16)
        SECRET_KEY=$(openssl rand -hex 32)
        API_KEY=$(openssl rand -base64 32)
        
        cat > .env << EOF
# VulnScope Environment Variables
# Généré automatiquement par setup-local-cloud.sh

# PostgreSQL
POSTGRES_PASSWORD=$POSTGRES_PASSWORD

# Redis
REDIS_PASSWORD=$REDIS_PASSWORD

# VulnScope
VULNSCOPE_SECRET_KEY=$SECRET_KEY
VULNSCOPE_API_KEY=$API_KEY
EOF
        
        success "Fichier .env généré avec des secrets aléatoires"
    fi
    
    success "docker-compose.local.yml généré"
}

# Afficher le résumé final
show_summary() {
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo "========================================"
    echo -e "${GREEN}      INSTALLATION TERMINÉE!${NC}"
    echo "========================================"
    echo ""
    echo "📊 Services installés:"
    echo "   • Docker:      $(docker --version)"
    echo "   • Coolify:     http://$LOCAL_IP:8000"
    echo "   • cloudflared: $(cloudflared --version)"
    echo ""
    
    if [[ -n "$DOMAIN" ]]; then
        echo "🌐 Accès public via Cloudflare:"
        echo "   • Coolify:   https://coolify.$DOMAIN"
        echo "   • VulnScope: https://vulnscope.$DOMAIN"
        echo "   • API:       https://api.$DOMAIN"
        echo ""
    fi
    
    echo "📋 Prochaines étapes:"
    echo "   1. Accédez à Coolify: http://$LOCAL_IP:8000"
    echo "   2. Créez votre compte administrateur"
    echo "   3. Configurez votre projet VulnScope"
    if [[ -z "$DOMAIN" ]]; then
        echo "   4. Configurez le tunnel Cloudflare:"
        echo "      cloudflared tunnel login"
        echo "      cloudflared tunnel create vulnscope-cloud"
    fi
    echo ""
    echo "📚 Documentation:"
    echo "   • DEPLOYMENT_LOCAL_CLOUDFLARE.md"
    echo "   • https://coolify.io/docs"
    echo ""
    echo "========================================"
}

# Fonction principale
main() {
    echo ""
    echo "========================================"
    echo "  VulnScope - Mini-Cloud Local Setup"
    echo "  Coolify + Cloudflare Tunnel"
    echo "========================================"
    echo ""
    
    parse_args "$@"
    check_root
    check_system
    update_system
    install_dependencies
    optimize_system
    install_docker
    install_coolify
    install_cloudflared
    configure_tunnel
    configure_firewall
    configure_fail2ban
    generate_docker_compose
    show_summary
}

# Exécuter
main "$@"