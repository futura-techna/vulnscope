#!/bin/bash
set -e

echo "🚀 Déploiement VulnScope - Option Gratuite"
echo "=========================================="

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Vérifier si Docker est installé
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_info "Docker n'est pas installé. Installation en cours..."
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker $USER
        log_success "Docker installé avec succès"
        log_warning "Vous devrez peut-être vous déconnecter/reconnecter pour utiliser Docker sans sudo"
    else
        log_success "Docker est déjà installé"
    fi
}

# Vérifier si Docker Compose est disponible
check_docker_compose() {
    if docker compose version &> /dev/null; then
        log_success "Docker Compose est disponible"
    elif command -v docker-compose &> /dev/null; then
        log_info "docker-compose (v1) détecté, création d'un alias..."
        mkdir -p ~/.local/bin
        echo '#!/bin/bash' > ~/.local/bin/docker
        echo 'docker "$@"' >> ~/.local/bin/docker
        chmod +x ~/.local/bin/docker
    else
        log_info "Installation de Docker Compose..."
        sudo apt update && sudo apt install -y docker-compose-plugin
        log_success "Docker Compose installé"
    fi
}

# Générer les secrets
generate_secrets() {
    log_info "Génération des secrets sécurisés..."
    
    export VULNSCOPE_SECRET_KEY=$(openssl rand -hex 32)
    export VULNSCOPE_API_KEY=$(openssl rand -base64 32)
    export POSTGRES_PASSWORD=$(openssl rand -hex 16)
    export VULNSCOPE_REDIS__PASSWORD=$(openssl rand -hex 16)
    export MINIO_ROOT_USER="vulnscope"
    export MINIO_ROOT_PASSWORD=$(openssl rand -hex 16)
    
    log_success "Secrets générés"
}

# Créer le fichier .env
create_env_file() {
    log_info "Création du fichier .env..."
    
    # Supprimer l'ancien fichier s'il existe
    rm -f .env
    
    cat > .env << EOF
# VulnScope Environment Configuration
# Generated on $(date)

# Security
VULNSCOPE_SECRET_KEY=${VULNSCOPE_SECRET_KEY}
VULNSCOPE_API_KEY=${VULNSCOPE_API_KEY}
VULNSCOPE_ENVIRONMENT=production
VULNSCOPE_DEBUG=false

# Database
VULNSCOPE_DATABASE__URL=postgresql://vulnscope:${POSTGRES_PASSWORD}@db:5432/vulnscope
POSTGRES_USER=vulnscope
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=vulnscope

# Redis
VULNSCOPE_REDIS__HOST=redis
VULNSCOPE_REDIS__PORT=6379
VULNSCOPE_REDIS__PASSWORD=${VULNSCOPE_REDIS__PASSWORD}

# MinIO Storage
MINIO_ROOT_USER=${MINIO_ROOT_USER}
MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}

# Frontend
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
API_URL=http://localhost:8000
EOF

    chmod 600 .env
    log_success "Fichier .env créé avec permissions sécurisées"
}

# Démarrer les services
start_services() {
    log_info "Démarrage des conteneurs Docker..."
    
    # Arrêter les anciens conteneurs s'ils existent
    docker compose down --remove-orphans 2>/dev/null || true
    
    # Démarrer les nouveaux conteneurs
    docker compose up -d
    
    log_success "Conteneurs démarrés"
}

# Attendre que les services soient prêts
wait_for_services() {
    log_info "Attente du démarrage des services..."
    
    local max_attempts=60
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
            log_success "L'API est prête!"
            return 0
        fi
        
        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done
    
    echo ""
    log_warning "L'API met plus de temps que prévu à démarrer"
    log_info "Vérifiez les logs avec: docker compose logs api"
    return 1
}

# Afficher le résumé
show_summary() {
    echo ""
    echo "========================================"
    echo -e "${GREEN}✅ Déploiement terminé avec succès!${NC}"
    echo "========================================"
    echo ""
    echo "📍 URLs d'accès:"
    echo "   ┌─────────────────────────────────────"
    echo "   │ Frontend:      http://localhost:3000"
    echo "   │ API:           http://localhost:8000"
    echo "   │ API Docs:      http://localhost:8000/docs"
    echo "   │ MinIO Console: http://localhost:9001"
    echo "   │ Adminer:       http://localhost:8080"
    echo "   └─────────────────────────────────────"
    echo ""
    echo "🔐 Les secrets ont été générés dans .env"
    echo "   Consultez avec: cat .env"
    echo ""
    echo "📋 Commandes utiles:"
    echo "   ┌─────────────────────────────────────────────────────"
    echo "   │ Voir les logs:     docker compose logs -f"
    echo "   │ Arrêter:           docker compose down"
    echo "   │ Redémarrer:        docker compose restart"
    echo "   │ État des services: docker compose ps"
    echo "   └─────────────────────────────────────────────────────"
    echo ""
}

# Menu interactif pour les options de déploiement
show_menu() {
    echo ""
    echo "🌟 Options de déploiement VulnScope"
    echo "===================================="
    echo ""
    echo "1) Déploiement local (Docker Compose)"
    echo "2) Préparer pour Coolify"
    echo "3) Préparer pour Cloudflare Tunnel"
    echo "4) Préparer pour k3s (Kubernetes)"
    echo "5) Afficher les informations VPS gratuits"
    echo "6) Quitter"
    echo ""
    read -p "Choisissez une option [1-6]: " choice
    
    case $choice in
        1)
            deploy_local
            ;;
        2)
            prepare_coolify
            ;;
        3)
            prepare_cloudflare
            ;;
        4)
            prepare_k3s
            ;;
        5)
            show_free_vps_info
            ;;
        6)
            echo "Au revoir!"
            exit 0
            ;;
        *)
            log_error "Option invalide"
            show_menu
            ;;
    esac
}

# Déploiement local
deploy_local() {
    log_info "Déploiement local en cours..."
    check_docker
    check_docker_compose
    generate_secrets
    create_env_file
    start_services
    wait_for_services
    show_summary
}

# Préparation Coolify
prepare_coolify() {
    log_info "Préparation pour Coolify..."
    echo ""
    echo "📋 Instructions pour Coolify:"
    echo "================================"
    echo ""
    echo "1. Installez Coolify sur votre VPS:"
    echo "   curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash"
    echo ""
    echo "2. Accédez à l'interface: https://votre-ip:3000"
    echo ""
    echo "3. Créez un nouveau projet 'VulnScope'"
    echo ""
    echo "4. Ajoutez les ressources dans cet ordre:"
    echo "   a) PostgreSQL Database"
    echo "   b) Redis Database"
    echo "   c) Application API (depuis Git)"
    echo "   d) Application Frontend (depuis Git)"
    echo ""
    echo "5. Variables d'environnement à configurer:"
    echo ""
    generate_secrets
    echo "   VULNSCOPE_SECRET_KEY=${VULNSCOPE_SECRET_KEY}"
    echo "   VULNSCOPE_API_KEY=${VULNSCOPE_API_KEY}"
    echo "   POSTGRES_PASSWORD=${POSTGRES_PASSWORD}"
    echo "   VULNSCOPE_REDIS__PASSWORD=${VULNSCOPE_REDIS__PASSWORD}"
    echo ""
}

# Préparation Cloudflare Tunnel
prepare_cloudflare() {
    log_info "Préparation pour Cloudflare Tunnel..."
    echo ""
    echo "📋 Instructions pour Cloudflare Tunnel:"
    echo "========================================"
    echo ""
    echo "1. Installez cloudflared:"
    echo "   curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared"
    echo "   chmod +x cloudflared && sudo mv cloudflared /usr/local/bin/"
    echo ""
    echo "2. Authentifiez-vous:"
    echo "   cloudflared tunnel login"
    echo ""
    echo "3. Créez le tunnel:"
    echo "   cloudflared tunnel create vulnscope"
    echo ""
    echo "4. Configurez le DNS:"
    echo "   cloudflared tunnel route dns vulnscope vulnscope.votre-domaine.com"
    echo "   cloudflared tunnel route dns vulnscope api.vulnscope.votre-domaine.com"
    echo ""
    echo "5. Déployez VulnScope localement:"
    echo "   ./deploy-free.sh (option 1)"
    echo ""
    echo "6. Démarrez le tunnel:"
    echo "   cloudflared tunnel run vulnscope"
    echo ""
}

# Préparation k3s
prepare_k3s() {
    log_info "Préparation pour k3s..."
    echo ""
    echo "📋 Instructions pour k3s (Kubernetes léger):"
    echo "=============================================="
    echo ""
    echo "1. Installez k3s sur votre VPS:"
    echo "   curl -sfL https://get.k3s.io | sh -"
    echo ""
    echo "2. Récupérez le kubeconfig:"
    echo "   sudo cat /etc/rancher/k3s/k3s.yaml > ~/.kube/config"
    echo "   chmod 600 ~/.kube/config"
    echo ""
    echo "3. Créez les fichiers Kubernetes dans le dossier k8s/"
    echo ""
    echo "4. Déployez:"
    echo "   kubectl apply -f k8s/"
    echo ""
    echo "5. Vérifiez le déploiement:"
    echo "   kubectl get pods -n vulnscope"
    echo ""
}

# Afficher les informations sur les VPS gratuits
show_free_vps_info() {
    echo ""
    echo "🆓 VPS Gratuits Disponibles"
    echo "==========================="
    echo ""
    echo "┌─────────────────────┬──────────────────────┬──────────┬─────────────────────┐"
    echo "│ Provider            │ Specs                │ Durée    │ Restrictions        │"
    echo "├─────────────────────┼──────────────────────┼──────────┼─────────────────────┤"
    echo "│ Oracle Cloud        │ 4 ARM CPU, 24GB RAM  │ Illimité │ Carte crédit req.   │"
    echo "│ Google Cloud        │ e2-micro             │ Illimité │ 1 instance max      │"
    echo "│ AWS                 │ t2.micro             │ 12 mois  │ 750h/mois           │"
    echo "│ Azure               │ B1s                  │ 12 mois  │ 750h/mois           │"
    echo "│ Fly.io              │ 3 VMs partagées      │ Illimité │ Crédit gratuit      │"
    echo "│ Railway             │ $5/mois crédit       │ Illimité │ Limité              │"
    echo "└─────────────────────┴──────────────────────┴──────────┴─────────────────────┘"
    echo ""
    echo "🏆 Recommandation: Oracle Cloud Free Tier"
    echo "   C'est le plus généreux avec 4 CPU ARM et 24GB RAM gratuits à vie!"
    echo ""
    echo "   Lien: https://www.oracle.com/cloud/free/"
    echo ""
}

# Point d'entrée principal
main() {
    # Si un argument est passé, exécuter directement
    if [ "$1" = "--local" ]; then
        deploy_local
        exit 0
    fi
    
    # Sinon, afficher le menu interactif
    show_menu
}

# Exécuter le script
main "$@"