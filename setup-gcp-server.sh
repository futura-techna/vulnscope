#!/bin/bash
# Script de configuration du serveur Google Cloud pour VulnScope
# À exécuter sur le VPS GCP après création

set -e

echo "🚀 Configuration du serveur Google Cloud pour VulnScope"
echo "======================================================"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Demander les informations
read -p "Entrez votre token DuckDNS: " DUCKDNS_TOKEN
read -p "Entrez votre sous-domaine DuckDNS (ex: vulnscope): " DUCKDNS_DOMAIN
read -p "Entrez votre email pour Let's Encrypt: " SSL_EMAIL

# 1. Mettre à jour le système
log_info "Mise à jour du système..."
sudo apt update && sudo apt upgrade -y

# 2. Installer les outils nécessaires
log_info "Installation des outils..."
sudo apt install -y curl wget git htop fail2ban

# 3. Installer Docker
log_info "Installation de Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker $USER
    log_success "Docker installé"
else
    log_success "Docker déjà installé"
fi

# 4. Créer le fichier swap (important pour e2-micro avec 1GB RAM)
log_info "Configuration du swap (2GB)..."
if [ ! -f /swapfile ]; then
    sudo fallocate -l 2G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
    log_success "Swap configuré"
else
    log_success "Swap déjà configuré"
fi

# 5. Optimiser la mémoire
log_info "Optimisation de la mémoire..."
sudo sysctl vm.swappiness=10
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf

# 6. Installer Coolify
log_info "Installation de Coolify..."
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash

# 7. Configurer DuckDNS
log_info "Configuration de DuckDNS..."
cat > ~/duckdns.sh << EOF
#!/bin/bash
TOKEN="${DUCKDNS_TOKEN}"
DOMAIN="${DUCKDNS_DOMAIN}"
CURRENT_IP=\$(curl -s https://api.ipify.org)
curl -s "https://www.duckdns.org/update?domains=\${DOMAIN}&token=\${TOKEN}&ip=\${CURRENT_IP}"
EOF
chmod +x ~/duckdns.sh

# Tester DuckDNS
~/duckdns.sh

# Ajouter au crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * $HOME/duckdns.sh > /dev/null 2>&1") | crontab -

# 8. Configurer le pare-feu
log_info "Configuration du pare-feu..."
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP
sudo ufw allow 443/tcp     # HTTPS
sudo ufw allow 8000/tcp    # Coolify
sudo ufw --force enable

# 9. Configurer fail2ban
log_info "Configuration de fail2ban..."
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# 10. Afficher le résumé
IP=$(curl -s https://api.ipify.org)

echo ""
echo "========================================"
echo -e "${GREEN}✅ Configuration terminée!${NC}"
echo "========================================"
echo ""
echo "📍 URLs d'accès:"
echo "   Coolify Dashboard: http://${IP}:8000"
echo "   Domaine DuckDNS:   ${DUCKDNS_DOMAIN}.duckdns.org"
echo ""
echo "📋 Prochaines étapes:"
echo "   1. Accédez à http://${IP}:8000"
echo "   2. Créez votre compte administrateur Coolify"
echo "   3. Configurez le domaine: ${DUCKDNS_DOMAIN}.duckdns.org"
echo "   4. Activez SSL avec Let's Encrypt (email: ${SSL_EMAIL})"
echo "   5. Déployez VulnScope (voir DEPLOYMENT_GCP_COOLIFY.md)"
echo ""
echo "🔧 Commandes utiles:"
echo "   Logs Coolify:     docker logs coolify"
echo "   État Docker:      docker ps"
echo "   Mémoire:          free -h"
echo "   Mettre à jour IP: ~/duckdns.sh"
echo ""
echo "⚠️  Note: Déconnectez-vous et reconnectez-vous pour utiliser Docker sans sudo"
echo ""