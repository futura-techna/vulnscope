#!/bin/bash

#==============================================================================
# VulnScope - Cloudflare Tunnel Manager
#==============================================================================
# Script de gestion des tunnels Cloudflare
#
# Usage: ./tunnel-manager.sh [COMMAND] [OPTIONS]
#
# Commandes:
#   setup       - Configurer un nouveau tunnel
#   start       - Démarrer le tunnel
#   stop        - Arrêter le tunnel
#   status      - Vérifier le statut du tunnel
#   logs        - Voir les logs du tunnel
#   add-route   - Ajouter une route DNS
#   remove-route- Supprimer une route DNS
#   list        - Lister tous les tunnels
#   delete      - Supprimer le tunnel
#   info        - Afficher les informations du tunnel
#==============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Variables par défaut
TUNNEL_NAME="vulnscope-cloud"
CONFIG_DIR="/etc/cloudflared"
CONFIG_FILE="${CONFIG_DIR}/config.yml"
SERVICE_NAME="cloudflared"

# Fonctions d'affichage
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
header() { echo -e "${CYAN}$1${NC}"; }

# Vérifier que cloudflared est installé
check_cloudflared() {
    if ! command -v cloudflared &> /dev/null; then
        error "cloudflared n'est pas installé. Installez-le avec:\n  curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb\n  sudo dpkg -i cloudflared.deb"
    fi
}

# Vérifier l'authentification
check_auth() {
    if [[ ! -d ~/.cloudflared ]]; then
        warning "Non authentifié à Cloudflare."
        info "Lancement de l'authentification..."
        cloudflared tunnel login
    fi
}

# Obtenir l'ID du tunnel
get_tunnel_id() {
    cloudflared tunnel list 2>/dev/null | grep "$TUNNEL_NAME" | awk '{print $1}' || echo ""
}

# Obtenir le domaine depuis la config
get_domain() {
    if [[ -f "$CONFIG_FILE" ]]; then
        grep "hostname:" "$CONFIG_FILE" | head -1 | sed 's/.*hostname: //' | cut -d'.' -f2-
    else
        echo ""
    fi
}

# Commande: setup
cmd_setup() {
    local domain="$1"
    
    if [[ -z "$domain" ]]; then
        read -p "Entrez votre domaine (ex: mondomaine.com): " domain
    fi
    
    header "========================================"
    header "  Configuration du tunnel Cloudflare"
    header "========================================"
    echo ""
    
    check_cloudflared
    check_auth
    
    # Créer le tunnel
    info "Création du tunnel '$TUNNEL_NAME'..."
    local tunnel_id=$(get_tunnel_id)
    
    if [[ -n "$tunnel_id" ]]; then
        warning "Le tunnel '$TUNNEL_NAME' existe déjà (ID: $tunnel_id)"
    else
        cloudflared tunnel create "$TUNNEL_NAME"
        tunnel_id=$(get_tunnel_id)
        success "Tunnel créé avec l'ID: $tunnel_id"
    fi
    
    # Créer le répertoire de config
    sudo mkdir -p "$CONFIG_DIR"
    
    # Générer la configuration
    info "Génération de la configuration..."
    sudo tee "$CONFIG_FILE" << EOF
# Configuration du tunnel Cloudflare pour VulnScope
# Généré le $(date)

tunnel: $tunnel_id
credentials-file: /home/$USER/.cloudflared/$tunnel_id.json

ingress:
  # Coolify Dashboard
  - hostname: coolify.$domain
    service: http://localhost:8000

  # VulnScope Frontend
  - hostname: vulnscope.$domain
    service: http://localhost:3000

  # VulnScope API
  - hostname: api.$domain
    service: http://localhost:8001

  # Règle par défaut
  - service: http_status:404
EOF
    
    success "Configuration créée: $CONFIG_FILE"
    
    # Créer les enregistrements DNS
    info "Création des enregistrements DNS..."
    cloudflared tunnel route dns "$TUNNEL_NAME" "coolify.$domain" || true
    cloudflared tunnel route dns "$TUNNEL_NAME" "vulnscope.$domain" || true
    cloudflared tunnel route dns "$TUNNEL_NAME" "api.$domain" || true
    
    success "Enregistrements DNS créés"
    
    # Installer comme service
    info "Installation du service système..."
    sudo cloudflared service install
    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    
    success "Service installé"
    
    echo ""
    header "========================================"
    success "Configuration terminée!"
    header "========================================"
    echo ""
    echo "Vos services sont accessibles via:"
    echo -e "  ${GREEN}Coolify:${NC}   https://coolify.$domain"
    echo -e "  ${GREEN}VulnScope:${NC} https://vulnscope.$domain"
    echo -e "  ${GREEN}API:${NC}       https://api.$domain"
    echo ""
    echo "Démarrez le tunnel avec:"
    echo "  ./tunnel-manager.sh start"
    echo ""
}

# Commande: start
cmd_start() {
    check_cloudflared
    
    if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
        warning "Le tunnel est déjà en cours d'exécution"
        return 0
    fi
    
    info "Démarrage du tunnel..."
    sudo systemctl start "$SERVICE_NAME"
    sleep 2
    
    if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
        success "Tunnel démarré avec succès"
        cmd_status
    else
        error "Échec du démarrage du tunnel. Vérifiez les logs avec: ./tunnel-manager.sh logs"
    fi
}

# Commande: stop
cmd_stop() {
    check_cloudflared
    
    if ! sudo systemctl is-active --quiet "$SERVICE_NAME"; then
        warning "Le tunnel n'est pas en cours d'exécution"
        return 0
    fi
    
    info "Arrêt du tunnel..."
    sudo systemctl stop "$SERVICE_NAME"
    success "Tunnel arrêté"
}

# Commande: restart
cmd_restart() {
    check_cloudflared
    
    info "Redémarrage du tunnel..."
    sudo systemctl restart "$SERVICE_NAME"
    sleep 2
    success "Tunnel redémarré"
    cmd_status
}

# Commande: status
cmd_status() {
    check_cloudflared
    
    header "========================================"
    header "  Statut du Tunnel Cloudflare"
    header "========================================"
    echo ""
    
    # Statut du service
    if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "Service:    ${GREEN}● Actif${NC}"
    else
        echo -e "Service:    ${RED}○ Inactif${NC}"
    fi
    
    # Informations du tunnel
    local tunnel_id=$(get_tunnel_id)
    if [[ -n "$tunnel_id" ]]; then
        echo "Tunnel:     $TUNNEL_NAME"
        echo "ID:         $tunnel_id"
    else
        echo -e "Tunnel:     ${YELLOW}Non configuré${NC}"
    fi
    
    # Domaine
    local domain=$(get_domain)
    if [[ -n "$domain" ]]; then
        echo "Domaine:    $domain"
    fi
    
    echo ""
    
    # Tester la connectivité
    if sudo systemctl is-active --quiet "$SERVICE_NAME" && [[ -n "$domain" ]]; then
        info "Test de connectivité..."
        
        if curl -s --max-time 5 "https://coolify.$domain" > /dev/null 2>&1; then
            echo -e "Connectivité: ${GREEN}✓ OK${NC}"
        else
            echo -e "Connectivité: ${YELLOW}⚠ En attente...${NC}"
            echo "             (Le tunnel peut prendre quelques secondes pour être prêt)"
        fi
    fi
    
    echo ""
}

# Commande: logs
cmd_logs() {
    check_cloudflared
    
    local lines="${1:-50}"
    info "Affichage des $lines dernières lignes de logs..."
    sudo journalctl -u "$SERVICE_NAME" -n "$lines" --no-pager
}

# Commande: logs-follow
cmd_logs_follow() {
    check_cloudflared
    info "Suivi des logs en temps réel (Ctrl+C pour quitter)..."
    sudo journalctl -u "$SERVICE_NAME" -f
}

# Commande: add-route
cmd_add_route() {
    local hostname="$1"
    
    if [[ -z "$hostname" ]]; then
        read -p "Entrez le hostname (ex: app.mondomaine.com): " hostname
    fi
    
    local port="$2"
    if [[ -z "$port" ]]; then
        read -p "Entrez le port local (ex: 8080): " port
    fi
    
    check_cloudflared
    
    info "Ajout de la route DNS..."
    cloudflared tunnel route dns "$TUNNEL_NAME" "$hostname"
    
    # Ajouter à la config
    if [[ -f "$CONFIG_FILE" ]]; then
        info "Mise à jour de la configuration..."
        
        # Créer une sauvegarde
        sudo cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
        
        # Ajouter la nouvelle règle avant le catch-all
        sudo sed -i "/- service: http_status:404/i\\
  - hostname: $hostname\\
    service: http://localhost:$port" "$CONFIG_FILE"
        
        success "Route ajoutée: $hostname -> localhost:$port"
        
        # Redémarrer le service
        if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
            info "Redémarrage du tunnel..."
            sudo systemctl restart "$SERVICE_NAME"
        fi
    fi
}

# Commande: remove-route
cmd_remove_route() {
    local hostname="$1"
    
    if [[ -z "$hostname" ]]; then
        error "Spécifiez le hostname à supprimer"
    fi
    
    check_cloudflared
    
    if [[ -f "$CONFIG_FILE" ]]; then
        info "Suppression de la route..."
        
        # Créer une sauvegarde
        sudo cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
        
        # Supprimer la règle (2 lignes)
        sudo sed -i "/hostname: $hostname/d" "$CONFIG_FILE"
        sudo sed -i "/service: http:\/\/localhost:/d" "$CONFIG_FILE" || true
        
        success "Route supprimée: $hostname"
        
        # Redémarrer le service
        if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
            sudo systemctl restart "$SERVICE_NAME"
        fi
    fi
}

# Commande: list
cmd_list() {
    check_cloudflared
    
    header "========================================"
    header "  Tunnels Cloudflare"
    header "========================================"
    echo ""
    
    cloudflared tunnel list
    
    echo ""
}

# Commande: delete
cmd_delete() {
    check_cloudflared
    
    warning "⚠️  Cette action va supprimer le tunnel '$TUNNEL_NAME'"
    read -p "Êtes-vous sûr? (yes/N): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        info "Annulé"
        return 0
    fi
    
    # Arrêter le service
    if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
        sudo systemctl stop "$SERVICE_NAME"
    fi
    
    # Supprimer le tunnel
    info "Suppression du tunnel..."
    cloudflared tunnel delete "$TUNNEL_NAME" || true
    
    # Supprimer la config
    if [[ -f "$CONFIG_FILE" ]]; then
        sudo rm "$CONFIG_FILE"
    fi
    
    # Désactiver le service
    sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    
    success "Tunnel supprimé"
}

# Commande: info
cmd_info() {
    check_cloudflared
    
    header "========================================"
    header "  Informations du Tunnel"
    header "========================================"
    echo ""
    
    local tunnel_id=$(get_tunnel_id)
    
    if [[ -z "$tunnel_id" ]]; then
        warning "Aucun tunnel configuré"
        echo ""
        echo "Créez un tunnel avec:"
        echo "  ./tunnel-manager.sh setup mondomaine.com"
        return 0
    fi
    
    cloudflared tunnel info "$TUNNEL_NAME"
    
    echo ""
    echo "Configuration: $CONFIG_FILE"
    echo ""
    
    if [[ -f "$CONFIG_FILE" ]]; then
        echo "Routes configurées:"
        grep "hostname:" "$CONFIG_FILE" | sed 's/^/  /'
    fi
    
    echo ""
}

# Commande: test
cmd_test() {
    check_cloudflared
    
    local domain=$(get_domain)
    
    if [[ -z "$domain" ]]; then
        error "Aucun domaine configuré"
    fi
    
    header "========================================"
    header "  Test de connectivité"
    header "========================================"
    echo ""
    
    local hosts=("coolify" "vulnscope" "api")
    
    for host in "${hosts[@]}"; do
        local url="https://${host}.${domain}"
        echo -n "Testing $url... "
        
        if curl -s --max-time 5 -o /dev/null -w "%{http_code}" "$url" | grep -q "200\|301\|302\|401\|403"; then
            echo -e "${GREEN}✓ OK${NC}"
        else
            echo -e "${RED}✗ Failed${NC}"
        fi
    done
    
    echo ""
}

# Afficher l'aide
show_help() {
    header "========================================"
    header "  VulnScope - Tunnel Manager"
    header "========================================"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commandes:"
    echo "  setup [DOMAIN]       Configurer un nouveau tunnel"
    echo "  start               Démarrer le tunnel"
    echo "  stop                Arrêter le tunnel"
    echo "  restart             Redémarrer le tunnel"
    echo "  status              Vérifier le statut"
    echo "  logs [N]            Afficher les N dernières lignes de logs (défaut: 50)"
    echo "  logs-follow         Suivre les logs en temps réel"
    echo "  add-route [HOST] [PORT]  Ajouter une route DNS"
    echo "  remove-route [HOST] Supprimer une route DNS"
    echo "  list                Lister tous les tunnels"
    echo "  delete              Supprimer le tunnel"
    echo "  info                Afficher les informations du tunnel"
    echo "  test                Tester la connectivité"
    echo "  help                Afficher cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0 setup mondomaine.com"
    echo "  $0 add-route grafana.mondomaine.com 3001"
    echo "  $0 logs 100"
    echo ""
}

# Main
case "${1:-help}" in
    setup)
        cmd_setup "$2"
        ;;
    start)
        cmd_start
        ;;
    stop)
        cmd_stop
        ;;
    restart)
        cmd_restart
        ;;
    status)
        cmd_status
        ;;
    logs)
        cmd_logs "${2:-50}"
        ;;
    logs-follow)
        cmd_logs_follow
        ;;
    add-route)
        cmd_add_route "$2" "$3"
        ;;
    remove-route)
        cmd_remove_route "$2"
        ;;
    list)
        cmd_list
        ;;
    delete)
        cmd_delete
        ;;
    info)
        cmd_info
        ;;
    test)
        cmd_test
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        error "Commande inconnue: $1. Utilisez 'help' pour voir les commandes disponibles."
        ;;
esac