#!/bin/bash

DOMAIN="vulnscope.example.com"
EMAIL="admin@example.com"
COMPOSE_FILE="docker-compose.prod.yml"

echo "=========================================="
echo " 🔐 SSL Certificate Generation"
echo "=========================================="

# Check if port 80 is already in use
if lsof -i :80 > /dev/null 2>&1; then
    echo "⚠️  Port 80 is in use. Attempting to free it..."
    
    # Stop nginx if it's using port 80
    docker compose -f $COMPOSE_FILE stop nginx 2>/dev/null
    sleep 2
    
    # Check again
    if lsof -i :80 > /dev/null 2>&1; then
        echo "❌ Port 80 is still in use. Please stop the conflicting service manually."
        echo "   Running services on port 80:"
        lsof -i :80
        exit 1
    fi
fi

echo "🔐 Génération du certificat Let's Encrypt..."
docker run --rm \
  --p 80:80 \
  -v ./ssl:/etc/letsencrypt \
  certbot/certbot certonly \
  --standalone \
  -d $DOMAIN \
  --email $EMAIL \
  --agree-tos \
  --non-interactive

if [ $? -eq 0 ]; then
    echo "✅ Certificat généré avec succès !"
    echo "📁 Certificats disponibles dans ./ssl/live/$DOMAIN/"
    echo "   - fullchain.pem"
    echo "   - privkey.pem"
    
    # Restart nginx
    echo "🚀 Redémarrage de Nginx..."
    docker compose -f $COMPOSE_FILE start nginx
    
    # Update nginx config to use SSL
    if [ -f "./ssl/live/$DOMAIN/fullchain.pem" ]; then
        echo "✅ SSL certificates are ready for use!"
    fi
else
    echo "❌ Échec de la génération du certificat"
    exit 1
fi

echo ""
echo "🔁 Pour renouveler automatiquement, ajouter dans crontab :"
echo "0 3 * * * cd $(pwd) && ./generate_ssl.sh"
