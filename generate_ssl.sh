#!/bin/bash

DOMAIN="vulnscope.duckdns.org"
EMAIL="mamesalioucisse@gmail.com"

echo "🛑 Arrêt temporaire de Nginx pour libérer le port 80..."
docker compose -f docker-compose.prod.yml stop nginx

echo "🔐 Génération du certificat Let's Encrypt pour $DOMAIN..."
docker run --rm \
  -p 80:80 \
  -v $(pwd)/ssl:/etc/letsencrypt \
  certbot/certbot certonly \
  --standalone \
  -d $DOMAIN \
  --email $EMAIL \
  --agree-tos \
  --non-interactive

echo "🚀 Redémarrage de Nginx..."
docker compose -f docker-compose.prod.yml start nginx

echo "📁 Certificats disponibles dans ./ssl/live/$DOMAIN/"
echo "  - fullchain.pem"
echo "  - privkey.pem"

echo "🔁 Pour renouveler automatiquement, ajoute dans crontab :"
echo "0 3 * * * docker run --rm -p 80:80 -v $(pwd)/ssl:/etc/letsencrypt certbot/certbot renew && docker compose -f docker-compose.prod.yml restart nginx"
