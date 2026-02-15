#!/bin/bash

DOMAIN="vulnscope.example.com"
EMAIL="admin@example.com"

echo "🛑 Arrêt temporaire de Nginx pour libérer le port 80..."
docker compose stop nginx

echo "🔐 Génération du certificat Let's Encrypt..."
docker run --rm \
  -p 80:80 \
  -v ./ssl:/etc/letsencrypt \
  certbot/certbot certonly \
  --standalone \
  -d $DOMAIN \
  --email $EMAIL \
  --agree-tos \
  --non-interactive

echo "🚀 Redémarrage de Nginx..."
docker compose start nginx

echo "📁 Certificats disponibles dans ./ssl/live/$DOMAIN/"
echo "  - fullchain.pem"
echo "  - privkey.pem"

echo "🔁 Pour renouveler automatiquement, ajouter dans crontab :"
echo "0 3 * * * docker run --rm -p 80:80 -v ./ssl:/etc/letsencrypt certbot/certbot renew && docker compose restart nginx"
