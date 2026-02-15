#!/bin/bash

ENV_FILE=".env"

echo "=========================================="
echo " 🔐 VulnScope - Génération automatique .env"
echo "=========================================="

# Vérification si .env existe déjà
if [ -f "$ENV_FILE" ]; then
    read -p ".env existe déjà. Écraser ? (y/n) : " confirm
    if [ "$confirm" != "y" ]; then
        echo "❌ Annulé."
        exit 1
    fi
fi

echo "🧪 Génération des secrets..."

VULNSCOPE_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
VULNSCOPE_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(16))")
REDIS_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(16))")

# Optionnel : MinIO
read -p "Activer MinIO (S3-compatible) ? (y/n) : " use_minio
if [ "$use_minio" = "y" ]; then
    MINIO_ROOT_USER=$(python3 -c "import secrets; print(secrets.token_hex(8))")
    MINIO_ROOT_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(16))")
fi

echo "📄 Création du fichier .env..."

cat > $ENV_FILE <<EOF
# ============================================
# VulnScope Production Environment File
# ============================================

# --- Core Secrets ---
VULNSCOPE_SECRET_KEY=$VULNSCOPE_SECRET_KEY
VULNSCOPE_API_KEY=$VULNSCOPE_API_KEY

# --- Database ---
POSTGRES_USER=vulnscope
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=vulnscope
VULNSCOPE_DATABASE__URL=postgresql://vulnscope:$POSTGRES_PASSWORD@db:5432/vulnscope

# --- Redis ---
VULNSCOPE_REDIS__HOST=redis
VULNSCOPE_REDIS__PORT=6379
VULNSCOPE_REDIS__PASSWORD=$REDIS_PASSWORD

# --- Dashboard ---
STREAMLIT_SERVER_PORT=8501

EOF

if [ "$use_minio" = "y" ]; then
cat >> $ENV_FILE <<EOF

# --- MinIO (S3 Storage) ---
MINIO_ROOT_USER=$MINIO_ROOT_USER
MINIO_ROOT_PASSWORD=$MINIO_ROOT_PASSWORD
VULNSCOPE_S3_ENDPOINT=http://minio:9000
VULNSCOPE_S3_BUCKET=vulnscope
EOF
fi

echo "✅ Fichier .env généré avec succès !"
echo "📁 Chemin : $(pwd)/.env"
