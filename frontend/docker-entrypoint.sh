#!/bin/sh
# Runtime configuration for VulnScope Frontend
# This script replaces placeholder values at runtime

# Default API URL if not set
API_URL=${API_URL:-http://localhost:8000}

# Replace the placeholder in the compiled JavaScript files
echo "Configuring API URL: $API_URL"
find /app/.next -type f -name "*.js" -exec sed -i "s|http://localhost:8000|$API_URL|g" {} \;

# Start the application
exec node server.js