# Optimized Dockerfile for Render free tier (limited memory)
# Uses standalone output and minimal dependencies

FROM node:20-alpine AS deps
WORKDIR /app

# Install dependencies only
COPY package.json ./
RUN npm install --no-audit --no-fund

# Build stage
FROM node:20-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Set environment variables for build
ENV NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production
ENV PORT=3000

# Build with memory optimization
RUN NODE_OPTIONS="--max-old-space-size=2048" npm run build

# Production image - minimal size using standalone output
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy standalone output (much smaller)
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Use standalone server
CMD ["node", "server.js"]