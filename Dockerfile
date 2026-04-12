FROM node:20-alpine

WORKDIR /app

# Install dependencies first (cached layer)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy app source
COPY . .

# Data directory inside the container (mounted as a volume)
RUN mkdir -p /data/uploads

EXPOSE 8080

ENV PORT=8080 \
    DATA_FILE=/data/data.json \
    UPLOADS_DIR=/data/uploads

# Version injected at build time by GitHub Actions (tag name or short commit SHA)
ARG APP_VERSION=dev
ENV APP_VERSION=$APP_VERSION

CMD ["node", "server.js"]
