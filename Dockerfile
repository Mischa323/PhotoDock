FROM node:20-slim

# python3 + git for PlatformIO; fonts + fontconfig so server-side SVG text
# rendering (sharp) has fonts to draw with — without them the device status
# screens render text as empty boxes (tofu).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       python3 python3-pip git fonts-dejavu-core fontconfig \
    && fc-cache -f \
    && rm -rf /var/lib/apt/lists/*

# PlatformIO CLI
RUN pip3 install --break-system-packages platformio

WORKDIR /app

# Install Node.js dependencies first (cached layer)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy app source
COPY . .

# Data directory inside the container (mounted as a volume)
RUN mkdir -p /data/uploads

EXPOSE 8080
EXPOSE 8081

ENV PORT=8080 \
    HTTPS_PORT=8081 \
    SSL_CERT=/data/ssl/cert.pem \
    SSL_KEY=/data/ssl/key.pem \
    DATA_FILE=/data/data.json \
    UPLOADS_DIR=/data/uploads

# Version injected at build time by GitHub Actions (tag name or short commit SHA)
ARG APP_VERSION=dev
ENV APP_VERSION=$APP_VERSION

CMD ["node", "backend/server.js"]
