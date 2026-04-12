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

CMD ["node", "server.js"]
