# Debian (glibc) so better-sqlite3 uses its prebuilt binary — no compiler needed.
FROM node:22-slim

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=4700
ENV SW_DATA_DIR=/app/data

COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

RUN mkdir -p /app/data
VOLUME ["/app/data"]

EXPOSE 4700

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:4700/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
