FROM node:22-bookworm-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
# npm prebuild normalizes all vendor rasters to PNG, preserving originals.
RUN npm run build

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
RUN apt-get update && apt-get install -y --no-install-recommends util-linux && rm -rf /var/lib/apt/lists/*
COPY --from=build --chown=node:node /app ./
# The catalog-chunks feature publishes immutable objects before advertising a
# snapshot through /watch. This writable named volume must be owned by the
# unprivileged runtime user (also when Docker initializes a fresh volume).
RUN mkdir -p /app/provider-control /app/notices /app/catalog-snapshots /app/server-vpn-results \
 && chown node:node /app/provider-control /app/notices /app/catalog-snapshots /app/server-vpn-results \
 && chmod 0700 /app/provider-control /app/notices /app/catalog-snapshots /app/server-vpn-results
USER node
EXPOSE 3000
CMD ["npm", "run", "start"]
