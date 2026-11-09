FROM node:22-bookworm-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . .
# Keep the vendor WebP unchanged and publish a PNG compatible with Android's
# verified icon cache and the content-addressed catalog snapshot validator.
RUN apt-get update \
 && apt-get install -y --no-install-recommends webp \
 && dwebp public/server-vpn-icons/md-proxy-vpn.webp -o public/server-vpn-icons/md-proxy-vpn.png \
 && node -e 'const b=require("node:fs").readFileSync("public/server-vpn-icons/md-proxy-vpn.png");if(b.subarray(0,8).toString("hex")!=="89504e470d0a1a0a")process.exit(1)' \
 && rm -rf /var/lib/apt/lists/*
RUN npm run build

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
RUN apt-get update && apt-get install -y --no-install-recommends util-linux && rm -rf /var/lib/apt/lists/*
COPY --from=build --chown=node:node /app ./
# The catalog-chunks feature publishes immutable objects before advertising a
# snapshot through /watch. This writable named volume must be owned by the
# unprivileged runtime user (also when Docker initializes a fresh volume).
RUN mkdir -p /app/provider-control /app/notices /app/catalog-snapshots \
 && chown node:node /app/provider-control /app/notices /app/catalog-snapshots \
 && chmod 0700 /app/provider-control /app/notices /app/catalog-snapshots
USER node
EXPOSE 3000
CMD ["npm", "run", "start"]
