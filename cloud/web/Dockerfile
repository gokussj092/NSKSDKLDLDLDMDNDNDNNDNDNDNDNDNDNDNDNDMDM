FROM node:22-bookworm-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
COPY --from=build --chown=node:node /app ./
RUN mkdir -p /app/provider-control /app/notice-feed && chown node:node /app/provider-control /app/notice-feed && chmod 0700 /app/provider-control /app/notice-feed
USER node
EXPOSE 3000
CMD ["npm", "run", "start"]
