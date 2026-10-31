FROM node:22-bookworm-slim
WORKDIR /app
COPY cloud/web/package.json ./
RUN npm pkg set overrides.tslib=2.8.1 && npm install --no-audit --no-fund --ignore-scripts --no-package-lock
COPY cloud/web/lib ./lib
# This isolated staging process exposes no ports and uses synthetic keys only.
CMD ["node", "-e", "setInterval(()=>{},1000)"]
