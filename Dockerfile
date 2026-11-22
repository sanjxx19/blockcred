# syntax=docker/dockerfile:1.7
# Multi-target image for the whole monorepo.
#   dev      -> everything (Hardhat, services, Vite dev server)  [used by docker-compose.yml]
#   service  -> production runtime for the API (no dev deps, non-root)
#   web      -> static web app served by nginx (proxies /api and /issuers to the API)

FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package*.json ./
COPY packages/sdk/package.json packages/sdk/
COPY contracts/package.json contracts/
COPY services/api/package.json services/api/
COPY apps/web/package.json apps/web/
RUN npm install --no-audit --no-fund

FROM deps AS dev
COPY . .
# Downloads the solc compiler and compiles contracts at build time
RUN npm run compile -w contracts

FROM deps AS web-build
COPY . .
ARG VITE_EXPLORER_TX_URL=
ENV VITE_EXPLORER_TX_URL=$VITE_EXPLORER_TX_URL
RUN npm run build -w apps/web

FROM nginx:1.27-alpine AS web
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=web-build /app/apps/web/dist /usr/share/nginx/html
EXPOSE 80

FROM node:22-bookworm-slim AS service
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps /app/package*.json ./
COPY packages/sdk packages/sdk
COPY services services
COPY --from=deps /app/node_modules node_modules
RUN npm prune --omit=dev --no-audit --no-fund || true
USER node
EXPOSE 4000
CMD ["node", "services/api/src/index.js"]
