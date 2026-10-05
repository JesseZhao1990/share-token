FROM node:24-bookworm-slim AS build
WORKDIR /source
ENV npm_config_registry=https://registry.npmjs.org
# Hub packaging uses TypeScript and Vite but does not need Electron's download
# or node-pty's native build. The runtime stage receives only the checked payload.
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json LICENSE NOTICE THIRD_PARTY_NOTICES.md ./
COPY third_party ./third_party
COPY apps ./apps
COPY packages ./packages
COPY scripts/package-hub.mjs ./scripts/package-hub.mjs
RUN node scripts/package-hub.mjs \
    && mkdir /payload \
    && tar -xzf artifacts/hub/share-token-hub-*.tar.gz -C /payload

FROM node:24-bookworm-slim
ENV NODE_ENV=production HUB_DATA_DIR=/data
WORKDIR /app
# A volume lock is needed because a restarted container can reuse the previous
# process ID recorded by SQLite. It also excludes a second container on /data.
RUN apt-get update \
    && apt-get install -y --no-install-recommends util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /data && chown node:node /data && chmod 700 /data
COPY --from=build --chown=node:node /payload/ ./
COPY --chown=node:node deploy/hub/start.mjs deploy/hub/healthcheck.mjs deploy/hub/entrypoint.sh ./deploy/hub/
USER node
EXPOSE 4387
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["node", "deploy/hub/healthcheck.mjs"]
ENTRYPOINT ["sh", "/app/deploy/hub/entrypoint.sh"]
