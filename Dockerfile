# Pin this official base tag to an approved digest before production deployment.
FROM node:24-bookworm-slim AS base
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev --no-audit --no-fund
COPY --chown=node:node src ./src

FROM base AS test
COPY --chown=node:node test ./test
USER node
RUN node src/check.mjs && node --test test/*.test.mjs

FROM base AS runtime
RUN mkdir /data && chown node:node /data
USER node
ENV NODE_ENV=production BRIDGE_DATA_DIR=/data BRIDGE_BIND_HOST=0.0.0.0 BRIDGE_PORT=8443
EXPOSE 8443
STOPSIGNAL SIGTERM
CMD ["node", "src/main.mjs"]
