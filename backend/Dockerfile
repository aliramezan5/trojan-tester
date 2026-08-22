FROM ghcr.io/sagernet/sing-box:v1.13.16@sha256:ba3a37088461712e8438de1d18d817a6b9964fe8c7bc7dd10218f6fd18214303 AS singbox
FROM node:22-bookworm-slim
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
WORKDIR /app
COPY backend/package.json ./package.json
COPY backend/server.mjs ./server.mjs
COPY backend/lib ./lib
ENV NODE_ENV=production PORT=8787 HOST=0.0.0.0
USER node
EXPOSE 8787
CMD ["node","server.mjs"]
