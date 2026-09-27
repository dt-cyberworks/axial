# Production edge: builds the operator console as a static SPA and serves it
# behind Caddy, which also reverse-proxies the public API to control-plane
# (REQ-IAM-010). Only this container's port is published in the production
# compose profile - control-plane itself is no longer host-published.

FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS frontend-build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
# Same-origin in production: the SPA calls relative paths, Caddy proxies them.
ENV VITE_API_BASE_URL=""
RUN npm run build

FROM caddy:2-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648
COPY --from=frontend-build /app/dist /srv/frontend
COPY edge/Caddyfile /etc/caddy/Caddyfile
