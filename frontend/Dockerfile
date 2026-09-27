# Operator-Konsole (Vite/React). Fuer den nebenberuflichen M1-M3-Start reicht
# `npm run dev` gegen die lokale control-plane (s. README). Dieses Image ist
# fuer einen spaeteren produktiven Build gedacht (statisch, hinter Reverse-Proxy).
FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
