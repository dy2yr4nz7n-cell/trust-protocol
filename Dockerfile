# syntax=docker/dockerfile:1.7
FROM debian:bookworm-slim AS c2pa-builder
ARG TARGETARCH=amd64
RUN test "$TARGETARCH" = amd64
ADD --checksum=sha256:e2dcd1cfcb872ee4f4cc4b353131615e09b608ed7cdea9f27a7f9d73d5d9af86 https://github.com/contentauth/c2patool/releases/download/v0.28.6/v0.28.6-x86_64-unknown-linux-gnu.tar.gz /tmp/c2patool.tar.gz
RUN mkdir /opt/c2patool && tar -xzf /tmp/c2patool.tar.gz -C /opt/c2patool --strip-components=1

FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/verifier/package.json ./apps/verifier/package.json
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
RUN apt-get update && apt-get install -y --no-install-recommends gosu ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=c2pa-builder /opt/c2patool/c2patool /usr/local/bin/c2patool
RUN c2patool --version
COPY --from=build --chown=node:node /app /app
RUN mkdir -p /app/data && chown node:node /app/data
RUN chmod +x /app/scripts/docker-entrypoint.sh
ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
EXPOSE 3000
CMD ["npm", "start"]
