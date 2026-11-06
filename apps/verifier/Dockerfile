FROM rust:1-bookworm AS c2pa-builder
RUN cargo install c2patool --version 0.28.6 --root /opt/c2patool

FROM node:20.19-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=c2pa-builder /opt/c2patool/bin/c2patool /usr/local/bin/c2patool
RUN c2patool --version | grep -q "c2patool 0.28.6" \
 || (echo "unexpected c2patool version" && exit 1)
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY . .
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
 && chown -R appuser:appuser /app
USER appuser
EXPOSE 3000
CMD ["node", "server.js"]
