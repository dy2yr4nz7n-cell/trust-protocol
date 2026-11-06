FROM node:20.19-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY . .
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
 && chown -R appuser:appuser /app
USER appuser
EXPOSE 3000
CMD ["node", "server.js"]
