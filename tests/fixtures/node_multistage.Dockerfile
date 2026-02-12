FROM node:18 AS builder
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:18-alpine
WORKDIR /app

RUN adduser -D -u 1001 appuser

COPY --from=builder /src/dist /app/dist
COPY --from=builder /src/package.json /app/
COPY --from=builder /src/node_modules /app/node_modules

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

USER appuser

ENTRYPOINT ["node", "dist/server.js"]
