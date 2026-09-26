# FROM base must inherit APP_HOME and resolve it to /app, never the literal `$APP_HOME`.
FROM node:20-alpine AS base
ENV APP_HOME=/app
WORKDIR $APP_HOME
COPY package.json $APP_HOME/package.json

FROM base
COPY server.js $APP_HOME/server.js
EXPOSE 3000
ENTRYPOINT ["node", "server.js"]
