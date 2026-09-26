# A shared internal base stage carries ENV/WORKDIR that the final stage inherits
# via `FROM base`. The generated goss.yml must reference the resolved directory
# (/app), never the literal `$APP_HOME`.
FROM node:20-alpine AS base
ENV APP_HOME=/app
WORKDIR $APP_HOME
COPY package.json $APP_HOME/package.json

FROM base
COPY server.js $APP_HOME/server.js
EXPOSE 3000
ENTRYPOINT ["node", "server.js"]
