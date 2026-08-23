# Fixture exercising ARG/ENV-driven and range EXPOSE forms.
FROM python:3.11-slim

ARG PORT=8000

WORKDIR /app

COPY . /app

ENV APP_PORT=${PORT}

EXPOSE ${APP_PORT}

CMD ["python", "-m", "http.server", "8000"]
