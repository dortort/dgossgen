FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y nginx curl && \
    rm -rf /var/lib/apt/lists/*

COPY default.conf /etc/nginx/conf.d/default.conf
COPY --chmod=0755 entrypoint.sh /docker-entrypoint.sh

WORKDIR /var/www/html
VOLUME ["/var/www/html", "/var/log/nginx"]

ENV NGINX_PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

USER www-data

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
