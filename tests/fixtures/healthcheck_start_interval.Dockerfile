FROM nginx:alpine

EXPOSE 8080

# --start-interval was added in Docker Engine 25 and is not one of the four
# flags the parser records; it must not leak into the healthcheck command.
HEALTHCHECK --start-interval=5s --interval=30s --timeout=3s CMD curl -f http://localhost:8080/ || exit 1
