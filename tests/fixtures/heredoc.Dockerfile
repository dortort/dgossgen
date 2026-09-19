FROM alpine:3.19

# RUN heredoc: the body carries the real package installs. Before heredoc
# support these lines were re-parsed as top-level instructions and silently
# dropped, so no package evidence was extracted.
RUN <<EOF
apk add --no-cache nginx
apk add --no-cache curl
EOF

# COPY heredoc: the body is nginx config content. The `user nginx;` line starts
# with a Dockerfile keyword and, before heredoc support, was fabricated into a
# USER instruction (and a High-confidence UserExists assertion the image never
# promised).
COPY <<CONF /etc/nginx/nginx.conf
user nginx;
worker_processes auto;
CONF

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
