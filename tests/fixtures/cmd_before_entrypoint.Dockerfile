# CMD appears before ENTRYPOINT (legal ordering). Docker treats the CMD tokens as
# arguments to the entrypoint, so the runtime process is the entrypoint binary and
# the flags must never surface as their own process assertion.
FROM alpine:3.19
CMD ["--port", "8080"]
ENTRYPOINT ["/usr/local/bin/server"]
