# This Dockerfile is built from an extracted SecWeaver Agent Linux release
# package, whose bin/secweaver-agent file is already the target architecture.
# Keeping compilation outside the runtime image makes the image reproducible
# from the signed release archive and avoids shipping a compiler or shell.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 65532 secweaver \
    && adduser -S -D -H -u 65532 -G secweaver secweaver \
    && install -d -o secweaver -g secweaver -m 0700 /var/lib/secweaver-agent

COPY --chown=secweaver:secweaver bin/secweaver-agent /usr/local/bin/secweaver-agent

USER secweaver:secweaver
ENTRYPOINT ["/usr/local/bin/secweaver-agent"]
CMD ["run", "-config", "/etc/secweaver-agent/config.json"]
