FROM --platform=${BUILDPLATFORM} golang:alpine as builder

WORKDIR /workdir
COPY --from=tonistiigi/xx:golang / /
ARG TARGETOS TARGETARCH TARGETVARIANT

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    make BINDIR= ${TARGETOS}-${TARGETARCH}${TARGETVARIANT} && \
    mv /clash* /clash

FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/eyslce/clash"

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /Country.mmdb /root/.config/clash/
COPY --from=builder /clash /
ENTRYPOINT ["/clash"]
