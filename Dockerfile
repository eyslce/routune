FROM --platform=${BUILDPLATFORM} golang:alpine as builder

WORKDIR /workdir
COPY --from=tonistiigi/xx:golang / /
ARG TARGETOS TARGETARCH TARGETVARIANT

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    make BINDIR= ${TARGETOS}-${TARGETARCH}${TARGETVARIANT} && \
    mv /routune* /routune

FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/eyslce/routune"

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /Country.mmdb /root/.config/routune/
COPY --from=builder /routune /
ENTRYPOINT ["/routune"]
