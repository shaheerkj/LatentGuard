# Base images pinned to specific minor versions so a CI rebuild stays
# reproducible. Bump deliberately, not by accident.
FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/proxy ./cmd/proxy

FROM alpine:3.19
RUN adduser -D -u 1000 latentguard
COPY --from=builder /out/proxy /usr/local/bin/proxy
# --chown so the latentguard user can rewrite threatintel.data at runtime
# (the M3/FE-2 fetcher rewrites the file on every refresh).
# rules/ ships with OWASP CRS vendored at v4.7.0 (see rules/90-crs/VERSION).
# Vendoring keeps the image build hermetic -- no network fetch at build
# time -- and pins detection semantics across rebuilds.
COPY --chown=latentguard:latentguard rules /etc/coraza/rules
USER latentguard
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/proxy"]
