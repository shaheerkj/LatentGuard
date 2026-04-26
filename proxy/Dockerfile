FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/proxy ./cmd/proxy

FROM alpine:3.19
RUN adduser -D -u 1000 latentguard
COPY --from=builder /out/proxy /usr/local/bin/proxy
COPY rules /etc/coraza/rules
USER latentguard
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/proxy"]
