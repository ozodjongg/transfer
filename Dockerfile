# syntax=docker/dockerfile:1

# ------------------------------------------------------------
# Build stage
# ------------------------------------------------------------
FROM golang:1.23-alpine AS builder

WORKDIR /src

# Copy module metadata first so Docker can cache dependencies.
COPY go.mod ./
RUN go mod download

# Copy source code and compile a small static Linux binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/transfer-server \
    ./cmd/server

# ------------------------------------------------------------
# Runtime stage
# ------------------------------------------------------------
FROM alpine:3.22

# Run as an unprivileged user.
RUN addgroup -S app && adduser -S -G app app

WORKDIR /app
COPY --from=builder /out/transfer-server /app/transfer-server

USER app

# Railway TCP Proxy should target this internal port.
EXPOSE 8080

ENTRYPOINT ["/app/transfer-server"]
CMD ["-addr", ":8080", "-max-file-gb", "10", "-room-ttl", "10m", "-transfer-timeout", "2h", "-max-connections", "512", "-max-handshakes-per-minute", "120"]
