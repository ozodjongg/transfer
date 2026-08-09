# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/transfer-server ./cmd/server

FROM alpine:3.22
RUN addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=builder /out/transfer-server /app/transfer-server
USER app
EXPOSE 8080
ENTRYPOINT ["/app/transfer-server"]
CMD ["-addr", ":8080", "-max-transfer-gb", "10", "-room-ttl", "10m", "-transfer-timeout", "2h", "-resume-grace", "2m", "-max-rooms", "100", "-max-manifest-mb", "2", "-max-connections", "240", "-max-handshakes-per-minute", "600"]
