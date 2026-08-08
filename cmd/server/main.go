package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/pro-transfer/internal/transfer"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	maxFileGB := flag.Int64("max-file-gb", 10, "maximum file size in GiB")
	roomTTL := flag.Duration("room-ttl", 10*time.Minute, "room waiting lifetime")
	transferTimeout := flag.Duration("transfer-timeout", 2*time.Hour, "maximum transfer duration")
	maxConnections := flag.Int("max-connections", 512, "maximum simultaneous TCP connections")
	maxHandshakes := flag.Int("max-handshakes-per-minute", 120, "maximum new handshakes per IP per minute")
	certFile := flag.String("tls-cert", "", "TLS certificate PEM file")
	keyFile := flag.String("tls-key", "", "TLS private key PEM file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var tlsConfig *tls.Config
	if *certFile != "" || *keyFile != "" {
		if *certFile == "" || *keyFile == "" {
			fmt.Fprintln(os.Stderr, "both -tls-cert and -tls-key are required")
			os.Exit(2)
		}
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load TLS certificate: %v\n", err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	}

	srv := transfer.NewServer(transfer.ServerConfig{
		Addr:                   *addr,
		RoomTTL:                *roomTTL,
		TransferTimeout:        *transferTimeout,
		MaxFileSize:            *maxFileGB << 30,
		MaxConnections:         *maxConnections,
		MaxHandshakesPerMinute: *maxHandshakes,
		TLSConfig:              tlsConfig,
		Logger:                 logger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		_ = srv.Shutdown()
		if err := <-errCh; err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Error("server shutdown error", "error", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}
}
