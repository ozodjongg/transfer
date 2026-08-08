package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/pro-transfer/internal/transfer"
)

const configFileName = "config.json"

type AppConfig struct {
	Server      string        `json:"server"`
	DownloadDir string        `json:"download_dir"`
	TLS         TLSConfig     `json:"tls"`
	Timeouts    TimeoutConfig `json:"timeouts"`
}

type TLSConfig struct {
	Enabled            bool   `json:"enabled"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	ServerName         string `json:"server_name,omitempty"`
}

type TimeoutConfig struct {
	Connect string `json:"connect"`
	IO      string `json:"io"`
}

func defaultAppConfig() AppConfig {
	return AppConfig{
		Server:      "localhost:8080",
		DownloadDir: "downloads",
		TLS: TLSConfig{
			Enabled: false,
		},
		Timeouts: TimeoutConfig{
			Connect: "10s",
			IO:      "2h",
		},
	}
}

func configPath() string {
	// A custom path can be useful for portable or managed deployments without
	// bringing back a large set of CLI flags.
	if custom := strings.TrimSpace(os.Getenv("PRO_TRANSFER_CONFIG")); custom != "" {
		return custom
	}

	// Normal packaged usage: config.json lives next to client.exe/client.
	if exe, err := os.Executable(); err == nil {
		path := filepath.Join(filepath.Dir(exe), configFileName)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Development usage (especially `go run`) should work from the project dir.
	if _, err := os.Stat(configFileName); err == nil {
		return configFileName
	}

	// If neither exists, prefer creating/looking next to the executable.
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), configFileName)
	}
	return configFileName
}

func ensureConfigFile(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("config tekshirishda xatolik: %w", err)
	}

	cfg := defaultAppConfig()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, fmt.Errorf("default config yaratishda xatolik: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("config papkasini yaratishda xatolik: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("default config yozishda xatolik: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(path)
		return false, fmt.Errorf("default config yozishda xatolik: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return false, fmt.Errorf("default configni yopishda xatolik: %w", err)
	}

	return true, nil
}

func loadAppConfig(path string) (AppConfig, error) {
	cfg := defaultAppConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return AppConfig{}, fmt.Errorf("config topilmadi: %s", path)
		}
		return AppConfig{}, err
	}

	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return AppConfig{}, fmt.Errorf("config.json noto'g'ri: %w", err)
	}
	cfg.Server = strings.TrimSpace(cfg.Server)
	cfg.DownloadDir = strings.TrimSpace(cfg.DownloadDir)
	cfg.TLS.ServerName = strings.TrimSpace(cfg.TLS.ServerName)
	cfg.Timeouts.Connect = strings.TrimSpace(cfg.Timeouts.Connect)
	cfg.Timeouts.IO = strings.TrimSpace(cfg.Timeouts.IO)
	if err := cfg.validate(); err != nil {
		return AppConfig{}, err
	}
	return cfg, nil
}

func (c AppConfig) validate() error {
	c.Server = strings.TrimSpace(c.Server)
	if c.Server == "" {
		return errors.New("config: server bo'sh bo'lishi mumkin emas")
	}
	if _, _, err := net.SplitHostPort(c.Server); err != nil {
		return fmt.Errorf("config: server host:port ko'rinishida bo'lishi kerak (%q): %w", c.Server, err)
	}
	if strings.TrimSpace(c.DownloadDir) == "" {
		return errors.New("config: download_dir bo'sh bo'lishi mumkin emas")
	}
	if _, err := parseDuration("timeouts.connect", c.Timeouts.Connect); err != nil {
		return err
	}
	if _, err := parseDuration("timeouts.io", c.Timeouts.IO); err != nil {
		return err
	}
	if c.TLS.InsecureSkipVerify && !c.TLS.Enabled {
		return errors.New("config: tls.insecure_skip_verify faqat tls.enabled=true bo'lganda ishlatiladi")
	}
	return nil
}

func parseDuration(name, value string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || d <= 0 {
		if err == nil {
			err = errors.New("duration 0 dan katta bo'lishi kerak")
		}
		return 0, fmt.Errorf("config: %s noto'g'ri (%q): %w", name, value, err)
	}
	return d, nil
}

func (c AppConfig) transferConfig() (transfer.ClientConfig, error) {
	connectTimeout, err := parseDuration("timeouts.connect", c.Timeouts.Connect)
	if err != nil {
		return transfer.ClientConfig{}, err
	}
	ioTimeout, err := parseDuration("timeouts.io", c.Timeouts.IO)
	if err != nil {
		return transfer.ClientConfig{}, err
	}

	var tlsConfig *tls.Config
	if c.TLS.Enabled {
		serverName := strings.TrimSpace(c.TLS.ServerName)
		if serverName == "" {
			host, _, err := net.SplitHostPort(c.Server)
			if err != nil {
				return transfer.ClientConfig{}, err
			}
			serverName = host
		}
		tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         serverName,
			InsecureSkipVerify: c.TLS.InsecureSkipVerify, // #nosec G402: explicit config opt-in for dev/self-signed deployments
		}
	}

	return transfer.ClientConfig{
		Addr:           c.Server,
		TLSConfig:      tlsConfig,
		ConnectTimeout: connectTimeout,
		IOTimeout:      ioTimeout,
	}, nil
}
