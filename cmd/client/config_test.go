package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadAppConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := []byte(`{
  "server": "example.test:8443",
  "download_dir": "received",
  "tls": {"enabled": true, "insecure_skip_verify": false, "server_name": "files.example.test"},
  "timeouts": {"connect": "5s", "io": "30m"}
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadAppConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "example.test:8443" || cfg.DownloadDir != "received" || !cfg.TLS.Enabled {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	clientCfg, err := cfg.transferConfig()
	if err != nil {
		t.Fatal(err)
	}
	if clientCfg.ConnectTimeout != 5*time.Second || clientCfg.IOTimeout != 30*time.Minute {
		t.Fatalf("unexpected timeouts: %+v", clientCfg)
	}
	if clientCfg.TLSConfig == nil || clientCfg.TLSConfig.ServerName != "files.example.test" {
		t.Fatalf("unexpected TLS config: %+v", clientCfg.TLSConfig)
	}
}

func TestLoadAppConfigRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"server":"localhost:8080","download_dir":"downloads","tls":{},"timeouts":{"connect":"10s","io":"2h"},"typo":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAppConfig(path); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestEnsureConfigFileCreatesDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	created, err := ensureConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected config file to be created")
	}

	cfg, err := loadAppConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := defaultAppConfig()
	if cfg.Server != want.Server || cfg.DownloadDir != want.DownloadDir || cfg.Timeouts != want.Timeouts || cfg.TLS != want.TLS {
		t.Fatalf("unexpected default config: %+v", cfg)
	}

	created, err = ensureConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("existing config must not be overwritten")
	}
}

func TestMalformedConfigReturnsClearError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"server":`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadAppConfig(path)
	if err == nil {
		t.Fatal("expected malformed JSON error")
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "config.json noto'g'ri") {
		t.Fatalf("unexpected error: %v", err)
	}
}
