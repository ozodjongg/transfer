package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"example.com/pro-transfer/internal/transfer"
)

func main() {
	// Config is ensured before parsing commands so even the first bare launch
	// (for example, double-clicking client.exe) creates config.json next to
	// the executable.
	path := configPath()
	created, err := ensureConfigFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[x] Config yaratilmadi: %v\n", err)
		os.Exit(1)
	}
	if created {
		fmt.Printf("[i] Default config.json yaratildi: %s\n", path)
	}

	cfg, err := loadAppConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[x] %v\n", err)
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		usage()
		return
	}

	switch strings.ToLower(os.Args[1]) {
	case "send", "sender", "s":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: client send <file>")
			os.Exit(2)
		}
		runSend(cfg, os.Args[2])
	case "receive", "receiver", "recv", "r":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: client receive <room-code>")
			os.Exit(2)
		}
		runReceive(cfg, os.Args[2])
	case "config":
		showConfig(path, cfg)
	default:
		usage()
		os.Exit(2)
	}
}

func runSend(appCfg AppConfig, filePath string) {
	cfg, err := appCfg.transferConfig()
	if err != nil {
		fatalConfig(err)
	}
	room, err := transfer.SendFile(cfg, filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[x] Yuborish xatosi (room=%s): %v\n", room, err)
		os.Exit(1)
	}
	fmt.Println("[✓] Fayl muvaffaqiyatli yetkazildi.")
}

func runReceive(appCfg AppConfig, room string) {
	cfg, err := appCfg.transferConfig()
	if err != nil {
		fatalConfig(err)
	}
	path, err := transfer.ReceiveFile(cfg, strings.ToUpper(strings.TrimSpace(room)), appCfg.DownloadDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[x] Qabul qilish xatosi: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[✓] Fayl saqlandi: %s\n", path)
}

func showConfig(path string, cfg AppConfig) {
	pretty, _ := json.MarshalIndent(cfg, "", "  ")
	fmt.Printf("Config: %s\n%s\n", path, pretty)
}

func fatalConfig(err error) {
	fmt.Fprintf(os.Stderr, "[x] Config xatosi: %v\n", err)
	os.Exit(1)
}

func usage() {
	fmt.Print(`Pro Transfer Client

Yuborish:
  client send <file>

Qabul qilish:
  client receive <room-code>

Joriy sozlamani ko'rish:
  client config

Sozlamalar client yonidagi config.json faylidan olinadi.

Misol:
  client send report.xlsx
  client receive AB7K4M9Q2X
`)
}
