package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"example.com/pro-transfer/internal/transfer"
)

func main() {
	if added, dir, err := ensureExecutableOnUserPath(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] PATH avtomatik sozlanmadi: %v\n", err)
	} else if added {
		fmt.Printf("[i] Transfer Windows User PATH'iga qo'shildi: %s\n", dir)
		fmt.Println("[i] 'transfer' komandasini ishlatish uchun yangi CMD/PowerShell oynasini oching.")
	}

	configFile := configPath()
	created, err := ensureConfigFile(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[x] Config yaratilmadi: %v\n", err)
		os.Exit(1)
	}
	if created {
		fmt.Printf("[i] Default config.json yaratildi: %s\n", configFile)
	}
	cfg, err := loadAppConfig(configFile)
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
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: transfer send <file-or-folder> [more files/folders...]")
			os.Exit(2)
		}
		runSend(cfg, os.Args[2:])
	case "receive", "receiver", "recv", "r":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: transfer receive <TRANSFER-CODE>")
			os.Exit(2)
		}
		runReceive(cfg, os.Args[2])
	case "config":
		showConfig(configFile, cfg)
	default:
		usage()
		os.Exit(2)
	}
}

func runSend(appCfg AppConfig, paths []string) {
	cfg, err := appCfg.transferConfig()
	if err != nil {
		fatalConfig(err)
	}
	code, err := transfer.SendPaths(cfg, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[x] Yuborish xatosi (code=%s): %v\n", code, err)
		os.Exit(1)
	}
	fmt.Println("[✓] Transfer muvaffaqiyatli yetkazildi.")
}

func runReceive(appCfg AppConfig, code string) {
	cfg, err := appCfg.transferConfig()
	if err != nil {
		fatalConfig(err)
	}
	paths, err := transfer.ReceiveTransfer(cfg, code, appCfg.DownloadDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[x] Qabul qilish xatosi: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[✓] Transfer saqlandi:")
	for _, p := range paths {
		fmt.Printf("    %s\n", p)
	}
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
	fmt.Print(`Pro Transfer v6

Yuborish:
  transfer send <file-or-folder> [more files/folders...]

Qabul qilish:
  transfer receive <TRANSFER-CODE>

Joriy sozlama:
  transfer config

Misollar:
  transfer send report.xlsx
  transfer send report.xlsx photo.jpg "D:\My Project"
  transfer receive ROOM.SECRET.ENCRYPTED_ROUTES

V6:
  - multiple files/folders
  - end-to-end AES-256-GCM
  - automatic LAN direct fast-path + public relay fallback
  - parallel public TCP streams
  - per-stream authenticated resume
  - secret-derived reconnect aliases
`)
}
