package main

import (
	"os"
	"path/filepath"
	"strings"
)

func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return "", err
	}
	return filepath.Clean(filepath.Dir(exe)), nil
}

func pathContainsDir(pathValue, target string) bool {
	target = normalizePathEntry(target)
	if target == "" {
		return false
	}
	for _, entry := range filepath.SplitList(pathValue) {
		if strings.EqualFold(normalizePathEntry(entry), target) {
			return true
		}
	}
	return false
}

func normalizePathEntry(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"`)
	if v == "" {
		return ""
	}
	v = os.ExpandEnv(v)
	if abs, err := filepath.Abs(v); err == nil {
		v = abs
	}
	return strings.TrimRight(filepath.Clean(v), `\\/`)
}
