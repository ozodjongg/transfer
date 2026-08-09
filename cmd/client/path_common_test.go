package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathContainsDir(t *testing.T) {
	target := filepath.Join(os.TempDir(), "ProTransfer", "bin")
	other := filepath.Join(os.TempDir(), "Other")
	pathValue := other + string(os.PathListSeparator) + target
	if !pathContainsDir(pathValue, target) {
		t.Fatalf("expected target path to be detected")
	}
}
