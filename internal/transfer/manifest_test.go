package transfer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildManifestMultipleFilesAndFolder(t *testing.T) {
	base := t.TempDir()
	one := filepath.Join(base, "one.txt")
	if err := os.WriteFile(one, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(base, "Project")
	if err := os.MkdirAll(filepath.Join(folder, "sub", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "sub", "two.txt"), []byte("two-two"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, sources, err := buildManifest([]string{one, folder})
	if err != nil {
		t.Fatal(err)
	}
	if m.TotalSize != int64(len("one")+len("two-two")) {
		t.Fatalf("total=%d", m.TotalSize)
	}
	if len(sources) != 2 {
		t.Fatalf("sources=%d", len(sources))
	}
	foundEmpty := false
	for _, e := range m.Entries {
		if e.Path == "Project/sub/empty" && e.Type == "dir" {
			foundEmpty = true
		}
	}
	if !foundEmpty {
		t.Fatal("empty folder missing from manifest")
	}
}
