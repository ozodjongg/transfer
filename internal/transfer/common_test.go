package transfer

import "testing"

func TestSafeFilename(t *testing.T) {
	cases := map[string]string{
		"report.xlsx":     "report.xlsx",
		"../secret.txt":   "secret.txt",
		"folder/file.csv": "file.csv",
		"\x00unsafe.bin":  "unsafe.bin",
	}
	for in, want := range cases {
		if got := SafeFilename(in); got != want {
			t.Fatalf("SafeFilename(%q)=%q, want %q", in, got, want)
		}
	}
}
