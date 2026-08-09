package transfer

import "testing"

func TestHumanDuration(t *testing.T) {
	if got := HumanDuration(3); got != "00:00" { // 3ns rounds down
		t.Fatalf("got %q", got)
	}
}

func TestValidateManifestPathRejectsTraversal(t *testing.T) {
	bad := []string{"../secret", "a/../../b", "/absolute", "a\\b", ""}
	for _, p := range bad {
		if err := validateManifestPath(p); err == nil {
			t.Fatalf("expected unsafe path rejection for %q", p)
		}
	}
}
