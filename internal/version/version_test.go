package version

import "testing"

func TestDefaultVersionMatchesCurrentRelease(t *testing.T) {
	if Version != "0.6.1" {
		t.Fatalf("Version = %q, want 0.6.1", Version)
	}
}
