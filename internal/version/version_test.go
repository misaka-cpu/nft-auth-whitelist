package version

import "testing"

func TestDefaultVersionMatchesCurrentRelease(t *testing.T) {
	if Version != "0.7.0" {
		t.Fatalf("Version = %q, want 0.7.0", Version)
	}
}
