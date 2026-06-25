package pipeline

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
)

func TestWriteOutputsUsesPrivateFileModes(t *testing.T) {
	dir := t.TempDir()
	p := Params{
		OutputAllowTxt:  filepath.Join(dir, "allow.txt"),
		OutputStateJSON: filepath.Join(dir, "state.json"),
		SourceLabel:     "test",
	}
	res := &Result{CIDRs: []string{"1.2.3.4/32"}}
	if err := WriteOutputs(time.Now(), res, p, audit.NewWithWriter(io.Discard)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{p.OutputAllowTxt, p.OutputStateJSON} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", path, info.Mode().Perm())
		}
	}
}

func TestAtomicWriteCreatesPrivateDirectories(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "private")
	path := filepath.Join(dir, "allow.txt")
	if err := AtomicWrite(path, []byte("1.2.3.4/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("created dir mode = %o, want 700", info.Mode().Perm())
	}
}
