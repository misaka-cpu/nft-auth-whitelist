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
