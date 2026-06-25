package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteDoesNotCreateMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	path := filepath.Join(dir, "allow.txt")

	if err := Write(path, []byte("1.2.3.4/32\n"), 0o600); err == nil {
		t.Fatal("Write should fail when parent directory is missing")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("written file should not exist, got err %v", err)
	}
}

func TestWriteUsesPrivateFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")

	if err := Write(path, []byte("1.2.3.4/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 600", info.Mode().Perm())
	}
}

func TestWriteWithDirCreatesPrivateDirectoryAndFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "private")
	path := filepath.Join(dir, "allow.txt")

	if err := WriteWithDir(path, []byte("1.2.3.4/32\n"), 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("created dir mode = %o, want 700", dirInfo.Mode().Perm())
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 600", fileInfo.Mode().Perm())
	}
}
