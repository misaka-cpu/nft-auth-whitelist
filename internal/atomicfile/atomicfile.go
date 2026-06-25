// Package atomicfile writes files through same-directory temp files and rename.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write writes data to a temp file in the destination directory, fsyncs it,
// applies perm, and renames it into place. The destination directory must
// already exist.
func Write(path string, data []byte, perm os.FileMode) error {
	return write(path, data, perm)
}

// WriteWithDir creates the destination directory with dirPerm before calling
// Write.
func WriteWithDir(path string, data []byte, filePerm, dirPerm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return err
	}
	return write(path, data, filePerm)
}

func write(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
