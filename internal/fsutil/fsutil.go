// Package fsutil holds small file-system helpers.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// WriteFileAtomic writes data to a temporary file in the same directory and
// renames it over path, so readers never observe a partially written file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(name)
		}
	}()
	if err := temporary.Chmod(perm); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		if runtime.GOOS != "windows" {
			return err
		}
		// Windows' MoveFile, used by os.Rename, does not replace an existing file.
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("%w (remove existing file: %v)", err, removeErr)
		}
		if err := os.Rename(name, path); err != nil {
			return err
		}
	}
	committed = true
	return nil
}
