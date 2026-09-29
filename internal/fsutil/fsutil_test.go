package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicReplacesAndLeavesNoTemporaryFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "nested", "file.txt")
	for _, content := range []string{"first", "second"} {
		if err := WriteFileAtomic(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "second" {
		t.Fatalf("content = %q, %v", data, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("unexpected leftovers: %v", entries)
	}
}
