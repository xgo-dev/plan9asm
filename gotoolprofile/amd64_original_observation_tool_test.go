package gotoolprofile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAMD64OriginalObservationSelectedToolRole(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "go")
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	truncateErr := file.Truncate(17 << 20)
	closeErr := file.Close()
	if truncateErr != nil || closeErr != nil {
		t.Fatal(truncateErr, closeErr)
	}
	files := newAMD64OriginalObservationFiles()
	if err := files.retainTool(name); err != nil {
		t.Fatal("actual Go/export observation did not retain its selected tool role", err)
	}
	if err := files.verify(); err != nil {
		t.Fatal(err)
	}
	if err := newAMD64OriginalObservationFiles().retain(name); err == nil {
		t.Fatal("selected tool bound leaked into original SDK/source/export retention")
	}
	if err := files.retain(name); err == nil {
		t.Fatal("selected original tool was relabeled as source/export")
	}
}
