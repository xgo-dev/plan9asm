package plan9asm

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// An explicit diagnostic export retains the exact compiled fixture for a
// second execution transport. The original test still runs and reports its
// own outcome; export never converts an emulator failure into a native pass.
func x86MMXExportNativeFixture(t *testing.T, executable, source, ir, level, triple string, rows int) {
	t.Helper()
	directory := os.Getenv("PLAN9ASM_MMX_NATIVE_EXPORT_DIR")
	if directory == "" {
		return
	}
	if !filepath.IsAbs(directory) || level != "-O0" && level != "-O2" {
		t.Fatal("native MMX export needs an explicit absolute directory and original optimization axis")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	name := "mmx-native-" + level[1:]
	write := func(name string, data []byte, mode os.FileMode) {
		t.Helper()
		file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal("incomplete native MMX export", writeErr, closeErr)
		}
	}
	write(name, binary, 0700)
	manifest, err := json.MarshalIndent(map[string]interface{}{
		"executable": name, "sha256": fmt.Sprintf("%x", sha256.Sum256(binary)),
		"assembly_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(source))),
		"ir_sha256":       fmt.Sprintf("%x", sha256.Sum256([]byte(ir))),
		"sdk":             runtime.Version(), "triple": triple, "backend_level": level, "rows": rows,
		"scope": "Compiled diagnostic artifact only; the original and second execution outcomes remain independent.",
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	write(name+".json", append(manifest, '\n'), 0600)
}
