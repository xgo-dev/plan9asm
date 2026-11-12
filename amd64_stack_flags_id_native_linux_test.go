//go:build linux && (amd64 || 386)

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The original source and all four strict expectations remain unchanged.
// A host-inapplicable portable lane cannot stand in for this native assertion.
func TestX86StackFlagsIDNativeGo(t *testing.T) {
	source := strings.Replace(x86StackIDSource(runtime.GOARCH), "idroundtrip(SB)", "·idroundtrip(SB)", 1)
	if runtime.GOARCH == "386" {
		source = strings.Replace(source, "$0-8", "$0-4", 1)
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":                         "module flagsidnative\n\ngo 1.20\n",
		"flags_" + runtime.GOARCH + ".s": source,
		"flags_test.go": `package flagsidnative
import "testing"
func idroundtrip(out *[4]uint32)
func TestOriginalGoAssembly(t *testing.T) {
  var out [4]uint32
  idroundtrip(&out)
  if out != [4]uint32{0x200000, 0x200000, 0x200000, 1} {
    t.Fatalf("original Go flags roundtrip: %x", out)
  }
}
`,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), "test", "-p=2", "-count=1", "-v")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH,
		"CGO_ENABLED=0", "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=", "GOEXPERIMENT=")
	x86FloatCompareCaptureCommand(t, command)
}
