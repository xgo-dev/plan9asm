//go:build go1.27

package plan9asm

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This consumes the complete original function and its SDK declaration, not
// a rewritten $0-32 header. Objects do not claim execution or package linkage.
func TestX86OmittedTEXTOriginalSubtleXORObjects(t *testing.T) {
	directory := filepath.Join(runtime.GOROOT(), "src/crypto/internal/fips140/subtle")
	source, err := os.ReadFile(filepath.Join(directory, "xor_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := os.ReadFile(filepath.Join(directory, "xor_asm.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "TEXT ·xorBytes(SB), NOSPLIT, $0\n") {
		t.Fatal("actual omitted-TEXT source fixture changed")
	}
	pkg := mustGoPackage(t, "subtle", string(declaration))
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, string(source))
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewPackageAPI(t, string(source), pkg, "amd64", triple, api)
				if err != nil {
					t.Fatal("unchanged complete SDK xorBytes source rejected", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, text, level)
					}
				}
			}
		})
	}
}
