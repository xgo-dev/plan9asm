package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestX86PrivateCallFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required for ordinary helper CALL objects")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declaration := x86PrivateCallWholeSource(target.arch)
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					dir := t.TempDir()
					input, output := filepath.Join(dir, "calls.ll"), filepath.Join(dir, "calls.o")
					if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+target.triple,
							"-filetype=obj", input, "-o", output))
						if info, err := os.Stat(output); err != nil || info.Size() == 0 {
							t.Fatal("missing complete original-source helper CALL object", err)
						}
					}
				})
			}
		})
	}
}
