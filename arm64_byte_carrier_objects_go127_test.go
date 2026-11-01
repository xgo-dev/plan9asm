//go:build go1.27

package plan9asm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestARM64ByteCarrierActualFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	directory, packagePath, widths := arm64ByteCarrierFixture(t)
	widths = arm64ByteCarrierExactWidthControl(t, directory, widths)
	if len(widths) != 10 {
		t.Fatal("complete nine wider stores and exact MOVW control are required")
	}
	declarations, err := os.ReadFile(filepath.Join(directory, "decl.go"))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := os.ReadFile(filepath.Join(directory, "original_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, packagePath, string(declarations))
	base := arm64ByteCarrierRequest(t, directory, packagePath)
	for _, target := range []struct{ goos, triple string }{
		{"darwin", "aarch64-apple-darwin"},
		{"linux", "aarch64-unknown-linux-gnu"},
		{"windows", "aarch64-pc-windows-msvc"},
		{"freebsd", "aarch64-unknown-freebsd"},
		{"openbsd", "aarch64-unknown-openbsd"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			request := base
			request.Target = target.goos + "/arm64"
			request.Environment = append([]string(nil), base.Environment...)
			for index, pair := range request.Environment {
				if strings.HasPrefix(pair, "GOOS=") {
					request.Environment[index] = "GOOS=" + target.goos
				}
			}
			lease, release := runtimeOracleStageContext(t)
			defer release()
			source, err := CaptureGoARM64ByteCarrierSource(lease, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), target.triple,
						func(_ *File, _ *Options, options *GoModuleOptions) {
							// Keeping the whole graph is allowed; filtering it is
							// independently rejected by the source-bound controls.
							options.KeepFunc = func(_, _ string) bool { return true }
						})
					if err != nil || ir == "" {
						t.Fatalf("complete original target could not translate: %v", err)
					}
					compileLLVMToObject(t, llc, target.triple, "carrier.ll", "carrier.o", ir)
				})
			}
		})
	}
}
