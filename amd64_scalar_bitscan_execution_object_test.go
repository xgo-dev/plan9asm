package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Compile the exact native fixtures on every development host. This checks
// original ABI0 callers, physical observers and test-private LLVM shims before
// the Linux owners execute them; object success never stands in for execution.
func TestX86ScalarBitScanExecutionCompleteOriginalGoLinksAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete native bit-scan fixtures require LLVM22 llc")
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			fixture := x86BitScanExecutionFixtureFor(t, arch)
			dir := t.TempDir()
			sources := map[string]string{
				"go.mod":                 "module bitscanexec\n\ngo 1.20\n",
				"main.go":                x86BitScanOriginalExecutionDriver(t, fixture),
				"public_" + arch + ".s":  fixture.public,
				"status_" + arch + ".s":  fixture.observers,
				"callers_" + arch + ".s": fixture.callers,
			}
			for name, source := range sources {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				t.Logf("original complete input=%s SHA256=%x", name, sha256.Sum256([]byte(source)))
			}
			driver, driverHash := x86LEAActualSDKDriver(t)
			verify := func() {
				for name, source := range sources {
					actual, err := os.ReadFile(filepath.Join(dir, name))
					if err != nil || string(actual) != source {
						t.Fatal("complete original fixture changed", name, err)
					}
				}
				actualDriver, actualHash := x86LEAActualSDKDriver(t)
				if actualDriver != driver || actualHash != driverHash {
					t.Fatal("original fixture compiler changed")
				}
			}
			original := filepath.Join(dir, "original")
			command := exec.Command(driver, "build", "-p=1", "-o", original, ".")
			command.Dir = dir
			command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
				"GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=", "GOMAXPROCS=2")
			verify()
			x86FloatCompareCaptureCommand(t, command)
			verify()
			info, err := os.Lstat(original)
			if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatal("original complete Go executable is missing or invalid", err)
			}

			triple := "x86_64-unknown-linux-gnu"
			if arch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, fixture.public, fixture.declarations, arch, triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete original numerical fixture failed", err)
					}
					ir = x86BitScanExecutionStatusShim(t, fixture, ir)
					for _, optimize := range []bool{false, true} {
						input := ir
						if optimize {
							input = x86MulDivRoundOptimize(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimize, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, triple, input, level)
							})
						}
					}
				})
			}
			verify()
		})
	}
}
