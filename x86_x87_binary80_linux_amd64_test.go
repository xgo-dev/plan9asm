//go:build linux && amd64

package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86X87Binary80ConstantsAndRC(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc, clang, found := findLlcAndClang(t)
	compiler386, err := exec.LookPath("i686-linux-gnu-gcc")
	if !found || err != nil {
		t.Fatal("native binary80 owner requires LLVM22 and the static i686 compiler", err)
	}
	for _, arch := range []string{"amd64", "386"} {
		execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
			compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
		if arch == "386" {
			execution.triple = "i386-unknown-linux-gnu"
			execution.compiler = []string{compiler386, "-static", "-no-pie", "-maccumulate-outgoing-args"}
		}
		execution.compiler = append(execution.compiler, "-DX87_ORIGINAL_GO_RECORDS=1")
		source, declarations := x86X87NativeConstantProgram(t, arch)
		statusSource, statusDeclarations := x86X87NativeClearStatusProgram(t, arch)
		source += statusSource
		declarations += statusDeclarations
		main, err := format.Source([]byte(x86X87NativeConstantOriginalDriver(declarations)))
		if err != nil {
			t.Fatal("original Go constant driver", err)
		}
		dir := t.TempDir()
		files := map[string][]byte{
			"go.mod": []byte("module binary80constants\n\ngo 1.20\n"), "main.go": main,
			"constants_" + arch + ".s": []byte(source), "state_" + arch + ".s": []byte(x86X87NativeStateAssembly(arch)),
		}
		for name, contents := range files {
			if err := os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil {
				t.Fatal(err)
			}
			t.Logf("whole original source=%s sha256=%x", name, sha256.Sum256(contents))
		}
		driver, driverHash := x86LEAActualSDKDriver(t)
		verify := func() {
			for name, contents := range files {
				actual, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || string(actual) != string(contents) {
					t.Fatal("complete original constant source changed", name, err)
				}
			}
			if actual, hash := x86LEAActualSDKDriver(t); actual != driver || hash != driverHash {
				t.Fatal("original SDK driver changed")
			}
		}
		original := filepath.Join(dir, "original")
		command := exec.Command(driver, "build", "-p=1", "-o", original, ".")
		command.Dir = dir
		command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=", "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOMAXPROCS=2")
		x86FloatCompareCaptureCommand(t, command)
		run := func(path string, args ...string) []byte {
			if arch == "amd64" {
				return execution.run(t, path, args...)
			}
			sealed, err := x87IA32StaticExecutable(path)
			if err != nil {
				t.Fatal("constant execution requires complete native ELF32", err)
			}
			return x87IA32RunDirect(t, sealed, args, os.Environ())
		}
		records := run(original)
		if len(records) != (28+3)*2 {
			t.Fatal("original Go constant inventory did not finish", len(records))
		}
		reference := filepath.Join(dir, "original.records")
		if err := os.WriteFile(reference, records, 0600); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []X87Mode{X87Auto, X87Hardware} {
			for _, api := range []string{"text", "module", "Go"} {
				ir := x86X87Binary80ConstantRuntimeIR(t, arch, execution.triple, api, mode)
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(fmt.Sprintf("%s/%d/%s/%s", arch, mode, api, level), func(t *testing.T) {
						executable := execution.compileLLVM(t, "x87-binary80-constants", ir, x86X87Binary80ConstantCOracle(), level)
						verify()
						actual, err := os.ReadFile(reference)
						if err != nil || string(actual) != string(records) {
							t.Fatal("original numerical records changed", err)
						}
						if output := run(executable, reference); len(output) != 0 {
							t.Fatal("unexpected numerical observer diagnostics", string(output))
						}
						verify()
						actual, err = os.ReadFile(reference)
						if err != nil || string(actual) != string(records) {
							t.Fatal("original numerical records changed", err)
						}
						t.Log("actual binary80 constants=28, original-Go/public comparisons=28, status clear cases=3, physical stack balanced and caller state restored")
					})
				}
			}
		}
	}
}

func TestCrossLinuxRuntimeMatrixX86X87Binary80ArithmeticOriginalGoAndLLVM(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc, clang, found := findLlcAndClang(t)
	compiler386, err := exec.LookPath("i686-linux-gnu-gcc")
	if !found || err != nil {
		t.Fatal("native arithmetic requires LLVM22 and the static i686 compiler", err)
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
				compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
			if arch == "386" {
				execution.triple = "i386-unknown-linux-gnu"
				execution.compiler = []string{compiler386, "-static", "-no-pie", "-maccumulate-outgoing-args"}
			}
			source, declarations := x86X87NativeArithmeticBundle(t, arch)
			main, err := format.Source([]byte(x86X87NativeArithmeticOriginalDriver(t, declarations)))
			if err != nil {
				t.Fatal("original Go arithmetic driver", err)
			}
			dir := t.TempDir()
			files := map[string][]byte{
				"go.mod": []byte("module binary80arithmetic\n\ngo 1.20\n"), "main.go": main,
				"arithmetic_" + arch + ".s": []byte(source), "state_" + arch + ".s": []byte(x86X87NativeStateAssembly(arch)),
			}
			for name, contents := range files {
				if err := os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil {
					t.Fatal(err)
				}
				t.Logf("whole original source=%s sha256=%x", name, sha256.Sum256(contents))
			}
			driver, driverHash := x86LEAActualSDKDriver(t)
			verify := func() {
				for name, contents := range files {
					actual, err := os.ReadFile(filepath.Join(dir, name))
					if err != nil || string(actual) != string(contents) {
						t.Fatal("complete original arithmetic source changed", name, err)
					}
				}
				if actual, hash := x86LEAActualSDKDriver(t); actual != driver || hash != driverHash {
					t.Fatal("original SDK driver changed")
				}
			}
			original := filepath.Join(dir, "original")
			command := exec.Command(driver, "build", "-p=1", "-o", original, ".")
			command.Dir = dir
			command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=", "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOMAXPROCS=2")
			x86FloatCompareCaptureCommand(t, command)
			run := func(path string, args ...string) []byte {
				if arch == "amd64" {
					return execution.run(t, path, args...)
				}
				sealed, err := x87IA32StaticExecutable(path)
				if err != nil {
					t.Fatal("direct arithmetic execution requires complete ELF32", err)
				}
				return x87IA32RunDirect(t, sealed, args, os.Environ())
			}
			verify()
			records := run(original)
			const checks = 54 * 3 * 4 * 8
			if len(records) != checks*8 {
				t.Fatal("original Go arithmetic inventory did not finish", len(records))
			}
			reference := filepath.Join(dir, "original.records")
			if err := os.WriteFile(reference, records, 0600); err != nil {
				t.Fatal(err)
			}
			verifyRecords := func() {
				actual, err := os.ReadFile(reference)
				if err != nil || string(actual) != string(records) {
					t.Fatal("original numerical records changed", err)
				}
			}
			t.Logf("actual original Go records=%d sha256=%x", checks, sha256.Sum256(records))
			for _, mode := range []X87Mode{X87Auto, X87Hardware} {
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86X87InitializedWordAPI(t, source, declarations, arch, execution.triple, api, mode)
					if err != nil || ir == "" {
						t.Fatal("whole public arithmetic source", api, err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(fmt.Sprintf("%d/%s/%s", mode, api, level), func(t *testing.T) {
							executable := execution.compileLLVM(t, "binary80-arithmetic", ir, x86X87NativeArithmeticCDriver(t), level)
							verify()
							verifyRecords()
							want := fmt.Sprintf("binary80 arithmetic original-Go/LLVM checks=%d\n", checks)
							if actual := run(executable, reference); string(actual) != want {
								t.Fatal("complete native arithmetic differential", string(actual))
							}
							verifyRecords()
							verify()
						})
					}
				}
			}
		})
	}
	x87IA32RequireNativeHost(t)
}
