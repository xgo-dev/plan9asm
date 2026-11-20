package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This required CI counterpart executes on the actual Linux/amd64 kernel.
// The static ELF32 transport rejects emulators and changed executables.
func TestCrossLinuxRuntimeMatrixX86TimestampNative386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if err != nil {
		t.Fatal("required native IA32 C compiler:", err)
	}
	declarations, assembly := x86TimestampRuntimeFixtures("386")
	declarations = "package main\n" + declarations
	goAssemblerOracleOutput(t, "386", assembly, "", true)
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":  "module timestamp386\n\ngo 1.20\n",
		"decl.go": declarations, "timestamp_386.s": assembly,
		"main.go": x86Timestamp386OriginalDriver,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	original := filepath.Join(dir, "original-go")
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p=2", "-o", original, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=386", "CGO_ENABLED=0",
		"GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=", "GOEXPERIMENT=")
	x86FloatCompareCaptureCommand(t, command)
	sealed, err := x87IA32StaticExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	if output := x87IA32RunDirect(t, sealed, nil, os.Environ()); string(output) != "original IA32 timestamp observations 256\n" {
		t.Fatalf("unchanged original Go IA32 timestamp execution: %q", output)
	}

	pkg := mustGoPackage(t, "timestamp386", declarations)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	translated, err := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
		GOARCH: "386", TargetTriple: "i386-unknown-linux-gnu",
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
	})
	if err != nil {
		if translated != nil && !translated.Module.IsNil() {
			translated.Module.Dispose()
		}
		t.Fatal(err)
	}
	if translated == nil || translated.Module.IsNil() {
		t.Fatal("successful IA32 translation did not produce a module")
	}
	ir := translated.Module.String()
	verifyError := llvm.VerifyModule(translated.Module, llvm.ReturnStatusAction)
	// Do not let native executable compilation keep a live module unnecessarily.
	translated.Module.Dispose()
	if verifyError != nil {
		t.Fatal(verifyError)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			input, object := filepath.Join(dir, "timestamp"+level+".ll"), filepath.Join(dir, "timestamp"+level+".o")
			main, executable := filepath.Join(dir, "main.c"), filepath.Join(dir, "timestamp"+level)
			for name, contents := range map[string]string{input: ir, main: x86Timestamp386IndependentC} {
				if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			x86FloatCompareCaptureCommand(t, exec.Command(llc, level,
				"-mtriple=i386-unknown-linux-gnu", "-filetype=obj", input, "-o", object))
			x86FloatCompareCaptureCommand(t, exec.Command(compiler, "-static", "-no-pie",
				object, main, "-O2", "-o", executable))
			sealed, err := x87IA32StaticExecutable(executable)
			if err != nil {
				t.Fatal(err)
			}
			if output := x87IA32RunDirect(t, sealed, nil, os.Environ()); string(output) != "IA32 timestamp observations 256\n" {
				t.Fatalf("LLVM IA32 TSC/AUX/flags/MXCSR/canaries: %q", output)
			}
		})
	}
	x87IA32RequireNativeHost(t)
}
