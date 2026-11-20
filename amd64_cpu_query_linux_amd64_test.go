package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86CPUQuery386IndependentC() string {
	return strings.NewReplacer(
		"uint64_t", "uint32_t", "UINT64_C(0xabcdef0123456789)", "UINT32_C(0x23456789)",
		"UINT64_C(0x13579bdf2468ace0)", "UINT32_C(0x2468ace0)",
		"UINT64_C(0x7e6d5c4b3a291807)", "UINT32_C(0x3a291807)",
		"UINT64_C(0xa1b2c3d400000000)", "UINT32_C(0)",
	).Replace(x86CPUQueryIndependentC)
}

// Real Linux IA32 execution is required separately from Rosetta, emulators
// and portable object compilation. Missing LLVM 22/cross tools fail this root.
func TestCrossLinuxRuntimeMatrixX86CPUQueryNative386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("required LLVM 22/native IA32 compiler: %v", err)
	}
	dir := t.TempDir()
	referenceSource, referenceExecutable := filepath.Join(dir, "reference.c"), filepath.Join(dir, "reference")
	if err := os.WriteFile(referenceSource, []byte("#define REFERENCE_ONLY 1\n"+x86CPUQuery386IndependentC()), 0600); err != nil {
		t.Fatal(err)
	}
	x86FloatCompareCaptureCommand(t, exec.Command(compiler, "-static", "-no-pie", referenceSource, "-O2", "-o", referenceExecutable))
	referenceProgram, err := x87IA32StaticExecutable(referenceExecutable)
	if err != nil {
		t.Fatal(err)
	}
	reference := string(x87IA32RunDirect(t, referenceProgram, nil, os.Environ()))
	lines := strings.Split(strings.TrimSpace(reference), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "cpu query ") || !strings.HasPrefix(lines[1], "xgetbv ") {
		t.Fatalf("actual native IA32 query reference: %q", reference)
	}
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			original := x86CPUQueryBuildOriginal386(t, raw)
			for _, suffix := range []string{"", "_af"} {
				if err := original.verify(); err != nil {
					t.Fatal(err)
				}
				output, err := x87IA32Capture(t, original.path, []string{suffix}, "", append(os.Environ(), "GOTRACEBACK=system"))
				if guard := original.verify(); guard != nil {
					t.Fatal(guard)
				}
				if lines[1] == "xgetbv SIGILL" {
					if !x86UndefinedTrapOriginalSignal(output, err) || !strings.HasPrefix(string(output), lines[0]+"\n") {
						t.Fatalf("original native IA32 query fault: %v\n%s", err, output)
					}
				} else if err != nil || string(output) != reference {
					t.Fatalf("original native IA32 query state: %v\n%s", err, output)
				}
			}
			declarations, assembly := x86CPUQueryRuntimeFixtures(raw, "386")
			pkg := mustGoPackage(t, "cpuquery386", "package cpuquery386\n"+declarations)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			translated, err := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
				GOARCH: "386", TargetTriple: "i386-unknown-linux-gnu",
				ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
			})
			if translated != nil && !translated.Module.IsNil() {
				if err != nil {
					translated.Module.Dispose()
				}
			}
			if err != nil || translated == nil || translated.Module.IsNil() {
				t.Fatalf("native IA32 query module: %v", err)
			}
			ir := translated.Module.String()
			verification := llvm.VerifyModule(translated.Module, llvm.ReturnStatusAction)
			translated.Module.Dispose()
			if verification != nil {
				t.Fatal(verification)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					input := ir
					if level == "-O2" {
						input = x86UndefinedTrapOptimizedIR(t, input)
					}
					dir := t.TempDir()
					ll, object := filepath.Join(dir, "query.ll"), filepath.Join(dir, "query.o")
					main, executable := filepath.Join(dir, "main.c"), filepath.Join(dir, "query")
					for name, contents := range map[string]string{ll: input, main: x86CPUQuery386IndependentC()} {
						if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
							t.Fatal(err)
						}
					}
					x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple=i386-unknown-linux-gnu", "-filetype=obj", ll, "-o", object))
					x86FloatCompareCaptureCommand(t, exec.Command(compiler, "-static", "-no-pie", object, main, "-O2", "-o", executable))
					sealed, err := x87IA32StaticExecutable(executable)
					if err != nil {
						t.Fatal(err)
					}
					if output := x87IA32RunDirect(t, sealed, nil, os.Environ()); string(output) != reference {
						t.Fatalf("actual native IA32 LLVM query state: %q / %q", output, reference)
					}
				})
			}
		})
	}
	x87IA32RequireNativeHost(t)
}
