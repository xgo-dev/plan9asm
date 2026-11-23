//go:build go1.27 && linux && amd64

package plan9asm

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

//go:embed testdata/native/x86-tls-386.s
var x86TLSRuntimeRead386Driver []byte

// The Linux amd64 cross-runtime owner supplies the authenticated i386 runner.
func TestCrossLinuxRuntimeMatrixX86TLSRuntimeReads386(t *testing.T) {
	llc, opt := findLLVM22Tool("llc"), findLLVM22Tool("opt")
	mc, linker := findLLVM22Tool("llvm-mc"), findLLVM22Tool("ld.lld")
	if llc == "" || opt == "" || mc == "" || linker == "" {
		t.Fatal("386 TLS runtime reads require LLVM 22 llc, opt, llvm-mc, and ld.lld")
	}
	qemu, err := exec.LookPath("qemu-i386")
	if err != nil {
		t.Fatal("386 TLS runtime reads require pinned QEMU:", err)
	}
	const linuxTriple = "i386-unknown-linux-gnu"
	for _, profile := range []struct {
		name, target string
		shared       bool
	}{
		{"LinuxLocalExec", "linux/386", false},
		{"LinuxInitialExec", "linux/386", true},
		{"WindowsFSSlotModel", "windows/386", false},
	} {
		t.Run(profile.name, func(t *testing.T) {
			pkg, file, options, original, request := x86TLSMoveSourceFixture(t, profile.target, profile.shared,
				"func Value() uint32", x86TLSRuntimeRead386Body)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoX86TLSMoveSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			options, err = source.BindRuntimeTLSReads(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}

			dir := t.TempDir()
			assembly := filepath.Join(dir, "driver.s")
			driver := filepath.Join(dir, "driver.o")
			if err := os.WriteFile(assembly, x86TLSRuntimeRead386Driver, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-triple=" + linuxTriple, "-filetype=obj", assembly, "-o", driver}
			if profile.target == "windows/386" {
				// An ELF guest supplies the Windows FS layout explicitly. The
				// separate relocation test uses the actual Windows COFF target.
				args = append(args, "--defsym=WINDOWS_SLOT=1")
			}
			x86FloatCompareCaptureCommand(t, exec.Command(mc, args...))

			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86TLSMoveBoundAPI(t, pkg, file, original, options, api)
				if err != nil {
					t.Fatal(api, err)
				}
				raw, optimized := filepath.Join(dir, api+".ll"), filepath.Join(dir, api+".opt.ll")
				if err := os.WriteFile(raw, []byte(ir), 0600); err != nil {
					t.Fatal(err)
				}
				x86FloatCompareCaptureCommand(t, exec.Command(opt, "-passes=default<O2>", "-verify-each", "-S", raw, "-o", optimized))
				for _, input := range []string{raw, optimized} {
					for _, level := range []string{"-O0", "-O2"} {
						name := filepath.Base(input) + level
						t.Run(name, func(t *testing.T) {
							object, executable := filepath.Join(dir, name+".o"), filepath.Join(dir, name)
							x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+linuxTriple,
								"-relocation-model=pic", "-filetype=obj", input, "-o", object))
							x86FloatCompareCaptureCommand(t, exec.Command(linker, "-m", "elf_i386",
								"-static", "-o", executable, driver, object))
							guest := runtimeOracleGuestArguments(t, []string{qemu, "-cpu", "max"}, executable)
							output := x86FloatCompareCaptureCommand(t, exec.Command(guest[0], guest[1:]...))
							if string(output) != "3 TLS states\n" {
								t.Fatalf("incomplete 386 TLS slot checks: %q", output)
							}
						})
					}
				}
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86TLSRuntimeReadsAMD64(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	opt := findLLVM22Tool("opt")
	if opt == "" {
		t.Fatal("AMD64 TLS runtime reads require LLVM 22 opt")
	}
	const oracle = `#include <stdint.h>
#include <stdio.h>

static __attribute__((noinline)) uint64_t expected(uint64_t a, uint64_t b) {
    return a + b;
}

__thread volatile uint64_t slots[2] __asm__("runtime.tlsg");
extern uint64_t Value(void);

int main(void) {
    const uint64_t values[][2] = {
        {UINT64_C(0x100000007), UINT64_C(0x200000017)},
        {UINT64_C(0x100000007), UINT64_C(0x300000029)},
        {UINT64_C(0xf00000013), UINT64_C(0x300000029)},
    };
    for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        slots[0] = values[i][0];
        slots[1] = values[i][1];
        if (Value() != expected(values[i][0], values[i][1])) {
            return i + 1;
        }
    }
    puts("3 AMD64 TLS states");
    return 0;
}
`
	for _, profile := range []struct {
		name   string
		shared bool
	}{
		{"local-exec", false},
		{"initial-exec", true},
	} {
		t.Run(profile.name, func(t *testing.T) {
			pkg, file, options, original, request := x86TLSMoveSourceFixture(t, "linux/amd64", profile.shared,
				"func Value() uint64", x86TLSRuntimeReadAMD64Body)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoX86TLSMoveSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			options, err = source.BindRuntimeTLSReads(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}

			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86TLSMoveBoundAPI(t, pkg, file, original, options, api)
					if err != nil {
						t.Fatal(err)
					}
					dir := t.TempDir()
					raw := filepath.Join(dir, "raw.ll")
					if err := os.WriteFile(raw, []byte(ir), 0600); err != nil {
						t.Fatal(err)
					}
					optimized := x86FloatCompareCaptureCommand(t, exec.Command(opt, "-passes=default<O2>", "-verify-each", "-S", raw, "-o", "-"))
					for _, module := range []struct{ name, ir string }{{"raw", ir}, {"optimized", string(optimized)}} {
						for _, level := range []string{"-O0", "-O2"} {
							output := execution.compileAndRunLLVM(t, module.name, module.ir, oracle, level)
							if string(output) != "3 AMD64 TLS states\n" {
								t.Fatalf("%s/%s incomplete ELF TLS slot checks: %q", module.name, level, output)
							}
						}
					}
				})
			}
		})
	}
}
