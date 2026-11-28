package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCrossArchARM64KernelABI(t *testing.T) {
	for _, system := range []string{"linux", "darwin"} {
		t.Run(system, func(t *testing.T) {
			triple := testTargetTriple(system, "arm64")
			num, pid, closeFD, svc := "R8", 172, 57, "SVC"
			if system == "darwin" {
				num, pid, closeFD, svc = "R16", 20, 6, "SVC $128"
			}
			src := fmt.Sprintf("TEXT rawpid(SB),4,$0\nMOVD $%d,%s\n%s\nRET\nTEXT badfd(SB),4,$0\nMOVD $-1,R0\nMOVD $%d,%s\n%s\n", pid, num, svc, closeFD, num, svc)
			if system == "darwin" {
				src += "BCS done\nMOVD $-1,R0\ndone:\n"
			}
			src += "RET\n"
			f, err := Parse(ArchARM64, src)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"rawpid": {Ret: I64}, "badfd": {Ret: I64}}})
			if err != nil {
				t.Fatal(err)
			}
			out := runOptO2(t, ir)
			verifyLLVMWithTargetLLC(t, out, triple)
			// SVC preserves incoming NZ on Linux and BSD. A prior SVC with
			// unknown incoming Z cannot justify BEQ, even when C is an output.
			f, err = Parse(ArchARM64, "TEXT invalid(SB),4,$0\n"+svc+"\nBEQ done\nMOVD $3,R0\ndone:\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(f, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"invalid": {Ret: I64}}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("SVC with unknown entry Z accepted: %v", err)
			}
			if runtime.GOOS == system && runtime.GOARCH == "arm64" {
				llc, clang := requireLlcAndClang(t)
				want := "-EBADF"
				if system == "darwin" {
					want = "EBADF"
				}
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "svc", triple, out, `
#include <unistd.h>
#include <errno.h>
extern long rawpid(void), badfd(void);
int main(void) { return rawpid() != getpid() || badfd() != `+want+`; }
`, nil)
			}
		})
	}
}

// AArch64 CPU-detection packages use WORD to build with Go toolchains whose
// assembler predates the named system register or scalable-length instruction.
func TestARM64RawFeatureQueries(t *testing.T) {
	src := "TEXT detect(SB),4,$0\nWORD $0xd5380000\nWORD $0x04225022\nWORD $0x04635023\nRET\n"
	f, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", Sigs: map[string]FuncSig{"detect": {Ret: I64}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mrs $0, S3_0_C0_C0_0", "@llvm.vscale.i64", `"+sve"`} {
		if !strings.Contains(ir, want) {
			t.Errorf("missing %q in feature detection function", want)
		}
	}
	verifyLLVMWithTargetLLC(t, ir, "aarch64-unknown-linux-gnu")
}
