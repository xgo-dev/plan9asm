package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Observe C2's real caller-SP effect with a source-native continuation. The
// trampoline restores the original SP before returning to the Go runtime.
// It is an independent machine-code witness, not a translated C tail call.
func x86RawNearReturnGoStackOracle(t *testing.T, arch string, runPrefix []string) {
	t.Helper()
	move, sub, add, address := "MOVQ", "SUBQ", "ADDQ", "LEAQ"
	wordBytes := 8
	if arch == "386" {
		move, sub, add, address = "MOVL", "SUBL", "ADDL", "LEAL"
		wordBytes = 4
	}
	var assembly strings.Builder
	for _, cleanup := range []int{0, 4} {
		fmt.Fprintf(&assembly, `TEXT ·Measure%d(SB),516,$0-%d
%s SP,BX
%s $16,SP
%s resume%d<>(SB),AX
%s AX,0(SP)
JMP native%d<>(SB)
TEXT native%d<>(SB),516,$0-0
BYTE $0xc2
WORD $%d
TEXT resume%d<>(SB),516,$0-0
%s SP,AX
%s BX,AX
%s $%d,AX
%s BX,SP
%s AX,ret+0(FP)
RET
`, cleanup, wordBytes, move, sub, address, cleanup, move, cleanup, cleanup,
			cleanup, cleanup, move, sub, add, 16-wordBytes, move, move)
	}
	for _, encoding := range []struct{ name, code string }{
		{"C3", "BYTE $0xc3"}, {"C2", "BYTE $0xc2\nWORD $0"},
	} {
		fmt.Fprintf(&assembly, `TEXT ·Result%s(SB),4,$0-4
CALL value%s<>(SB)
MOVL AX,ret+0(FP)
RET
TEXT value%s<>(SB),4,$0-0
MOVL $17,AX
%s
RET
`, encoding.name, encoding.name, encoding.name, encoding.code)
	}
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":                "module example.com/rawreturn\n\ngo 1.20\n",
		"oracle_" + arch + ".s": assembly.String(),
		"oracle_test.go": `package rawreturn
import "testing"
func Measure0() int
func Measure4() int
func ResultC2() int32
func ResultC3() int32
func TestActualMachineStack(t *testing.T) {
  if delta := Measure0(); delta != 0 { t.Fatalf("C2 zero cleanup: SP delta %d", delta) }
  if delta := Measure4(); delta != 4 { t.Fatalf("C2 imm16=4: SP delta %d", delta) }
  if ResultC2() != 17 || ResultC3() != 17 { t.Fatal("zero-cleanup raw return lost AX") }
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"test", "-vet=off", "-count=1"}
	if len(runPrefix) != 0 {
		args = append(args, "-exec", strings.Join(runPrefix, " "))
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH="+arch, "CGO_ENABLED=0", "GODEBUG=asyncpreemptoff=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual Go %s raw-return stack oracle: %v\n%s", arch, err, out)
	}
}

func TestCrossLinuxRuntimeMatrixX86RawNearReturn(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("x86 source-stack oracle runs in the required Linux/amd64 cross-runtime gate")
	}
	x86RawNearReturnGoStackOracle(t, "amd64", nil)
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	var runPrefix []string
	if crossRosetta {
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	var source strings.Builder
	for _, encoding := range []struct{ name, code string }{
		{"rawC3", "BYTE $0xc3"}, {"rawC2", "BYTE $0xc2\nWORD $0"},
	} {
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\nMOVL $17,AX\n%s\nRET\n", encoding.name, encoding.code)
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"rawC3": {Name: "rawC3", Ret: I32}, "rawC2": {Name: "rawC2", Ret: I32}}})
	if err != nil {
		t.Fatal(err)
	}
	const main = `#include <stdint.h>
extern int32_t rawC2(void), rawC3(void);
int main(void) {
  for (unsigned i=0; i<1024; i++) {
    volatile uint64_t canary = UINT64_C(0x123456789abcdef0);
    if (rawC2()!=17 || rawC3()!=17 || canary!=UINT64_C(0x123456789abcdef0)) return 1;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "raw_near_return", triple, ir, main, runPrefix)
	if os.Getenv("PLAN9ASM_CROSS_EXEC") == "1" {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
			t.Fatal("PLAN9ASM_CROSS_EXEC raw-return matrix requires Linux/amd64")
		}
		x86RawNearReturnGoStackOracle(t, "386", []string{"qemu-i386", "-L", "/usr/i686-linux-gnu"})
		ir, err := Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"rawC3": {Name: "rawC3", Ret: I32}, "rawC2": {Name: "rawC2", Ret: I32}}})
		if err != nil {
			t.Fatal(err)
		}
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"i686-linux-gnu-gcc", "-no-pie"},
			"raw_near_return386", "i386-unknown-linux-gnu", ir, main, []string{"qemu-i386", "-L", "/usr/i686-linux-gnu"})
	}
}
