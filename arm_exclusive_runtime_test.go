package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARMExclusiveMonitor(t *testing.T) {
	// Separate functions must operate on the same physical exclusive monitor.
	src := `TEXT reserve(SB),NOSPLIT,$0-12
	MOVW addr+0(FP), R4
	MOVW enabled+4(FP), R5
	MOVW $0, R0
	CMP $0, R5
	LDREX.NE (R4), R0
	MOVW R0, ret+8(FP)
	RET

TEXT attempt(SB),NOSPLIT,$0-12
	MOVW addr+0(FP), R4
	MOVW value+4(FP), R5
	STREX R5, (R4), R0
	MOVW R0, ret+8(FP)
	RET

TEXT conditionalAttempt(SB),NOSPLIT,$0-12
	MOVW addr+0(FP), R4
	MOVW value+4(FP), R5
	CMP $0, R5
	MOVW $27, R0
	STREX.NE R5, (R4), R0
	MOVW R0, ret+8(FP)
	RET

TEXT clearReservation(SB),NOSPLIT,$0-0
	WORD $0xf57ff01f
	RET
`
	for _, width := range []string{"B", "D"} {
		src += fmt.Sprintf(`TEXT reserve%s(SB),NOSPLIT,$0-12
	MOVW addr+0(FP), R4
	LDREX%s (R4), R6
	MOVW R6, ret+8(FP)
	RET

TEXT attempt%s(SB),NOSPLIT,$0-12
	MOVW addr+0(FP), R4
	MOVW value+4(FP), R6
	MVN R6, R7
	STREX%s R6, (R4), R0
	MOVW R0, ret+8(FP)
	RET
`, width, width, width, width)
	}
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{"clearReservation": {Name: "clearReservation", Ret: Void}}
	for _, name := range []string{"reserve", "attempt", "conditionalAttempt", "reserveB", "attemptB", "reserveD", "attemptD"} {
		sig := crossAddSig("arm")
		sig.Name = name
		sigs[name] = sig
	}
	opts := Options{Goarch: "arm", Sigs: sigs, TargetTriple: "x86_64-unknown-linux-gnu"}
	if _, err := Translate(file, opts); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("cross-target translation error = %v, want missing A32 monitor", err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, triple := range []string{"armv5-unknown-linux-gnueabi", "armv6-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf"} {
		opts.TargetTriple = triple
		ir, err := Translate(file, opts)
		if err != nil {
			t.Fatal(err)
		}
		ir = runOptO2(t, ir)
		cmd := exec.Command(llc, "-mtriple="+triple, "-filetype=obj", "-o", filepath.Join(t.TempDir(), "reserve.o"), "-")
		cmd.Stdin = strings.NewReader(ir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", triple, err, out)
		}
		if os.Getenv("PLAN9ASM_CROSS_EXEC") == "1" && triple == "armv7-unknown-linux-gnueabihf" {
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc"}, "exclusive", triple, ir, `
extern int reserve(int *, int);
extern int attempt(int *, int), conditionalAttempt(int *, int);
extern int reserveB(int *, int), attemptB(int *, int);
extern int reserveD(int *, int), attemptD(int *, int);
extern void clearReservation(void);
int main(void) {
	int value = 16;
	_Alignas(8) int pair[2] = {0x12345678, 0x87654321};
	for (int i = 0; i < 100; ++i) {
		if (reserveB(pair, 1) != 0x78) return 6;
		if (attemptB(pair, 0x1122) == 0) break;
	}
	if (pair[0] != 0x12345622) return 7;
	for (int i = 0; i < 100; ++i) {
		if (reserveD(pair, 1) != 0x12345622) return 8;
		if (attemptD(pair, 0x4a5a) == 0) break;
	}
	if (pair[0] != 0x4a5a || pair[1] != ~0x4a5a) return 9;
	clearReservation();
	if (reserve((int *)0, 0) != 0 || attempt(&value, 99) == 0 || value != 16) return 1;
	if (reserve(&value, 1) != 16) return 2;
	clearReservation();
	if (attempt(&value, 99) == 0 || value != 16) return 3;
	for (int i = 0; i < 100; ++i) {
		if (reserve(&value, 1) != 16 || conditionalAttempt((int *)0, 0) != 27) return 4;
		if (attempt(&value, 99) == 0) return value != 99;
	}
	return 5;
}
`, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
		}
	}
}
