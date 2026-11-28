package plan9asm

import (
	"strings"
	"testing"
)

func translateARMForTest(t *testing.T, src string, sigs map[string]FuncSig) string {
	t.Helper()
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym: func(sym string) string {
			sym = goStripABISuffix(sym)
			sym = strings.ReplaceAll(sym, "∕", "/")
			if strings.HasPrefix(sym, "runtime·") {
				return strings.ReplaceAll(sym, "·", ".")
			}
			if strings.HasPrefix(sym, "·") {
				return "example." + strings.TrimPrefix(sym, "·")
			}
			if !strings.Contains(sym, "·") && !strings.Contains(sym, ".") && !strings.Contains(sym, "/") {
				return "example." + sym
			}
			return strings.ReplaceAll(sym, "·", ".")
		},
		Sigs: sigs,
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	return ll
}

func TestTranslateARMExtendedArithmetic(t *testing.T) {
	ll := translateARMForTest(t, `TEXT ·ops(SB),NOSPLIT,$0-0
	CMP R0, R0
	MVN.EQ.S R0, R1
	ADC.S R1, R2, R3
	SBC.S R1, R2, R4
	MUL R0, R1, R5
	MULLU.EQ R0, R1, (R6, R7)
	MULA R0, R1, R2, R8
	MULAL.EQ R0, R1, (R9, R10)
	MULAWT R0, R1, R2, R11
	DIVUHW R1, R2, R12
	CLZ R12, R0
	MRC $15, $0, R1, $1, $0, $0
	RET
`, map[string]FuncSig{
		"example.ops": {Name: "example.ops", Ret: Void},
	})
	for _, want := range []string{
		"mul i32",
		"mul i64",
		"select i1",
		"call i32 @llvm.ctlz.i32",
		`asm sideeffect "mrc p15, 0, $0, 1, 0, 0"`,
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}

func TestTranslateARMBranchesCallsAndShiftForms(t *testing.T) {
	ll := translateARMForTest(t, `TEXT ·caller(SB),NOSPLIT,$0-0
	CMP R0, R0
	BEQ ok
	MOVW $1, R0
ok:
	MOVW R1<<2, R2
	MOVW R2>>1, R3
	MOVW R3->1, R4
	MOVW R4@>8, R5
	MOVW R5<<R6, R7
	CALL ·callee(SB)
	MOVW $runtime·main(SB), R2
	RET

TEXT ·callee(SB),NOSPLIT,$0-0
	RET

TEXT ·tail(SB),NOSPLIT,$0-0
	B ·callee(SB)
`, map[string]FuncSig{
		"example.caller": {Name: "example.caller", Ret: Void},
		"example.callee": {Name: "example.callee", Ret: I16},
		"example.tail":   {Name: "example.tail", Ret: I16},
	})
	for _, want := range []string{
		"br i1",
		"call i16 @example.callee()",
		"ptrtoint ptr @runtime.main to i32",
		"shl i32",
		"lshr i32",
		"ashr i32",
		"call i32 @llvm.fshr.i32",
		"ret i16 0",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}

func TestTranslateARMAdditionalAtomicForms(t *testing.T) {
	ll := translateARMForTest(t, `TEXT ·atomics(SB),NOSPLIT,$0-0
	LDREXB (R1), R0
	STREXB R3, (R1), R0
	LDREXD (R1), R2
	STREXD R2, (R1), R0
	RET
`, map[string]FuncSig{
		"example.atomics": {Name: "example.atomics", Ret: Void},
	})
	for _, want := range []string{
		".inst 0xe1d10f9f", ".inst 0xe1c10f93",
		".inst 0xe1b12f9f", ".inst 0xe1a10f92",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}
