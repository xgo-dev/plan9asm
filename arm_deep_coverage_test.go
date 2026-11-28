package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARMLinearCoverageDeep(t *testing.T) {
	ll := translateARMForTest(t, `TEXT ·linear(SB),NOSPLIT,$0-0
	MOVB $1, R1
	MOVBU $2, R2
	ADD R5, R4, R7
	SUB R1, R7
	AND R2, R7, R8
	ORR R8, R7, R9
	EOR R9, R8, R10
	RSB $1, R10, R11
	MOVW R11<<2, R0
	RET
`, map[string]FuncSig{
		"example.linear": {
			Name:    "example.linear",
			Args:    []LLVMType{I32, I32, I32},
			ArgRegs: []Reg{"R4", "R5", "R6"},
			Ret:     I32,
		},
	})
	for _, want := range []string{
		"trunc i32 1 to i8",
		"sext i8",
		"zext i8",
		"add i32",
		"sub i32",
		"and i32",
		"or i32",
		"xor i32",
		"shl i32",
		"ret i32",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}
