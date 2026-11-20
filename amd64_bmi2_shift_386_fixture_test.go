package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// SP preserves the complete historical source. DX is an explicitly separate
// executable GP companion: it does not certify the original physical-SP rows.
func x86BMI2Shift386Fixture(t *testing.T, secondDestination string) (string, map[string]FuncSig, string, string) {
	t.Helper()
	if secondDestination != "SP" && secondDestination != "DX" {
		t.Fatal("unknown BMI2 386 fixture role", secondDestination)
	}
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	for _, op := range x86BMI2ShiftTestOps {
		kind := 0
		if strings.HasPrefix(op, "SHRX") {
			kind = 1
		} else if strings.HasPrefix(op, "SARX") {
			kind = 2
		}

		for _, raw := range []bool{false, true} {
			for _, destination := range []string{"CX", secondDestination} {
				name := fmt.Sprintf("shift386_%d", index)
				index++
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-12\n", name)
				source.WriteString("MOVL count+0(FP),AX\nMOVL source+4(FP),BX\n")
				line := fmt.Sprintf("%s AX,(BX),%s\n", op, destination)
				if raw {
					code := assembleX87ControlBytes(t, "386", "TEXT probe(SB),4,$0-0\n"+line+"RET\n")
					for _, b := range code[:len(code)-1] {
						fmt.Fprintf(&source, "BYTE $%#02x\n", b)
					}
				} else {
					source.WriteString(line)
				}
				fmt.Fprintf(&source, "MOVL %s,ret+8(FP)\nRET\n", destination)

				sigs[name] = FuncSig{
					Name: name,
					Args: []LLVMType{I32, Ptr},
					Ret:  I32,
					Frame: FrameLayout{
						Params: []FrameSlot{
							{Offset: 0, Type: I32, Index: 0, Field: -1},
							{Offset: 4, Type: Ptr, Index: 1, Field: -1},
						},
						Results: []FrameSlot{
							{Offset: 8, Type: I32, Index: 0, Field: -1},
						},
					},
				}
				fmt.Fprintf(&declarations, "extern uint32_t %s(uint32_t, const uint32_t*);\n", name)
				fmt.Fprintf(&checks, "    if (check(%s, value, %d)) return %d;\n", name, kind, index)
			}
		}
	}
	if index != 24 {
		t.Fatalf("generated %d functions, want 24", index)
	}
	return source.String(), sigs, declarations.String(), checks.String()
}
